package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/shreyshringare/Ledger/internal/engine"
)

type PostgresStore struct {
	db *pgxpool.Pool
}

func NewPostgresStore(db *pgxpool.Pool) *PostgresStore {
	return &PostgresStore{db: db}
}

func (s *PostgresStore) CreateAccount(ctx context.Context, acc engine.Account) error {
	_, err := s.db.Exec(ctx,
		`INSERT INTO accounts (id, name, type, currency, is_active, created_at)
                 VALUES ($1, $2, $3, $4, $5, $6)`,
		acc.ID, acc.Name, string(acc.Type), acc.Currency, acc.IsActive, acc.CreatedAt,
	)
	return err
}

func (s *PostgresStore) GetAccount(ctx context.Context, id string) (engine.Account, error) {
	row := s.db.QueryRow(ctx,
		`SELECT id, name, type, currency, is_active, created_at, archived_at
		 FROM accounts WHERE id = $1`,
		id,
	)
	acc, err := scanAccountRow(row)
	if err != nil {
		return engine.Account{}, fmt.Errorf("get account: %w", err)
	}
	return acc, nil
}

func (s *PostgresStore) GetAccountByName(ctx context.Context, name string) (engine.Account, error) {
	row := s.db.QueryRow(ctx,
		`SELECT id, name, type, currency, is_active, created_at, archived_at
		 FROM accounts WHERE name = $1 AND archived_at IS NULL`,
		name,
	)
	acc, err := scanAccountRow(row)
	if err != nil {
		return engine.Account{}, fmt.Errorf("get account by name: %w", err)
	}
	return acc, nil
}

func (s *PostgresStore) ListAccounts(ctx context.Context) ([]engine.Account, error) {
	rows, err := s.db.Query(ctx,
		`SELECT id, name, type, currency, is_active, created_at, archived_at
		 FROM accounts WHERE archived_at IS NULL ORDER BY created_at`,
	)
	if err != nil {
		return nil, fmt.Errorf("list accounts: %w", err)
	}
	defer rows.Close()

	var accounts []engine.Account
	for rows.Next() {
		var acc engine.Account
		var accType string
		var archivedAt *time.Time
		if err := rows.Scan(&acc.ID, &acc.Name, &accType, &acc.Currency, &acc.IsActive, &acc.CreatedAt, &archivedAt); err != nil {
			return nil, fmt.Errorf("scan account: %w", err)
		}
		acc.Type = engine.AccountType(accType)
		acc.ArchivedAt = archivedAt
		accounts = append(accounts, acc)
	}
	return accounts, rows.Err()
}

func (s *PostgresStore) PostTransaction(ctx context.Context, tx engine.Transaction) (engine.Transaction, error) {
	txOpts := pgx.TxOptions{IsoLevel: pgx.Serializable}
	err := pgx.BeginTxFunc(ctx, s.db, txOpts, func(qtx pgx.Tx) error {
		// Fetch last hash inside the serializable transaction to prevent race conditions.
		var prevHash string
		err := qtx.QueryRow(ctx,
			`SELECT hash FROM transactions ORDER BY posted_at DESC LIMIT 1`,
		).Scan(&prevHash)
		if err != nil {
			prevHash = "genesis"
		}
		tx.PrevHash = prevHash

		hash, err := tx.ComputeHash(prevHash)
		if err != nil {
			return fmt.Errorf("compute hash: %w", err)
		}
		tx.Hash = hash

		_, err = qtx.Exec(ctx,
			`INSERT INTO transactions (id, description, posted_at, hash, prev_hash)
                         VALUES ($1, $2, $3, $4, $5)`,
			tx.ID, tx.Description, tx.PostedAt, tx.Hash, tx.PrevHash,
		)
		if err != nil {
			return fmt.Errorf("insert transaction: %w", err)
		}
		for _, e := range tx.Entries {
			_, err := qtx.Exec(ctx,
				`INSERT INTO entries (id, transaction_id, account_id, amount_minor, currency, is_debit, created_at)
                                 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
				e.ID, e.TransactionID, e.AccountID, e.AmountMinor, e.Currency, e.IsDebit, e.CreatedAt,
			)
			if err != nil {
				return fmt.Errorf("insert entry: %w", err)
			}
		}
		return nil
	})
	if err != nil {
		return engine.Transaction{}, err
	}
	return tx, nil
}

func (s *PostgresStore) GetTransaction(ctx context.Context, id string) (engine.Transaction, error) {
	var tx engine.Transaction
	err := s.db.QueryRow(ctx,
		`SELECT id, description, posted_at, hash, prev_hash FROM transactions WHERE id = $1`,
		id,
	).Scan(&tx.ID, &tx.Description, &tx.PostedAt, &tx.Hash, &tx.PrevHash)
	if err != nil {
		return engine.Transaction{}, fmt.Errorf("get transaction: %w", err)
	}

	rows, err := s.db.Query(ctx,
		`SELECT id, transaction_id, account_id, amount_minor, currency, is_debit, created_at
                 FROM entries WHERE transaction_id = $1`,
		id,
	)
	if err != nil {
		return engine.Transaction{}, fmt.Errorf("get entries: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var e engine.Entry
		if err := rows.Scan(&e.ID, &e.TransactionID, &e.AccountID, &e.AmountMinor, &e.Currency, &e.IsDebit, &e.CreatedAt); err != nil {
			return engine.Transaction{}, fmt.Errorf("scan entry: %w", err)
		}
		tx.Entries = append(tx.Entries, e)
	}
	return tx, rows.Err()
}

func (s *PostgresStore) ListTransactions(ctx context.Context) ([]engine.Transaction, error) {
	rows, err := s.db.Query(ctx,
		`SELECT t.id, t.description, t.posted_at, t.hash, t.prev_hash,
		        e.id, e.transaction_id, e.account_id, e.amount_minor, e.currency, e.is_debit, e.created_at
		 FROM transactions t
		 LEFT JOIN entries e ON e.transaction_id = t.id
		 ORDER BY t.posted_at, e.created_at`,
	)
	if err != nil {
		return nil, fmt.Errorf("list transactions: %w", err)
	}
	defer rows.Close()

	var ordered []engine.Transaction
	txIndex := map[string]int{}

	for rows.Next() {
		var tx engine.Transaction
		// Nullable entry columns (NULL when no entries exist for a transaction).
		var eID, eTxID, eAccID *uuid.UUID
		var eAmountMinor *int64
		var eCurrency *string
		var eIsDebit *bool
		var eCreatedAt *time.Time

		if err := rows.Scan(
			&tx.ID, &tx.Description, &tx.PostedAt, &tx.Hash, &tx.PrevHash,
			&eID, &eTxID, &eAccID, &eAmountMinor, &eCurrency, &eIsDebit, &eCreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan row: %w", err)
		}

		txKey := tx.ID.String()
		idx, seen := txIndex[txKey]
		if !seen {
			idx = len(ordered)
			txIndex[txKey] = idx
			ordered = append(ordered, tx)
		}

		if eID != nil {
			e := engine.Entry{
				ID:            *eID,
				TransactionID: *eTxID,
				AccountID:     *eAccID,
				AmountMinor:   *eAmountMinor,
				Currency:      *eCurrency,
				IsDebit:       *eIsDebit,
				CreatedAt:     *eCreatedAt,
			}
			ordered[idx].Entries = append(ordered[idx].Entries, e)
		}
	}
	return ordered, rows.Err()
}

func (s *PostgresStore) ListTransactionsPaginated(ctx context.Context, limit, offset int) ([]engine.Transaction, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	if offset < 0 {
		offset = 0
	}
	rows, err := s.db.Query(ctx,
		`SELECT t.id, t.description, t.posted_at, t.hash, t.prev_hash,
		        e.id, e.transaction_id, e.account_id, e.amount_minor, e.currency, e.is_debit, e.created_at
		 FROM (
		   SELECT id, description, posted_at, hash, prev_hash
		   FROM transactions
		   ORDER BY posted_at ASC, id ASC
		   LIMIT $1 OFFSET $2
		 ) t
		 LEFT JOIN entries e ON e.transaction_id = t.id
		 ORDER BY t.posted_at, e.created_at`,
		limit, offset,
	)
	if err != nil {
		return nil, fmt.Errorf("list transactions paginated: %w", err)
	}
	defer rows.Close()

	var ordered []engine.Transaction
	txIndex := map[string]int{}

	for rows.Next() {
		var tx engine.Transaction
		var eID, eTxID, eAccID *uuid.UUID
		var eAmountMinor *int64
		var eCurrency *string
		var eIsDebit *bool
		var eCreatedAt *time.Time

		if err := rows.Scan(
			&tx.ID, &tx.Description, &tx.PostedAt, &tx.Hash, &tx.PrevHash,
			&eID, &eTxID, &eAccID, &eAmountMinor, &eCurrency, &eIsDebit, &eCreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan row: %w", err)
		}

		txKey := tx.ID.String()
		idx, seen := txIndex[txKey]
		if !seen {
			idx = len(ordered)
			txIndex[txKey] = idx
			ordered = append(ordered, tx)
		}

		if eID != nil {
			e := engine.Entry{
				ID:            *eID,
				TransactionID: *eTxID,
				AccountID:     *eAccID,
				AmountMinor:   *eAmountMinor,
				Currency:      *eCurrency,
				IsDebit:       *eIsDebit,
				CreatedAt:     *eCreatedAt,
			}
			ordered[idx].Entries = append(ordered[idx].Entries, e)
		}
	}
	return ordered, rows.Err()
}

func (s *PostgresStore) GetBalance(ctx context.Context, accountID string, currency string) (int64, error) {
	var balance int64
	err := s.db.QueryRow(ctx,
		`SELECT COALESCE(SUM(CASE WHEN is_debit THEN amount_minor ELSE -amount_minor END), 0)
                 FROM entries WHERE account_id = $1 AND currency = $2`,
		accountID, currency,
	).Scan(&balance)
	if err != nil {
		return 0, fmt.Errorf("get balance: %w", err)
	}
	return balance, nil
}

func (s *PostgresStore) CheckIdempotencyKey(ctx context.Context, key string) ([]byte, bool, error) {
	var body []byte
	err := s.db.QueryRow(ctx,
		`SELECT response_body FROM idempotency_keys WHERE key = $1`, key,
	).Scan(&body)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return body, true, nil
}

func (s *PostgresStore) SaveIdempotencyKey(ctx context.Context, key string, txID uuid.UUID, responseBody []byte) error {
	_, err := s.db.Exec(ctx,
		`INSERT INTO idempotency_keys (key, transaction_id, response_body)
         VALUES ($1, $2, $3) ON CONFLICT (key) DO NOTHING`,
		key, txID, responseBody,
	)
	return err
}

var _ engine.Store = (*PostgresStore)(nil)
