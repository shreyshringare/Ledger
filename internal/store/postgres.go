package store

import (
	"context"
	"fmt"

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
	var acc engine.Account
	var accType string
	err := s.db.QueryRow(ctx,
		`SELECT id, name, type, currency, is_active, created_at FROM accounts WHERE id = $1`,
		id,
	).Scan(&acc.ID, &acc.Name, &accType, &acc.Currency, &acc.IsActive, &acc.CreatedAt)
	if err != nil {
		return engine.Account{}, fmt.Errorf("get account: %w", err)
	}
	acc.Type = engine.AccountType(accType)
	return acc, nil
}

func (s *PostgresStore) GetAccountByName(ctx context.Context, name string) (engine.Account, error) {
	var acc engine.Account
	var accType string
	err := s.db.QueryRow(ctx,
		`SELECT id, name, type, currency, is_active, created_at FROM accounts WHERE name = $1`,
		name,
	).Scan(&acc.ID, &acc.Name, &accType, &acc.Currency, &acc.IsActive, &acc.CreatedAt)
	if err != nil {
		return engine.Account{}, fmt.Errorf("get account by name: %w", err)
	}
	acc.Type = engine.AccountType(accType)
	return acc, nil
}

func (s *PostgresStore) ListAccounts(ctx context.Context) ([]engine.Account, error) {
	rows, err := s.db.Query(ctx,
		`SELECT id, name, type, currency, is_active, created_at FROM accounts ORDER BY created_at`,
	)
	if err != nil {
		return nil, fmt.Errorf("list accounts: %w", err)
	}
	defer rows.Close()

	var accounts []engine.Account
	for rows.Next() {
		var acc engine.Account
		var accType string
		if err := rows.Scan(&acc.ID, &acc.Name, &accType, &acc.Currency, &acc.IsActive, &acc.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan account: %w", err)
		}
		acc.Type = engine.AccountType(accType)
		accounts = append(accounts, acc)
	}
	return accounts, rows.Err()
}

func (s *PostgresStore) PostTransaction(ctx context.Context, tx engine.Transaction) error {
	return pgx.BeginFunc(ctx, s.db, func(qtx pgx.Tx) error {
		_, err := qtx.Exec(ctx,
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
		`SELECT id, description, posted_at, hash, prev_hash FROM transactions ORDER BY posted_at`,
	)
	if err != nil {
		return nil, fmt.Errorf("list transactions: %w", err)
	}
	defer rows.Close()

	var txs []engine.Transaction
	for rows.Next() {
		var tx engine.Transaction
		if err := rows.Scan(&tx.ID, &tx.Description, &tx.PostedAt, &tx.Hash, &tx.PrevHash); err != nil {
			return nil, fmt.Errorf("scan transaction: %w", err)
		}
		txs = append(txs, tx)
	}
	return txs, rows.Err()
}

func (s *PostgresStore) GetLastHash(ctx context.Context) (string, error) {
	var hash string
	err := s.db.QueryRow(ctx,
		`SELECT hash FROM transactions ORDER BY posted_at DESC LIMIT 1`,
	).Scan(&hash)
	if err != nil {
		return "genesis", nil
	}
	return hash, nil
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

var _ engine.Store = (*PostgresStore)(nil)
var _ = uuid.Nil
