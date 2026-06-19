package store

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/shreyshringare/Ledger/internal/engine"
)

// ArchiveAccount sets archived_at = NOW() on the account. Never hard-deletes.
// Returns pgx.ErrNoRows if the account is not found or already archived.
func (s *PostgresStore) ArchiveAccount(ctx context.Context, id string) error {
	tag, err := s.db.Exec(ctx,
		`UPDATE accounts SET archived_at = NOW() WHERE id = $1 AND archived_at IS NULL`,
		id,
	)
	if err != nil {
		return fmt.Errorf("archive account: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows // not found or already archived
	}
	return nil
}

// encryptionKey reads the symmetric encryption key from the environment.
// Returns empty string if not set — description will be NULL in that case.
func encryptionKey() string {
	return os.Getenv("ENCRYPTION_KEY")
}

// scanAccountRowWithDescription scans a row with columns:
// id, name, type, currency, is_active, created_at, archived_at, description(nullable text)
func scanAccountRowWithDescription(row pgx.Row) (engine.Account, error) {
	var acc engine.Account
	var accType string
	var archivedAt *time.Time
	var desc *string
	err := row.Scan(&acc.ID, &acc.Name, &accType, &acc.Currency, &acc.IsActive,
		&acc.CreatedAt, &archivedAt, &desc)
	if err != nil {
		return engine.Account{}, err
	}
	acc.Type = engine.AccountType(accType)
	acc.ArchivedAt = archivedAt
	if desc != nil {
		acc.Description = *desc
	}
	return acc, nil
}
