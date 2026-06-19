package store

import (
	"context"
	"fmt"
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

// scanAccountRow scans a full account row including the optional archived_at column.
// Column order: id, name, type, currency, is_active, created_at, archived_at
func scanAccountRow(row pgx.Row) (engine.Account, error) {
	var acc engine.Account
	var accType string
	var archivedAt *time.Time
	err := row.Scan(&acc.ID, &acc.Name, &accType, &acc.Currency, &acc.IsActive, &acc.CreatedAt, &archivedAt)
	if err != nil {
		return engine.Account{}, err
	}
	acc.Type = engine.AccountType(accType)
	acc.ArchivedAt = archivedAt
	return acc, nil
}
