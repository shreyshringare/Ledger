package store

import (
	"context"
	"fmt"
)

// DeleteExpiredIdempotencyKeys deletes idempotency keys older than 7 days.
// Called by Engine.StartIdempotencyCleanup every hour.
func (s *PostgresStore) DeleteExpiredIdempotencyKeys(ctx context.Context) error {
	_, err := s.db.Exec(ctx,
		`DELETE FROM idempotency_keys WHERE created_at < NOW() - INTERVAL '7 days'`,
	)
	if err != nil {
		return fmt.Errorf("delete expired idempotency keys: %w", err)
	}
	return nil
}
