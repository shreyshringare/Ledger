// internal/store/postgres_apikeys.go
package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/shreyshringare/Ledger/internal/engine"
)

// CreateAPIKey inserts a new API key. The secret must already be bcrypt-hashed.
func (s *PostgresStore) CreateAPIKey(ctx context.Context, key engine.APIKey) error {
	_, err := s.db.Exec(ctx,
		`INSERT INTO api_keys (id, key_id, hashed_secret, scope, created_at)
		 VALUES ($1, $2, $3, $4, $5)`,
		key.ID, key.KeyID, key.HashedSecret, key.Scope, key.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("create api key: %w", err)
	}
	return nil
}

// GetAPIKeyByKeyID retrieves an active (non-revoked) API key by its public key_id.
func (s *PostgresStore) GetAPIKeyByKeyID(ctx context.Context, keyID string) (engine.APIKey, error) {
	var k engine.APIKey
	err := s.db.QueryRow(ctx,
		`SELECT id, key_id, hashed_secret, scope, created_at, revoked_at, last_used_at
		 FROM api_keys WHERE key_id = $1`,
		keyID,
	).Scan(
		&k.ID, &k.KeyID, &k.HashedSecret, &k.Scope,
		&k.CreatedAt, &k.RevokedAt, &k.LastUsedAt,
	)
	if err == pgx.ErrNoRows {
		return engine.APIKey{}, err
	}
	if err != nil {
		return engine.APIKey{}, fmt.Errorf("get api key: %w", err)
	}
	return k, nil
}

// RevokeAPIKey sets revoked_at to now. Only affects active keys.
func (s *PostgresStore) RevokeAPIKey(ctx context.Context, id string) error {
	_, err := s.db.Exec(ctx,
		`UPDATE api_keys SET revoked_at = $1 WHERE id = $2 AND revoked_at IS NULL`,
		time.Now().UTC(), id,
	)
	if err != nil {
		return fmt.Errorf("revoke api key: %w", err)
	}
	return nil
}

// UpdateAPIKeyLastUsed updates last_used_at. Called after every successful auth.
// Errors are intentionally ignored by the caller (best-effort telemetry).
func (s *PostgresStore) UpdateAPIKeyLastUsed(ctx context.Context, id string) error {
	_, err := s.db.Exec(ctx,
		`UPDATE api_keys SET last_used_at = $1 WHERE id = $2`,
		time.Now().UTC(), id,
	)
	if err != nil {
		return fmt.Errorf("update api key last used: %w", err)
	}
	return nil
}

// compile-time interface check
var _ engine.APIKeyStore = (*PostgresStore)(nil)
