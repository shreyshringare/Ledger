// internal/engine/apikey.go
package engine

import (
	"context"
	"time"
)

// APIKey represents an API credential. The plaintext secret is NEVER stored —
// only the bcrypt hash. The combined key sent to clients is: "<key_id>.<secret>"
// where key_id is the lookup identifier and secret is the credential.
//
// Scopes:
//   - "read"  — GET endpoints only
//   - "write" — all endpoints including POST/DELETE
type APIKey struct {
	ID           string     // internal UUID (primary key)
	KeyID        string     // public identifier (sent in X-API-Key header)
	HashedSecret string     // bcrypt hash of the secret — never the plaintext
	Scope        string     // "read" or "write"
	CreatedAt    time.Time
	RevokedAt    *time.Time // nil = active; non-nil = revoked
	LastUsedAt   *time.Time // updated on each successful auth
}

// APIKeyStore defines persistence operations for API keys.
// Implemented by PostgresStore in internal/store/postgres_apikeys.go.
// A fake implementation is used in tests.
type APIKeyStore interface {
	// CreateAPIKey persists a new API key. HashedSecret must already be bcrypt-hashed.
	CreateAPIKey(ctx context.Context, key APIKey) error

	// GetAPIKeyByKeyID retrieves a key by its public KeyID.
	// Returns an error wrapping pgx.ErrNoRows if not found.
	GetAPIKeyByKeyID(ctx context.Context, keyID string) (APIKey, error)

	// RevokeAPIKey sets RevokedAt to now. Idempotent — revoking an already-revoked key is a no-op.
	RevokeAPIKey(ctx context.Context, id string) error

	// UpdateAPIKeyLastUsed sets LastUsedAt to now. Best-effort — errors are logged, not returned.
	UpdateAPIKeyLastUsed(ctx context.Context, id string) error
}
