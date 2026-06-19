package api

import (
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/shreyshringare/Ledger/internal/engine"
)

// contextKey is a private type for context values — avoids collisions with other packages.
type contextKey string

const contextKeyAPIKeyID contextKey = "api_key_id"

// Handler holds shared dependencies for all HTTP handlers.
// Fields are added incrementally — nil fields indicate features not yet wired.
type Handler struct {
	engine         *engine.Engine
	apiKeyStore    engine.APIKeyStore
	rl             *rateLimiter
	db             *pgxpool.Pool
	startTime      time.Time
	cache          *bcryptCache
	jwtSecret      []byte
	usedRefreshIDs sync.Map // jti → struct{} for single-use refresh tokens
}

// NewHandler creates a Handler with all dependencies via functional options.
func NewHandler(e *engine.Engine, opts ...HandlerOption) *Handler {
	h := &Handler{engine: e, startTime: time.Now(), cache: newBcryptCache(30*time.Second, 1000)}
	for _, o := range opts {
		o(h)
	}
	// Background goroutine evicts expired refresh token JTIs (24h TTL).
	// Prevents usedRefreshIDs from growing unbounded over time.
	go func() {
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			now := time.Now()
			h.usedRefreshIDs.Range(func(k, v any) bool {
				if exp, ok := v.(time.Time); ok && now.After(exp) {
					h.usedRefreshIDs.Delete(k)
				}
				return true
			})
		}
	}()
	return h
}

// HandlerOption configures optional Handler dependencies.
type HandlerOption func(*Handler)

// WithAPIKeyStore wires an APIKeyStore into the Handler for auth middleware.
func WithAPIKeyStore(aks engine.APIKeyStore) HandlerOption {
	return func(h *Handler) { h.apiKeyStore = aks }
}

// WithRateLimiter wires a rate limiter into the Handler (Task 8).
func WithRateLimiter(rl *rateLimiter) HandlerOption {
	return func(h *Handler) { h.rl = rl }
}

// WithDB wires a pgxpool.Pool into the Handler for direct DB access.
func WithDB(db *pgxpool.Pool) HandlerOption {
	return func(h *Handler) { h.db = db }
}

// WithJWTSecret sets the HMAC-SHA256 signing secret for JWT token issuance and verification.
func WithJWTSecret(secret []byte) HandlerOption {
	return func(h *Handler) { h.jwtSecret = secret }
}
