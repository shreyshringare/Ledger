package api

import (
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/shreyshringare/Ledger/internal/engine"
)

// contextKey is a private type for context values — avoids collisions with other packages.
type contextKey string

const contextKeyAPIKeyID contextKey = "api_key_id"

// rateLimiter is a placeholder — full implementation in Task 8.
type rateLimiter struct{}

// Handler holds shared dependencies for all HTTP handlers.
// Fields are added incrementally — nil fields indicate features not yet wired.
type Handler struct {
	engine      *engine.Engine
	apiKeyStore engine.APIKeyStore
	rl          *rateLimiter
	db          *pgxpool.Pool
	startTime   time.Time
}

// NewHandler creates a Handler with all dependencies via functional options.
func NewHandler(e *engine.Engine, opts ...HandlerOption) *Handler {
	h := &Handler{engine: e, startTime: time.Now()}
	for _, o := range opts {
		o(h)
	}
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
