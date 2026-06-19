package api

import "github.com/shreyshringare/Ledger/internal/engine"

// Handler holds shared dependencies for all HTTP handlers.
// apiKeyStore and rl (rate limiter) added in Tasks 5 & 8.
type Handler struct {
	engine *engine.Engine
}

func NewHandler(e *engine.Engine, _ interface{}) *Handler {
	return &Handler{engine: e}
}
