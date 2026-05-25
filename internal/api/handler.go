package api

import "github.com/shreyshringare/Ledger/internal/engine"

// Handler holds shared dependencies for all HTTP handlers.
type Handler struct {
	engine *engine.Engine
}

func NewHandler(e *engine.Engine) *Handler {
	return &Handler{engine: e}
}
