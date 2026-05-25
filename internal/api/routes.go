package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/shreyshringare/Ledger/internal/engine"
)

func BuildRouter(e *engine.Engine) http.Handler {
	h := NewHandler(e)
	r := chi.NewRouter()

	r.Post("/accounts", h.CreateAccount)
	r.Get("/accounts", h.ListAccounts)
	r.Post("/transactions", h.PostTransaction)
	r.Get("/transactions", h.ListTransactions)
	r.Get("/transactions/{id}", h.GetTransaction)
	r.Get("/accounts/{id}/balance", h.GetBalance)
	r.Get("/chain/verify", h.VerifyChain)

	return r
}
