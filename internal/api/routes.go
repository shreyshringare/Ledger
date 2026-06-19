package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

// BuildRouter constructs the chi router with all routes under /v1/.
// Middleware stack (auth, rate limit, security headers) added in later tasks.
func BuildRouter(h *Handler) http.Handler {
	r := chi.NewRouter()

	// Unauthenticated
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok"}`)) //nolint:errcheck
	})

	// Auth endpoints — validate credentials themselves, not protected by auth middleware.
	r.Post("/v1/auth/token", h.IssueToken)
	r.Post("/v1/auth/refresh", h.RefreshToken)

	// All API routes under /v1/
	r.Route("/v1", func(r chi.Router) {
		// Accounts
		r.Post("/accounts", h.CreateAccount)
		r.Get("/accounts", h.ListAccounts)
		r.Get("/accounts/{id}/balance", h.GetBalance)

		// Transactions
		r.Post("/transactions", h.PostTransaction)
		r.Get("/transactions", h.ListTransactions)
		r.Get("/transactions/{id}", h.GetTransaction)

		// Chain
		r.Get("/chain/verify", h.VerifyChain)
	})

	return r
}
