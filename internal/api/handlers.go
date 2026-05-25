package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/shreyshringare/Ledger/internal/engine"
)

// writeJSON writes v as JSON with the given status code.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// writeError writes a JSON error response.
func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func (h *Handler) CreateAccount(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name     string `json:"name"`
		Type     string `json:"type"`
		Currency string `json:"currency"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	validTypes := map[string]bool{
		"ASSET": true, "LIABILITY": true, "EQUITY": true,
		"REVENUE": true, "EXPENSE": true,
	}
	if !validTypes[req.Type] {
		writeError(w, http.StatusBadRequest, "invalid account type: "+req.Type)
		return
	}

	acc := engine.Account{
		ID:        uuid.New(),
		Name:      req.Name,
		Type:      engine.AccountType(req.Type),
		Currency:  req.Currency,
		IsActive:  true,
		CreatedAt: time.Now().UTC().Truncate(time.Microsecond),
	}

	if err := h.engine.Store().CreateAccount(r.Context(), acc); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, acc)
}

func (h *Handler) ListAccounts(w http.ResponseWriter, r *http.Request) {
	accounts, err := h.engine.Store().ListAccounts(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, accounts)
}

func (h *Handler) ListTransactions(w http.ResponseWriter, r *http.Request) {
	transactions, err := h.engine.Store().ListTransactions(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, transactions)
}

func (h *Handler) PostTransaction(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")

	// Return cached response if key already seen
	if idempotencyKey != "" {
		if cached, ok, err := h.engine.Store().CheckIdempotencyKey(r.Context(), idempotencyKey); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		} else if ok {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Idempotent-Replayed", "true")
			w.WriteHeader(http.StatusCreated)
			w.Write(cached)
			return
		}
	}

	var req struct {
		Description string `json:"description"`
		Entries     []struct {
			AccountName string `json:"account_name"`
			Amount      int64  `json:"amount"`
			Currency    string `json:"currency"`
			IsDebit     bool   `json:"is_debit"`
		} `json:"entries"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	var entries []engine.Entry
	for _, e := range req.Entries {
		acc, err := h.engine.Store().GetAccountByName(r.Context(), e.AccountName)
		if err != nil {
			writeError(w, http.StatusBadRequest, "account not found: "+e.AccountName)
			return
		}
		entries = append(entries, engine.Entry{
			AccountID:   acc.ID,
			AmountMinor: e.Amount,
			Currency:    e.Currency,
			IsDebit:     e.IsDebit,
		})
	}

	tx, err := h.engine.Post(r.Context(), req.Description, entries)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Cache the response for future replays
	if idempotencyKey != "" {
		body, _ := json.Marshal(tx)
		_ = h.engine.Store().SaveIdempotencyKey(r.Context(), idempotencyKey, tx.ID, body)
	}

	writeJSON(w, http.StatusCreated, tx)
}

func (h *Handler) GetTransaction(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	tx, err := h.engine.Store().GetTransaction(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "transaction not found: "+id)
		return
	}

	writeJSON(w, http.StatusOK, tx)
}

func (h *Handler) GetBalance(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	currency := r.URL.Query().Get("currency")
	if currency == "" {
		currency = "USD"
	}

	balance, err := h.engine.Balance(r.Context(), id, currency)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"account_id":   id,
		"currency":     currency,
		"balance":      balance,
		"minor_units":  true,
	})
}

func (h *Handler) VerifyChain(w http.ResponseWriter, r *http.Request) {
	if err := h.engine.VerifyChain(r.Context()); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"intact":  false,
			"message": err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"intact":  true,
		"message": "chain intact — no tampering detected",
	})
}
