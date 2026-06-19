// internal/api/handlers_apikeys.go
package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/shreyshringare/Ledger/internal/engine"
	"golang.org/x/crypto/bcrypt"
)

// CreateAPIKey handles POST /v1/admin/api-keys.
// Returns the combined key exactly once — it is never retrievable again.
// Body: {"scope": "read"|"write"}
func (h *Handler) CreateAPIKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Scope string `json:"scope"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteProblem(w, r, http.StatusBadRequest, "Invalid Request Body", err.Error())
		return
	}
	if req.Scope != "read" && req.Scope != "write" {
		WriteProblem(w, r, http.StatusBadRequest, "Invalid Scope", "scope must be 'read' or 'write'")
		return
	}

	keyID := uuid.New().String()
	secretBytes := make([]byte, 32)
	if _, err := rand.Read(secretBytes); err != nil {
		WriteProblem(w, r, http.StatusInternalServerError, "Internal Error", "failed to generate key")
		return
	}
	secret := hex.EncodeToString(secretBytes)

	hashed, err := bcrypt.GenerateFromPassword([]byte(secret), 12)
	if err != nil {
		WriteProblem(w, r, http.StatusInternalServerError, "Internal Error", "failed to hash key")
		return
	}

	key := engine.APIKey{
		ID:           uuid.New().String(),
		KeyID:        keyID,
		HashedSecret: string(hashed),
		Scope:        req.Scope,
		CreatedAt:    time.Now().UTC(),
	}

	if err := h.apiKeyStore.CreateAPIKey(r.Context(), key); err != nil {
		WriteProblem(w, r, http.StatusInternalServerError, "Internal Error", "failed to store key")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{ //nolint:errcheck
		"key":    keyID + "." + secret,
		"key_id": keyID,
		"scope":  req.Scope,
	})
}

// RevokeAPIKey handles DELETE /v1/admin/api-keys/{id}.
func (h *Handler) RevokeAPIKey(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := h.apiKeyStore.RevokeAPIKey(r.Context(), id); err != nil {
		WriteProblem(w, r, http.StatusInternalServerError, "Internal Error", "failed to revoke key")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// RotateAPIKey handles POST /v1/admin/api-keys/{id}/rotate.
// {id} is the public key_id. Revokes old key and creates replacement with same scope.
func (h *Handler) RotateAPIKey(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	ctx := r.Context()

	old, err := h.apiKeyStore.GetAPIKeyByKeyID(ctx, id)
	if err != nil {
		WriteProblem(w, r, http.StatusNotFound, "Not Found", "API key not found")
		return
	}

	newKeyID := uuid.New().String()
	secretBytes := make([]byte, 32)
	if _, err := rand.Read(secretBytes); err != nil {
		WriteProblem(w, r, http.StatusInternalServerError, "Internal Error", "failed to generate key")
		return
	}
	secret := hex.EncodeToString(secretBytes)
	hashed, err := bcrypt.GenerateFromPassword([]byte(secret), 12)
	if err != nil {
		WriteProblem(w, r, http.StatusInternalServerError, "Internal Error", "failed to hash key")
		return
	}

	newKey := engine.APIKey{
		ID:           uuid.New().String(),
		KeyID:        newKeyID,
		HashedSecret: string(hashed),
		Scope:        old.Scope,
		CreatedAt:    time.Now().UTC(),
	}
	if err := h.apiKeyStore.CreateAPIKey(ctx, newKey); err != nil {
		WriteProblem(w, r, http.StatusInternalServerError, "Internal Error", "failed to create replacement key")
		return
	}
	if err := h.apiKeyStore.RevokeAPIKey(ctx, old.ID); err != nil {
		WriteProblem(w, r, http.StatusInternalServerError, "Internal Error", "failed to revoke old key")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{ //nolint:errcheck
		"key":         newKeyID + "." + secret,
		"key_id":      newKeyID,
		"revoked_key": old.KeyID,
		"scope":       old.Scope,
	})
}
