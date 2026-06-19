package api

import (
	"context"
	"log/slog"
	"net/http"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// APIKeyAuthMiddleware authenticates requests using an API key in the X-API-Key header.
// Format: "X-API-Key: <key_id>.<secret>"
//
// Flow:
//  1. Parse header → split on first "." → key_id + secret
//  2. Look up api_keys by key_id
//  3. Check revoked_at is nil
//  4. bcrypt.CompareHashAndPassword(stored_hash, secret) — constant-time
//  5. Store key_id in context for logging/audit
//  6. Best-effort: update last_used_at in background goroutine
func (h *Handler) APIKeyAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rawKey := r.Header.Get("X-API-Key")
		if rawKey == "" {
			WriteProblem(w, r, http.StatusUnauthorized,
				"Unauthorized", "X-API-Key header is required")
			return
		}

		keyID, secret, ok := parseAPIKeyHeader(rawKey)
		if !ok {
			WriteProblem(w, r, http.StatusUnauthorized,
				"Unauthorized", "invalid X-API-Key format — expected <key_id>.<secret>")
			return
		}

		apiKey, err := h.apiKeyStore.GetAPIKeyByKeyID(r.Context(), keyID)
		if err != nil {
			// Don't reveal whether the key_id exists — always return the same message.
			WriteProblem(w, r, http.StatusUnauthorized, "Unauthorized", "invalid API key")
			return
		}

		if apiKey.RevokedAt != nil {
			WriteProblem(w, r, http.StatusUnauthorized, "Unauthorized", "API key has been revoked")
			return
		}

		// bcrypt.CompareHashAndPassword is constant-time — safe against timing attacks.
		if err := bcrypt.CompareHashAndPassword([]byte(apiKey.HashedSecret), []byte(secret)); err != nil {
			WriteProblem(w, r, http.StatusUnauthorized, "Unauthorized", "invalid API key")
			return
		}

		// Best-effort: record when this key was last used. Uses background context
		// because the request context may be cancelled before the goroutine runs.
		go func() {
			if err := h.apiKeyStore.UpdateAPIKeyLastUsed(context.Background(), apiKey.ID); err != nil {
				slog.Warn("failed to update api key last_used_at", "key_id", keyID, "err", err)
			}
		}()

		// Store key_id in context so handlers and log middleware can access it.
		ctx := context.WithValue(r.Context(), contextKeyAPIKeyID, apiKey.KeyID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// parseAPIKeyHeader splits "key_id.secret" into its parts.
// Returns ok=false if the format is invalid (no dot, empty key_id, or empty secret).
func parseAPIKeyHeader(raw string) (keyID, secret string, ok bool) {
	idx := strings.Index(raw, ".")
	if idx < 1 || idx == len(raw)-1 {
		return "", "", false
	}
	return raw[:idx], raw[idx+1:], true
}
