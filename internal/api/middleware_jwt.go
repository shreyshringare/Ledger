// Package api — JWT Bearer authentication middleware.
package api

import (
	"context"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// JWTAuthMiddleware checks for a Bearer token in the Authorization header.
// If present: verifies signature, expiry, and token_type=access, then sets the
// key_id in context so downstream handlers can identify the caller.
// If absent: passes through to the next handler (APIKeyAuthMiddleware handles it).
func (h *Handler) JWTAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			// No Bearer token — fall through to API key auth.
			next.ServeHTTP(w, r)
			return
		}

		if len(h.jwtSecret) == 0 {
			WriteProblem(w, r, http.StatusInternalServerError, "Configuration Error", "JWT not configured")
			return
		}

		tokenStr := strings.TrimPrefix(auth, "Bearer ")
		claims := &ledgerClaims{}
		token, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, jwt.ErrSignatureInvalid
			}
			return h.jwtSecret, nil
		})
		if err != nil || !token.Valid {
			WriteProblem(w, r, http.StatusUnauthorized, "Unauthorized", "invalid or expired token")
			return
		}
		if claims.TokenType != "access" {
			WriteProblem(w, r, http.StatusUnauthorized, "Unauthorized", "not an access token")
			return
		}

		ctx := context.WithValue(r.Context(), contextKeyAPIKeyID, claims.Subject)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
