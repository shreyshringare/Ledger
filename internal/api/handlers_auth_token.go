// Package api — JWT token issuance and refresh handlers.
package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// ledgerClaims extends jwt.RegisteredClaims with application-specific fields.
type ledgerClaims struct {
	jwt.RegisteredClaims
	Scope     string `json:"scope"`
	TokenType string `json:"token_type"` // "access" or "refresh"
}

// IssueToken handles POST /v1/auth/token.
// Validates the X-API-Key header, then returns a 5-min access token and 24h refresh token.
func (h *Handler) IssueToken(w http.ResponseWriter, r *http.Request) {
	if len(h.jwtSecret) == 0 {
		WriteProblem(w, r, http.StatusInternalServerError, "Configuration Error", "JWT not configured")
		return
	}

	rawKey := r.Header.Get("X-API-Key")
	if rawKey == "" {
		WriteProblem(w, r, http.StatusUnauthorized, "Unauthorized", "X-API-Key header is required")
		return
	}
	keyID, secret, ok := parseAPIKeyHeader(rawKey)
	if !ok {
		WriteProblem(w, r, http.StatusUnauthorized, "Unauthorized", "invalid X-API-Key format")
		return
	}
	apiKey, err := h.apiKeyStore.GetAPIKeyByKeyID(r.Context(), keyID)
	if err != nil || apiKey.RevokedAt != nil {
		WriteProblem(w, r, http.StatusUnauthorized, "Unauthorized", "invalid API key")
		return
	}

	// Cache-aware bcrypt check — avoids re-hashing on repeated calls.
	if matched, found := h.cache.Get(secret); found {
		if !matched {
			WriteProblem(w, r, http.StatusUnauthorized, "Unauthorized", "invalid API key")
			return
		}
	} else {
		if err := bcrypt.CompareHashAndPassword([]byte(apiKey.HashedSecret), []byte(secret)); err != nil {
			h.cache.Set(secret, false)
			WriteProblem(w, r, http.StatusUnauthorized, "Unauthorized", "invalid API key")
			return
		}
		h.cache.Set(secret, true)
	}

	now := time.Now()

	// Access token — 5 minutes.
	accessClaims := ledgerClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   apiKey.KeyID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(5 * time.Minute)),
			ID:        uuid.New().String(),
		},
		Scope:     apiKey.Scope,
		TokenType: "access",
	}
	accessToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims).SignedString(h.jwtSecret)
	if err != nil {
		WriteProblem(w, r, http.StatusInternalServerError, "Internal Error", "failed to sign access token")
		return
	}

	// Refresh token — 24 hours.
	refreshClaims := ledgerClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   apiKey.KeyID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(24 * time.Hour)),
			ID:        uuid.New().String(),
		},
		Scope:     apiKey.Scope,
		TokenType: "refresh",
	}
	refreshToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims).SignedString(h.jwtSecret)
	if err != nil {
		WriteProblem(w, r, http.StatusInternalServerError, "Internal Error", "failed to sign refresh token")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{ //nolint:errcheck
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"expires_in":    300, // 5 minutes in seconds
		"token_type":    "Bearer",
	})
}

// RefreshToken handles POST /v1/auth/refresh.
// Accepts {"refresh_token": "<jwt>"} body.
// Single-use: reusing a refresh token returns 401.
func (h *Handler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	if len(h.jwtSecret) == 0 {
		WriteProblem(w, r, http.StatusInternalServerError, "Configuration Error", "JWT not configured")
		return
	}

	var body struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.RefreshToken == "" {
		WriteProblem(w, r, http.StatusBadRequest, "Bad Request", "refresh_token is required")
		return
	}

	claims := &ledgerClaims{}
	token, err := jwt.ParseWithClaims(body.RefreshToken, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return h.jwtSecret, nil
	})
	if err != nil || !token.Valid {
		WriteProblem(w, r, http.StatusUnauthorized, "Unauthorized", "invalid or expired refresh token")
		return
	}
	if claims.TokenType != "refresh" {
		WriteProblem(w, r, http.StatusUnauthorized, "Unauthorized", "not a refresh token")
		return
	}

	// Single-use check: reject if jti already consumed.
	jti := claims.ID
	if _, loaded := h.usedRefreshIDs.LoadOrStore(jti, struct{}{}); loaded {
		WriteProblem(w, r, http.StatusUnauthorized, "Unauthorized", "refresh token already used")
		return
	}

	now := time.Now()
	accessClaims := ledgerClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   claims.Subject,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(5 * time.Minute)),
			ID:        uuid.New().String(),
		},
		Scope:     claims.Scope,
		TokenType: "access",
	}
	accessToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims).SignedString(h.jwtSecret)
	if err != nil {
		WriteProblem(w, r, http.StatusInternalServerError, "Internal Error", "failed to sign token")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{ //nolint:errcheck
		"access_token": accessToken,
		"expires_in":   300,
		"token_type":   "Bearer",
	})
}
