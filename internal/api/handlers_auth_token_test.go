package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/shreyshringare/Ledger/internal/engine"
	"golang.org/x/crypto/bcrypt"
)

func setupJWTTest(t *testing.T) (*Handler, string) {
	t.Helper()
	store := newFakeAPIKeyStore()
	secret := []byte("test-jwt-secret-32-bytes-padding!")
	h := NewHandler(nil, WithAPIKeyStore(store), WithJWTSecret(secret))

	apiSecret := "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	hash, err := bcrypt.GenerateFromPassword([]byte(apiSecret), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	store.keys["test-key-id"] = engine.APIKey{
		ID:           "test-id",
		KeyID:        "test-key-id",
		HashedSecret: string(hash),
		Scope:        "write",
		CreatedAt:    time.Now(),
	}
	return h, "test-key-id." + apiSecret
}

func TestIssueToken_ValidAPIKey(t *testing.T) {
	h, validKey := setupJWTTest(t)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/token", nil)
	req.Header.Set("X-API-Key", validKey)
	h.IssueToken(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp["access_token"] == "" {
		t.Error("expected access_token in response")
	}
	if resp["refresh_token"] == "" {
		t.Error("expected refresh_token in response")
	}
	if resp["expires_in"] != float64(300) {
		t.Errorf("expected expires_in=300, got %v", resp["expires_in"])
	}
	if resp["token_type"] != "Bearer" {
		t.Errorf("expected token_type=Bearer, got %v", resp["token_type"])
	}
}

func TestIssueToken_MissingAPIKey(t *testing.T) {
	h, _ := setupJWTTest(t)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/token", nil)
	h.IssueToken(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

func TestIssueToken_InvalidAPIKey(t *testing.T) {
	h, _ := setupJWTTest(t)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/token", nil)
	req.Header.Set("X-API-Key", "test-key-id.wrongsecret00000000000000000000000000000000000000000000000000000")
	h.IssueToken(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

func TestIssueToken_NoJWTSecret(t *testing.T) {
	store := newFakeAPIKeyStore()
	h := NewHandler(nil, WithAPIKeyStore(store)) // no WithJWTSecret

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/token", nil)
	req.Header.Set("X-API-Key", "test-key-id.something")
	h.IssueToken(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 when JWT not configured, got %d", rec.Code)
	}
}

func TestRefreshToken_Valid(t *testing.T) {
	h, validKey := setupJWTTest(t)

	// First get tokens.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/token", nil)
	req.Header.Set("X-API-Key", validKey)
	h.IssueToken(rec, req)

	var tokens map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&tokens); err != nil {
		t.Fatalf("failed to decode token response: %v", err)
	}
	refreshToken, _ := tokens["refresh_token"].(string)
	if refreshToken == "" {
		t.Fatal("no refresh_token in response")
	}

	// Refresh.
	body, _ := json.Marshal(map[string]string{"refresh_token": refreshToken})
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/v1/auth/refresh", bytes.NewReader(body))
	req2.Header.Set("Content-Type", "application/json")
	h.RefreshToken(rec2, req2)

	if rec2.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec2.Code, rec2.Body.String())
	}
	var refreshResp map[string]interface{}
	if err := json.NewDecoder(rec2.Body).Decode(&refreshResp); err != nil {
		t.Fatalf("failed to decode refresh response: %v", err)
	}
	if refreshResp["access_token"] == "" {
		t.Error("expected access_token in refresh response")
	}
}

func TestRefreshToken_SingleUse(t *testing.T) {
	h, validKey := setupJWTTest(t)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/token", nil)
	req.Header.Set("X-API-Key", validKey)
	h.IssueToken(rec, req)

	var tokens map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&tokens); err != nil {
		t.Fatalf("failed to decode token response: %v", err)
	}
	refreshToken, _ := tokens["refresh_token"].(string)

	useRefresh := func() int {
		body, _ := json.Marshal(map[string]string{"refresh_token": refreshToken})
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/auth/refresh", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		h.RefreshToken(rec, req)
		return rec.Code
	}

	if code := useRefresh(); code != http.StatusOK {
		t.Fatalf("first refresh: expected 200, got %d", code)
	}
	if code := useRefresh(); code != http.StatusUnauthorized {
		t.Errorf("second refresh: expected 401 (single-use), got %d", code)
	}
}

func TestRefreshToken_RejectAccessToken(t *testing.T) {
	h, validKey := setupJWTTest(t)

	// Get tokens then try to refresh using the access token.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/token", nil)
	req.Header.Set("X-API-Key", validKey)
	h.IssueToken(rec, req)

	var tokens map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&tokens) //nolint:errcheck
	accessToken, _ := tokens["access_token"].(string)

	body, _ := json.Marshal(map[string]string{"refresh_token": accessToken})
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/v1/auth/refresh", bytes.NewReader(body))
	req2.Header.Set("Content-Type", "application/json")
	h.RefreshToken(rec2, req2)

	if rec2.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 when using access token as refresh token, got %d", rec2.Code)
	}
}

func TestJWTAuthMiddleware_ValidToken(t *testing.T) {
	h, _ := setupJWTTest(t)
	secret := []byte("test-jwt-secret-32-bytes-padding!")

	claims := ledgerClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "test-key-id",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
			ID:        "test-jti-valid",
		},
		Scope:     "write",
		TokenType: "access",
	}
	tokenStr, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(secret)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	var gotKeyID string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKeyID, _ = r.Context().Value(contextKeyAPIKeyID).(string)
		w.WriteHeader(http.StatusOK)
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/accounts", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	h.JWTAuthMiddleware(next).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if gotKeyID != "test-key-id" {
		t.Errorf("expected key_id=test-key-id in context, got %q", gotKeyID)
	}
}

func TestJWTAuthMiddleware_ExpiredToken(t *testing.T) {
	h, _ := setupJWTTest(t)
	secret := []byte("test-jwt-secret-32-bytes-padding!")

	claims := ledgerClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "test-key-id",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-1 * time.Minute)), // already expired
			ID:        "test-jti-expired",
		},
		Scope:     "write",
		TokenType: "access",
	}
	tokenStr, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(secret)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/accounts", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	h.JWTAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for expired token, got %d", rec.Code)
	}
}

func TestJWTAuthMiddleware_NoBearerFallsThrough(t *testing.T) {
	h, _ := setupJWTTest(t)

	var nextCalled bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/accounts", nil)
	// No Authorization header — should fall through to next.
	h.JWTAuthMiddleware(next).ServeHTTP(rec, req)

	if !nextCalled {
		t.Error("expected next handler to be called when no Bearer token")
	}
}

func TestJWTAuthMiddleware_RefreshTokenRejected(t *testing.T) {
	h, _ := setupJWTTest(t)
	secret := []byte("test-jwt-secret-32-bytes-padding!")

	claims := ledgerClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "test-key-id",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			ID:        "test-jti-refresh",
		},
		Scope:     "write",
		TokenType: "refresh", // wrong type
	}
	tokenStr, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(secret)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/accounts", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	h.JWTAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 when using refresh token as bearer, got %d", rec.Code)
	}
}
