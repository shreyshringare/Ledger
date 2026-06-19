// internal/api/middleware_hmac_test.go
package api

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func signRequest(secret, method, path, body string, ts int64) string {
	bodyHash := sha256.Sum256([]byte(body))
	message := fmt.Sprintf("%s\n%s\n%s\n%d", method, path, hex.EncodeToString(bodyHash[:]), ts)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(message))
	return hex.EncodeToString(mac.Sum(nil))
}

func TestHMACMiddleware_ValidSignature(t *testing.T) {
	secret := "mysecret"
	middleware := HMACMiddleware(secret)

	body := `{"amount":100}`
	ts := time.Now().Unix()
	sig := signRequest(secret, "POST", "/v1/transactions", body, ts)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/transactions", bytes.NewBufferString(body))
	req.Header.Set("X-Signature", sig)
	req.Header.Set("X-Timestamp", strconv.FormatInt(ts, 10))
	middleware(next).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHMACMiddleware_ReplayAttack(t *testing.T) {
	secret := "mysecret"

	body := `{"amount":100}`
	ts := time.Now().Add(-10 * time.Minute).Unix()
	sig := signRequest(secret, "POST", "/v1/transactions", body, ts)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/transactions", bytes.NewBufferString(body))
	req.Header.Set("X-Signature", sig)
	req.Header.Set("X-Timestamp", strconv.FormatInt(ts, 10))
	HMACMiddleware(secret)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for replay, got %d", rec.Code)
	}
}

func TestHMACMiddleware_TamperedBody(t *testing.T) {
	secret := "mysecret"
	body := `{"amount":100}`
	ts := time.Now().Unix()
	sig := signRequest(secret, "POST", "/v1/transactions", body, ts)

	tamperedBody := `{"amount":999999}`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/transactions", bytes.NewBufferString(tamperedBody))
	req.Header.Set("X-Signature", sig)
	req.Header.Set("X-Timestamp", strconv.FormatInt(ts, 10))
	HMACMiddleware(secret)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for tampered body, got %d", rec.Code)
	}
}
