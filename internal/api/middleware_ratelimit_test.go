package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRateLimitMiddleware_AllowsUnderLimit(t *testing.T) {
	h := NewHandler(nil, WithAPIKeyStore(newFakeAPIKeyStore()))
	h.InitRateLimiter(3, 60)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	for i := 0; i < 3; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/v1/accounts", nil)
		req = req.WithContext(context.WithValue(req.Context(), contextKeyAPIKeyID, "test-key"))
		h.RateLimitMiddleware(next).ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("request %d: expected 200, got %d", i+1, rec.Code)
		}
	}
}

func TestRateLimitMiddleware_BlocksOverLimit(t *testing.T) {
	h := NewHandler(nil, WithAPIKeyStore(newFakeAPIKeyStore()))
	h.InitRateLimiter(2, 60)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	makeReq := func() int {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/v1/accounts", nil)
		req = req.WithContext(context.WithValue(req.Context(), contextKeyAPIKeyID, "key-a"))
		h.RateLimitMiddleware(next).ServeHTTP(rec, req)
		return rec.Code
	}

	makeReq()
	makeReq()
	if code := makeReq(); code != http.StatusTooManyRequests {
		t.Errorf("expected 429, got %d", code)
	}
}

func TestRateLimitMiddleware_SeparateLimitsPerKey(t *testing.T) {
	h := NewHandler(nil, WithAPIKeyStore(newFakeAPIKeyStore()))
	h.InitRateLimiter(1, 60)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	makeReqWith := func(keyID string) int {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/v1/accounts", nil)
		req = req.WithContext(context.WithValue(req.Context(), contextKeyAPIKeyID, keyID))
		h.RateLimitMiddleware(next).ServeHTTP(rec, req)
		return rec.Code
	}

	makeReqWith("key-a")
	if code := makeReqWith("key-a"); code != http.StatusTooManyRequests {
		t.Errorf("key-a: expected 429, got %d", code)
	}
	if code := makeReqWith("key-b"); code != http.StatusOK {
		t.Errorf("key-b: expected 200, got %d", code)
	}
}
