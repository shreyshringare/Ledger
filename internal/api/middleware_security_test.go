package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSecurityHeadersMiddleware(t *testing.T) {
	handler := SecurityHeadersMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/accounts", nil)
	handler.ServeHTTP(rec, req)

	tests := []struct{ header, want string }{
		{"X-Content-Type-Options", "nosniff"},
		{"X-Frame-Options", "DENY"},
		{"Content-Security-Policy", "default-src 'none'"},
	}
	for _, tt := range tests {
		if got := rec.Header().Get(tt.header); got != tt.want {
			t.Errorf("%s: want %q, got %q", tt.header, tt.want, got)
		}
	}
}

func TestBodySizeLimitMiddleware(t *testing.T) {
	handler := BodySizeLimitMiddleware(10)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// 11 bytes — over limit
	body := strings.NewReader("hello world") // 11 bytes
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/transactions", body)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("expected 413, got %d", rec.Code)
	}
}

func TestRequestTimeoutMiddleware(t *testing.T) {
	handler := RequestTimeoutMiddleware(1)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Sleep longer than the timeout
		select {
		case <-r.Context().Done():
			WriteProblem(w, r, http.StatusServiceUnavailable, "Request Timeout", "request took too long")
			return
		case <-time.After(5 * time.Second):
			w.WriteHeader(http.StatusOK)
		}
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/accounts", nil)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rec.Code)
	}
}
