package api

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"time"
)

// SecurityHeadersMiddleware sets protective HTTP headers on every response.
func SecurityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'none'")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		next.ServeHTTP(w, r)
	})
}

// BodySizeLimitMiddleware rejects requests whose body exceeds maxBytes.
func BodySizeLimitMiddleware(maxBytes int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Read the body with size limit
			body := http.MaxBytesReader(w, r.Body, maxBytes)
			data, err := io.ReadAll(body)
			if err != nil && err.Error() == "http: request body too large" {
				WriteProblem(w, r, http.StatusRequestEntityTooLarge,
					"Payload Too Large", "request body exceeds 1MB limit")
				return
			}
			// Restore body for handler
			r.Body = io.NopCloser(bytes.NewReader(data))
			next.ServeHTTP(w, r)
		})
	}
}

// RequestTimeoutMiddleware adds a deadline to every request context.
func RequestTimeoutMiddleware(timeoutSeconds int) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, cancel := context.WithTimeout(r.Context(), time.Duration(timeoutSeconds)*time.Second)
			defer cancel()
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// drainAndClose discards remaining request body to allow connection reuse.
func drainAndClose(r *http.Request) {
	io.Copy(io.Discard, r.Body) //nolint:errcheck
	r.Body.Close()
}
