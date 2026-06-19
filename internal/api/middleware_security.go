package api

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

// SecurityHeadersMiddleware sets protective HTTP headers on every response.
// It enforces X-Content-Type-Options, X-Frame-Options, Content-Security-Policy,
// and Strict-Transport-Security headers to mitigate common web vulnerabilities.
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
// Without this, a client can exhaust server memory with a huge payload.
// For a financial API, 1 MB (1 << 20) is a reasonable ceiling.
func BodySizeLimitMiddleware(maxBytes int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Read at most maxBytes+1 — if we get more, the body is over limit.
			// Memory cost is bounded: at most maxBytes+1 bytes allocated per request.
			limited := io.LimitReader(r.Body, maxBytes+1)
			body, err := io.ReadAll(limited)
			if err != nil {
				WriteProblem(w, r, http.StatusBadRequest, "Bad Request", "could not read request body")
				return
			}
			if int64(len(body)) > maxBytes {
				WriteProblem(w, r, http.StatusRequestEntityTooLarge,
					"Payload Too Large",
					fmt.Sprintf("request body exceeds %d byte limit", maxBytes))
				return
			}
			// Restore body so the handler can read it.
			r.Body = io.NopCloser(bytes.NewReader(body))
			next.ServeHTTP(w, r)
		})
	}
}

// RequestTimeoutMiddleware adds a deadline to every request context.
// It ensures that slow or hanging requests do not tie up server resources indefinitely.
func RequestTimeoutMiddleware(timeoutSeconds int) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, cancel := context.WithTimeout(r.Context(), time.Duration(timeoutSeconds)*time.Second)
			defer cancel()
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
