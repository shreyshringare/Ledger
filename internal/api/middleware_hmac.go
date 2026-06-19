// internal/api/middleware_hmac.go
package api

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

// HMACMiddleware verifies HMAC-SHA256 request signatures.
//
// The client must compute:
//
//	message = "{METHOD}\n{PATH}\n{sha256(body)_hex}\n{unix_timestamp}"
//	signature = HMAC-SHA256(key=shared_secret, message=message)
//
// And send:
//
//	X-Signature: <hex_signature>
//	X-Timestamp: <unix_timestamp>
//
// Why HMAC and not just the API key?
//   - An API key proves identity. HMAC proves the request body wasn't modified in transit.
//   - The timestamp prevents replay attacks: an intercepted request can't be resent after 5 minutes.
//   - This is the exact pattern used by Stripe webhooks and Twilio callbacks.
func HMACMiddleware(sharedSecret string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sig := r.Header.Get("X-Signature")
			tsStr := r.Header.Get("X-Timestamp")

			if sig == "" || tsStr == "" {
				WriteProblem(w, r, http.StatusUnauthorized,
					"Unauthorized", "X-Signature and X-Timestamp headers are required")
				return
			}

			ts, err := strconv.ParseInt(tsStr, 10, 64)
			if err != nil {
				WriteProblem(w, r, http.StatusUnauthorized, "Unauthorized", "invalid X-Timestamp")
				return
			}

			// Reject requests with timestamps older than 5 minutes — prevents replay attacks
			age := time.Since(time.Unix(ts, 0))
			if age > 5*time.Minute || age < -1*time.Minute {
				WriteProblem(w, r, http.StatusUnauthorized,
					"Unauthorized", "request timestamp is outside the 5-minute window")
				return
			}

			// Read body to verify its hash — then restore it for the handler
			body, err := io.ReadAll(r.Body)
			if err != nil {
				WriteProblem(w, r, http.StatusBadRequest, "Bad Request", "failed to read request body")
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))

			// Recompute expected signature
			bodyHash := sha256.Sum256(body)
			message := fmt.Sprintf("%s\n%s\n%s\n%d",
				r.Method, r.URL.RequestURI(), hex.EncodeToString(bodyHash[:]), ts)

			mac := hmac.New(sha256.New, []byte(sharedSecret))
			mac.Write([]byte(message))
			expected := mac.Sum(nil)

			// Decode client signature
			sigBytes, err := hex.DecodeString(sig)
			if err != nil {
				WriteProblem(w, r, http.StatusUnauthorized, "Unauthorized", "invalid X-Signature encoding")
				return
			}

			// hmac.Equal is constant-time — prevents timing attacks
			if !hmac.Equal(sigBytes, expected) {
				WriteProblem(w, r, http.StatusUnauthorized, "Unauthorized", "invalid request signature")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
