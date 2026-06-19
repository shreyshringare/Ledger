package api

import (
	"net/http"
	"sync"
	"time"
)

// rateLimiter holds per-key sliding window state.
// Why sliding window: a fixed window allows 2x the limit at window boundaries.
// Sliding window tracks the actual last N seconds, preventing burst exploitation.
type rateLimiter struct {
	mu       sync.Mutex
	windows  map[string]*slidingWindow
	limit    int
	windowSz time.Duration
}

type slidingWindow struct {
	mu       sync.Mutex
	requests []time.Time
}

func newRateLimiter(requestsPerWindow int, windowSeconds int) *rateLimiter {
	rl := &rateLimiter{
		windows:  make(map[string]*slidingWindow),
		limit:    requestsPerWindow,
		windowSz: time.Duration(windowSeconds) * time.Second,
	}
	go rl.cleanup()
	return rl
}

func (rl *rateLimiter) allow(key string) bool {
	rl.mu.Lock()
	w, ok := rl.windows[key]
	if !ok {
		w = &slidingWindow{}
		rl.windows[key] = w
	}
	rl.mu.Unlock()

	w.mu.Lock()
	defer w.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-rl.windowSz)

	i := 0
	for i < len(w.requests) && w.requests[i].Before(cutoff) {
		i++
	}
	w.requests = w.requests[i:]

	if len(w.requests) >= rl.limit {
		return false
	}
	w.requests = append(w.requests, now)
	return true
}

func (rl *rateLimiter) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		cutoff := time.Now().Add(-rl.windowSz)
		rl.mu.Lock()
		for key, w := range rl.windows {
			w.mu.Lock()
			if len(w.requests) == 0 || w.requests[len(w.requests)-1].Before(cutoff) {
				delete(rl.windows, key)
			}
			w.mu.Unlock()
		}
		rl.mu.Unlock()
	}
}

// InitRateLimiter configures the rate limiter on the Handler.
// Called once at server startup. Default production: 100 req/60s per API key.
func (h *Handler) InitRateLimiter(requestsPerWindow, windowSeconds int) {
	h.rl = newRateLimiter(requestsPerWindow, windowSeconds)
}

// RateLimitMiddleware enforces per-API-key rate limits.
// Must run AFTER APIKeyAuthMiddleware so key_id is in context.
func (h *Handler) RateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		keyID, _ := r.Context().Value(contextKeyAPIKeyID).(string)
		if keyID == "" {
			next.ServeHTTP(w, r)
			return
		}

		if h.rl == nil || !h.rl.allow(keyID) {
			w.Header().Set("Retry-After", "60")
			WriteProblem(w, r, http.StatusTooManyRequests,
				"Too Many Requests", "rate limit exceeded — retry after 60 seconds")
			return
		}

		next.ServeHTTP(w, r)
	})
}
