// internal/api/auth_cache.go
package api

import (
	"crypto/sha256"
	"fmt"
	"sync"
	"time"
)

// bcryptCacheEntry stores a cached bcrypt verification result.
type bcryptCacheEntry struct {
	matched   bool
	expiresAt time.Time
}

// bcryptCache is a simple TTL cache for bcrypt verification results.
// Key: sha256(api_key_secret), Value: match result + expiry.
// Security: we never store the raw secret — only its SHA-256 hash.
// A revoked key stops working within TTL seconds (default 30s).
type bcryptCache struct {
	mu      sync.RWMutex
	entries map[string]bcryptCacheEntry
	ttl     time.Duration
	maxSize int
}

func newBcryptCache(ttl time.Duration, maxSize int) *bcryptCache {
	return &bcryptCache{
		entries: make(map[string]bcryptCacheEntry, maxSize),
		ttl:     ttl,
		maxSize: maxSize,
	}
}

func cacheKey(secret string) string {
	h := sha256.Sum256([]byte(secret))
	return fmt.Sprintf("%x", h)
}

// Get returns (matched, found). found=false means cache miss.
func (c *bcryptCache) Get(secret string) (bool, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, ok := c.entries[cacheKey(secret)]
	if !ok || time.Now().After(entry.expiresAt) {
		return false, false
	}
	return entry.matched, true
}

// Set stores a bcrypt result with TTL. Evicts expired entries if at capacity.
func (c *bcryptCache) Set(secret string, matched bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= c.maxSize {
		now := time.Now()
		for k, v := range c.entries {
			if now.After(v.expiresAt) {
				delete(c.entries, k)
			}
		}
	}
	c.entries[cacheKey(secret)] = bcryptCacheEntry{
		matched:   matched,
		expiresAt: time.Now().Add(c.ttl),
	}
}
