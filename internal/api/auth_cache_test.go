// internal/api/auth_cache_test.go
package api

import (
	"testing"
	"time"
)

func TestBcryptCache_MissOnFirstCall(t *testing.T) {
	c := newBcryptCache(30*time.Second, 100)
	_, found := c.Get("mysecret")
	if found {
		t.Error("expected cache miss on first call")
	}
}

func TestBcryptCache_HitOnSecondCall(t *testing.T) {
	c := newBcryptCache(30*time.Second, 100)
	c.Set("mysecret", true)
	matched, found := c.Get("mysecret")
	if !found {
		t.Error("expected cache hit on second call")
	}
	if !matched {
		t.Error("expected matched=true")
	}
}

func TestBcryptCache_ExpiryAfterTTL(t *testing.T) {
	c := newBcryptCache(10*time.Millisecond, 100)
	c.Set("mysecret", true)
	time.Sleep(15 * time.Millisecond)
	_, found := c.Get("mysecret")
	if found {
		t.Error("expected cache miss after TTL expiry")
	}
}

func TestBcryptCache_EvictionAtMaxSize(t *testing.T) {
	c := newBcryptCache(1*time.Millisecond, 2) // maxSize=2
	c.Set("key1", true)
	c.Set("key2", true)
	time.Sleep(5 * time.Millisecond) // expire both
	// Adding key3 should trigger eviction of expired entries
	c.Set("key3", true)
	if len(c.entries) > 2 {
		t.Errorf("expected eviction, entries=%d", len(c.entries))
	}
	_, found := c.Get("key3")
	if !found {
		t.Error("key3 should be in cache after eviction")
	}
}
