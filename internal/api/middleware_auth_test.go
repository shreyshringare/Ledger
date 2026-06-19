package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/shreyshringare/Ledger/internal/engine"
)

type fakeAPIKeyStore struct {
	keys map[string]engine.APIKey
}

func newFakeAPIKeyStore() *fakeAPIKeyStore {
	return &fakeAPIKeyStore{keys: make(map[string]engine.APIKey)}
}

func (f *fakeAPIKeyStore) CreateAPIKey(_ context.Context, key engine.APIKey) error {
	f.keys[key.KeyID] = key
	return nil
}

func (f *fakeAPIKeyStore) GetAPIKeyByKeyID(_ context.Context, keyID string) (engine.APIKey, error) {
	k, ok := f.keys[keyID]
	if !ok {
		return engine.APIKey{}, fmt.Errorf("not found")
	}
	return k, nil
}

func (f *fakeAPIKeyStore) RevokeAPIKey(_ context.Context, id string) error { return nil }

func (f *fakeAPIKeyStore) UpdateAPIKeyLastUsed(_ context.Context, id string) error { return nil }

func setupAuthTest(t *testing.T) (*Handler, *fakeAPIKeyStore, string) {
	t.Helper()
	store := newFakeAPIKeyStore()
	h := NewHandler(nil, WithAPIKeyStore(store))

	secret := "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	key := engine.APIKey{
		ID:           "test-id",
		KeyID:        "test-key-id",
		HashedSecret: string(hash),
		Scope:        "write",
		CreatedAt:    time.Now(),
	}
	store.keys[key.KeyID] = key

	validHeader := key.KeyID + "." + secret
	return h, store, validHeader
}

func TestAPIKeyAuthMiddleware_Valid(t *testing.T) {
	h, _, validHeader := setupAuthTest(t)

	var gotKeyID string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKeyID, _ = r.Context().Value(contextKeyAPIKeyID).(string)
		w.WriteHeader(http.StatusOK)
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/accounts", nil)
	req.Header.Set("X-API-Key", validHeader)
	h.APIKeyAuthMiddleware(next).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if gotKeyID != "test-key-id" {
		t.Errorf("expected key_id in context, got %q", gotKeyID)
	}
}

func TestAPIKeyAuthMiddleware_MissingHeader(t *testing.T) {
	h, _, _ := setupAuthTest(t)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/accounts", nil)
	h.APIKeyAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

func TestAPIKeyAuthMiddleware_WrongSecret(t *testing.T) {
	h, _, _ := setupAuthTest(t)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/accounts", nil)
	req.Header.Set("X-API-Key", "test-key-id.wrongsecretwrongsecretwrongsecretwrongsecretwrongsecretwrongsecret")
	h.APIKeyAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

func TestAPIKeyAuthMiddleware_RevokedKey(t *testing.T) {
	h, store, validHeader := setupAuthTest(t)
	revokedAt := time.Now()
	k := store.keys["test-key-id"]
	k.RevokedAt = &revokedAt
	store.keys["test-key-id"] = k

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/accounts", nil)
	req.Header.Set("X-API-Key", validHeader)
	h.APIKeyAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for revoked key, got %d", rec.Code)
	}
}
