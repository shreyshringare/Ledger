// internal/api/handlers_apikeys_test.go
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/shreyshringare/Ledger/internal/engine"
)

func TestCreateAPIKey(t *testing.T) {
	store := newFakeAPIKeyStore()
	h := NewHandler(nil, WithAPIKeyStore(store))

	body := `{"scope":"write"}`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/api-keys", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	h.CreateAPIKey(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]string
	json.NewDecoder(rec.Body).Decode(&resp)

	if resp["key"] == "" {
		t.Error("expected 'key' field in response")
	}
	if resp["key_id"] == "" {
		t.Error("expected 'key_id' field in response")
	}
	if len(resp["key"]) < 10 {
		t.Errorf("key looks too short: %q", resp["key"])
	}

	// Key must be persisted with a hashed secret (not plaintext)
	parts := splitKey(resp["key"])
	stored, err := store.GetAPIKeyByKeyID(context.Background(), parts[0])
	if err != nil {
		t.Fatalf("key not persisted: %v", err)
	}
	if stored.HashedSecret == parts[1] {
		t.Error("stored secret must be hashed, not plaintext")
	}
}

func TestRevokeAPIKey(t *testing.T) {
	store := newFakeAPIKeyStore()
	h := NewHandler(nil, WithAPIKeyStore(store))

	store.keys["k1"] = engine.APIKey{ID: "id-1", KeyID: "k1", Scope: "write"}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/v1/admin/api-keys/id-1", nil)
	req = setChiURLParam(req, "id", "id-1")
	h.RevokeAPIKey(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d", rec.Code)
	}
}

// splitKey splits "key_id.secret" → ["key_id", "secret"]
func splitKey(combined string) []string {
	for i, c := range combined {
		if c == '.' {
			return []string{combined[:i], combined[i+1:]}
		}
	}
	return []string{combined, ""}
}

// setChiURLParam injects a chi URL param into the request context for testing.
func setChiURLParam(r *http.Request, key, val string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add(key, val)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}
