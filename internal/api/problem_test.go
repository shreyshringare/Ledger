package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWriteProblem(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/accounts", nil)

	WriteProblem(rec, req, http.StatusBadRequest, "Invalid Input", "field 'name' is required")

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
		t.Fatalf("expected application/problem+json, got %s", ct)
	}

	var p Problem
	if err := json.NewDecoder(rec.Body).Decode(&p); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if p.Status != 400 {
		t.Errorf("expected status 400, got %d", p.Status)
	}
	if p.Title != "Invalid Input" {
		t.Errorf("expected title 'Invalid Input', got %q", p.Title)
	}
	if p.Detail != "field 'name' is required" {
		t.Errorf("expected detail, got %q", p.Detail)
	}
	if p.Instance != "/v1/accounts" {
		t.Errorf("expected instance '/v1/accounts', got %q", p.Instance)
	}
}
