package api

import (
	"encoding/json"
	"net/http"
	"strings"
)

// Problem is an RFC 9457 problem details object.
// https://www.rfc-editor.org/rfc/rfc9457
//
// Why RFC 9457 instead of {"error":"..."}:
//   - Machine-readable: clients branch on `type` URI, not string matching
//   - `instance` ties the error to the exact request path — useful in logs
//   - Standard used by Stripe, Plaid, Visa Developer APIs, Mastercard Developers
type Problem struct {
	Type     string `json:"type"`
	Title    string `json:"title"`
	Status   int    `json:"status"`
	Detail   string `json:"detail,omitempty"`
	Instance string `json:"instance,omitempty"`
}

// WriteProblem writes an RFC 9457 problem details response.
// Use this for every error response — never write {"error":"..."} directly.
func WriteProblem(w http.ResponseWriter, r *http.Request, status int, title, detail string) {
	p := Problem{
		Type:     "https://ledger.example.com/errors/" + titleToSlug(title),
		Title:    title,
		Status:   status,
		Detail:   detail,
		Instance: r.URL.RequestURI(),
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(p) //nolint:errcheck
}

// titleToSlug converts "Invalid Input" → "invalid-input" for the type URI.
func titleToSlug(s string) string {
	return strings.ToLower(strings.ReplaceAll(s, " ", "-"))
}
