package unit_test

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/shreyshringare/Ledger/internal/engine"
	"github.com/shreyshringare/Ledger/internal/mcp"
)

// fakeMCPStore implements engine.Store for MCP integration tests.
// It is safe for sequential use only; no locking is needed in tests.
type fakeMCPStore struct {
	accounts     map[string]engine.Account
	transactions []engine.Transaction
}

func newFakeMCPStore() *fakeMCPStore {
	return &fakeMCPStore{
		accounts: make(map[string]engine.Account),
	}
}

func (f *fakeMCPStore) CreateAccount(_ context.Context, acc engine.Account) error {
	f.accounts[acc.ID.String()] = acc
	return nil
}

func (f *fakeMCPStore) GetAccount(_ context.Context, id string) (engine.Account, error) {
	acc, ok := f.accounts[id]
	if !ok {
		return engine.Account{}, fmt.Errorf("account %s not found", id)
	}
	return acc, nil
}

func (f *fakeMCPStore) GetAccountByName(_ context.Context, name string) (engine.Account, error) {
	for _, acc := range f.accounts {
		if acc.Name == name {
			return acc, nil
		}
	}
	return engine.Account{}, fmt.Errorf("account %q not found", name)
}

func (f *fakeMCPStore) ListAccounts(_ context.Context) ([]engine.Account, error) {
	var out []engine.Account
	for _, acc := range f.accounts {
		if acc.ArchivedAt == nil {
			out = append(out, acc)
		}
	}
	return out, nil
}

func (f *fakeMCPStore) ArchiveAccount(_ context.Context, id string) error {
	acc, ok := f.accounts[id]
	if !ok {
		return fmt.Errorf("account %s not found", id)
	}
	now := time.Now()
	acc.ArchivedAt = &now
	f.accounts[id] = acc
	return nil
}

func (f *fakeMCPStore) PostTransaction(_ context.Context, tx engine.Transaction) (engine.Transaction, error) {
	prevHash := "genesis"
	if len(f.transactions) > 0 {
		prevHash = f.transactions[len(f.transactions)-1].Hash
	}
	tx.PrevHash = prevHash

	hash, err := tx.ComputeHash(prevHash)
	if err != nil {
		return engine.Transaction{}, fmt.Errorf("compute hash: %w", err)
	}
	tx.Hash = hash

	f.transactions = append(f.transactions, tx)
	return tx, nil
}

func (f *fakeMCPStore) GetTransaction(_ context.Context, id string) (engine.Transaction, error) {
	for _, tx := range f.transactions {
		if tx.ID.String() == id {
			return tx, nil
		}
	}
	return engine.Transaction{}, fmt.Errorf("transaction %s not found", id)
}

func (f *fakeMCPStore) ListTransactions(_ context.Context) ([]engine.Transaction, error) {
	return f.transactions, nil
}

func (f *fakeMCPStore) ListTransactionsPaginated(_ context.Context, _, _ int) ([]engine.Transaction, error) {
	return nil, nil
}

func (f *fakeMCPStore) GetBalance(_ context.Context, accountID string, currency string) (int64, error) {
	var sum int64
	for _, tx := range f.transactions {
		for _, e := range tx.Entries {
			if e.AccountID.String() == accountID && e.Currency == currency {
				if e.IsDebit {
					sum += e.AmountMinor
				} else {
					sum -= e.AmountMinor
				}
			}
		}
	}
	return sum, nil
}

func (f *fakeMCPStore) CheckIdempotencyKey(_ context.Context, _ string) ([]byte, bool, error) {
	return nil, false, nil
}

func (f *fakeMCPStore) SaveIdempotencyKey(_ context.Context, _ string, _ uuid.UUID, _ []byte) error {
	return nil
}

func (f *fakeMCPStore) DeleteExpiredIdempotencyKeys(_ context.Context) error {
	return nil
}

// newMCPServer wires up a fresh engine + MCP server backed by fakeMCPStore.
func newMCPServer() (*mcp.Server, *fakeMCPStore) {
	store := newFakeMCPStore()
	e := engine.NewEngine(store)
	tools := mcp.NewTools(e)
	server := mcp.NewServer(tools)
	return server, store
}

// handleJSON is a helper that builds a JSONRPCRequest from raw JSON and calls Handle.
func handleJSON(t *testing.T, server *mcp.Server, raw string) mcp.JSONRPCResponse {
	t.Helper()
	var req mcp.JSONRPCRequest
	if err := json.Unmarshal([]byte(raw), &req); err != nil {
		t.Fatalf("failed to build request: %v", err)
	}
	return server.Handle(req)
}

// TestMCPPostTransaction_Valid posts a balanced transaction and expects success.
func TestMCPPostTransaction_Valid(t *testing.T) {
	server, store := newMCPServer()

	// Pre-seed two accounts so uuid.Parse succeeds when the tool builds entries.
	cashID := uuid.New()
	revenueID := uuid.New()
	store.accounts[cashID.String()] = engine.Account{
		ID:       cashID,
		Name:     "Cash",
		Type:     engine.Asset,
		Currency: "INR",
		IsActive: true,
	}
	store.accounts[revenueID.String()] = engine.Account{
		ID:       revenueID,
		Name:     "Revenue",
		Type:     engine.Revenue,
		Currency: "INR",
		IsActive: true,
	}

	reqJSON := fmt.Sprintf(`{
		"jsonrpc": "2.0",
		"id": 1,
		"method": "tools/call",
		"params": {
			"name": "post_transaction",
			"arguments": {
				"description": "Sale of goods",
				"entries": [
					{"account_id": %q, "amount_minor": 10000, "is_debit": true,  "currency": "INR"},
					{"account_id": %q, "amount_minor": 10000, "is_debit": false, "currency": "INR"}
				]
			}
		}
	}`, cashID.String(), revenueID.String())

	resp := handleJSON(t, server, reqJSON)

	if resp.Error != nil {
		t.Fatalf("expected no error, got code=%d msg=%s", resp.Error.Code, resp.Error.Message)
	}
	if resp.Result == nil {
		t.Fatal("expected non-nil result")
	}
}

// TestMCPPostTransaction_NegativeAmount verifies that a negative amount is rejected at the MCP boundary.
func TestMCPPostTransaction_NegativeAmount(t *testing.T) {
	server, store := newMCPServer()

	cashID := uuid.New()
	revenueID := uuid.New()
	store.accounts[cashID.String()] = engine.Account{ID: cashID, Name: "Cash", Type: engine.Asset, Currency: "INR", IsActive: true}
	store.accounts[revenueID.String()] = engine.Account{ID: revenueID, Name: "Revenue", Type: engine.Revenue, Currency: "INR", IsActive: true}

	reqJSON := fmt.Sprintf(`{
		"jsonrpc": "2.0",
		"id": 2,
		"method": "tools/call",
		"params": {
			"name": "post_transaction",
			"arguments": {
				"description": "Bad entry",
				"entries": [
					{"account_id": %q, "amount_minor": -100, "is_debit": true,  "currency": "INR"},
					{"account_id": %q, "amount_minor": -100, "is_debit": false, "currency": "INR"}
				]
			}
		}
	}`, cashID.String(), revenueID.String())

	resp := handleJSON(t, server, reqJSON)

	if resp.Error == nil {
		t.Fatal("expected error for negative amount, got nil")
	}
	if resp.Error.Code != -32602 {
		t.Fatalf("expected code -32602, got %d", resp.Error.Code)
	}
}

// TestMCPPostTransaction_MissingAccountID verifies that a blank account_id is rejected at the MCP boundary.
func TestMCPPostTransaction_MissingAccountID(t *testing.T) {
	server, _ := newMCPServer()

	reqJSON := `{
		"jsonrpc": "2.0",
		"id": 3,
		"method": "tools/call",
		"params": {
			"name": "post_transaction",
			"arguments": {
				"description": "Missing account",
				"entries": [
					{"account_id": "",  "amount_minor": 500, "is_debit": true,  "currency": "INR"},
					{"account_id": "",  "amount_minor": 500, "is_debit": false, "currency": "INR"}
				]
			}
		}
	}`

	resp := handleJSON(t, server, reqJSON)

	if resp.Error == nil {
		t.Fatal("expected error for missing account_id, got nil")
	}
	if resp.Error.Code != -32602 {
		t.Fatalf("expected code -32602, got %d", resp.Error.Code)
	}
}

// TestMCPPostTransaction_BadCurrency verifies that a non-3-char currency is rejected at the MCP boundary.
func TestMCPPostTransaction_BadCurrency(t *testing.T) {
	server, store := newMCPServer()

	cashID := uuid.New()
	revenueID := uuid.New()
	store.accounts[cashID.String()] = engine.Account{ID: cashID, Name: "Cash", Type: engine.Asset, Currency: "INR", IsActive: true}
	store.accounts[revenueID.String()] = engine.Account{ID: revenueID, Name: "Revenue", Type: engine.Revenue, Currency: "INR", IsActive: true}

	reqJSON := fmt.Sprintf(`{
		"jsonrpc": "2.0",
		"id": 4,
		"method": "tools/call",
		"params": {
			"name": "post_transaction",
			"arguments": {
				"description": "Bad currency",
				"entries": [
					{"account_id": %q, "amount_minor": 200, "is_debit": true,  "currency": "INVALID"},
					{"account_id": %q, "amount_minor": 200, "is_debit": false, "currency": "INVALID"}
				]
			}
		}
	}`, cashID.String(), revenueID.String())

	resp := handleJSON(t, server, reqJSON)

	if resp.Error == nil {
		t.Fatal("expected error for bad currency, got nil")
	}
	if resp.Error.Code != -32602 {
		t.Fatalf("expected code -32602, got %d", resp.Error.Code)
	}
}

// TestMCPVerifyChain_Valid confirms that an empty chain reports valid == true.
func TestMCPVerifyChain_Valid(t *testing.T) {
	server, _ := newMCPServer()

	reqJSON := `{
		"jsonrpc": "2.0",
		"id": 5,
		"method": "tools/call",
		"params": {
			"name": "verify_chain",
			"arguments": {}
		}
	}`

	resp := handleJSON(t, server, reqJSON)

	if resp.Error != nil {
		t.Fatalf("expected no error, got code=%d msg=%s", resp.Error.Code, resp.Error.Message)
	}

	// Result should be map[string]bool{"valid": true}
	raw, err := json.Marshal(resp.Result)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	var result map[string]any
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	valid, ok := result["valid"]
	if !ok {
		t.Fatal(`result missing "valid" field`)
	}
	if valid != true {
		t.Fatalf(`expected "valid" == true, got %v`, valid)
	}
}

// TestMCPDetectFraudRings_InvalidMinCycleSize ensures min_cycle_size < 2 is rejected at the MCP boundary.
func TestMCPDetectFraudRings_InvalidMinCycleSize(t *testing.T) {
	server, _ := newMCPServer()

	reqJSON := `{
		"jsonrpc": "2.0",
		"id": 6,
		"method": "tools/call",
		"params": {
			"name": "detect_fraud_rings",
			"arguments": {
				"min_cycle_size": 1
			}
		}
	}`

	resp := handleJSON(t, server, reqJSON)

	if resp.Error == nil {
		t.Fatal("expected error for min_cycle_size < 2, got nil")
	}
	if resp.Error.Code != -32602 {
		t.Fatalf("expected code -32602, got %d", resp.Error.Code)
	}
}
