package mcp

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/shreyshringare/Ledger/internal/engine"
)

// toolDefinition describes an MCP tool for the tools/list response.
type toolDefinition struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

// Tools holds the engine and implements all MCP tool handlers.
type Tools struct {
	engine *engine.Engine
}

// NewTools returns a Tools wired to the given engine.
func NewTools(e *engine.Engine) *Tools {
	return &Tools{engine: e}
}

// List returns all available tool definitions for tools/list.
func (t *Tools) List() []toolDefinition {
	return []toolDefinition{
		{
			Name:        "post_transaction",
			Description: "Post a double-entry transaction. Debits must equal credits.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"description": map[string]any{"type": "string"},
					"entries": map[string]any{
						"type": "array",
						"items": map[string]any{
							"type": "object",
							"properties": map[string]any{
								"account_id":   map[string]any{"type": "string"},
								"amount_minor": map[string]any{"type": "integer"},
								"is_debit":     map[string]any{"type": "boolean"},
								"currency":     map[string]any{"type": "string"},
							},
							"required": []string{"account_id", "amount_minor", "is_debit", "currency"},
						},
					},
					"currency": map[string]any{"type": "string"},
				},
				"required": []string{"description", "entries"},
			},
		},
		{
			Name:        "verify_chain",
			Description: "Verify the SHA-256 hash chain integrity of all transactions.",
			InputSchema: map[string]any{"type": "object", "properties": map[string]any{}},
		},
		{
			Name:        "detect_fraud_rings",
			Description: "Detect circular transaction patterns (fraud rings) using Tarjan's SCC algorithm.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"min_flow_minor": map[string]any{"type": "integer"},
					"min_cycle_size": map[string]any{"type": "integer"},
				},
				"required": []string{"min_cycle_size"},
			},
		},
	}
}

// Call dispatches a tools/call request to the appropriate handler.
func (t *Tools) Call(req JSONRPCRequest) JSONRPCResponse {
	var call struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &call); err != nil {
		return errorResponse(req.ID, -32602, "invalid params: "+err.Error())
	}

	ctx := context.Background()

	switch call.Name {
	case "post_transaction":
		return t.postTransaction(ctx, req.ID, call.Arguments)
	case "verify_chain":
		return t.verifyChain(ctx, req.ID)
	case "detect_fraud_rings":
		return t.detectFraudRings(ctx, req.ID, call.Arguments)
	default:
		return errorResponse(req.ID, -32601, "unknown tool: "+call.Name)
	}
}

func (t *Tools) postTransaction(ctx context.Context, id any, args json.RawMessage) JSONRPCResponse {
	var in PostTransactionInput
	if err := json.Unmarshal(args, &in); err != nil {
		return errorResponse(id, -32602, "invalid params: "+err.Error())
	}
	if err := in.Validate(); err != nil {
		return errorResponse(id, -32602, "validation failed: "+err.Error())
	}

	entries := make([]engine.Entry, len(in.Entries))
	for i, e := range in.Entries {
		accountID, err := uuid.Parse(e.AccountID)
		if err != nil {
			return errorResponse(id, -32602, fmt.Sprintf("entry %d: invalid account_id UUID: %s", i, e.AccountID))
		}
		entries[i] = engine.Entry{
			AccountID:   accountID,
			AmountMinor: e.AmountMinor,
			Currency:    e.Currency,
			IsDebit:     e.IsDebit,
		}
	}

	tx, err := t.engine.Post(ctx, in.Description, entries)
	if err != nil {
		return errorResponse(id, -32000, err.Error())
	}
	return JSONRPCResponse{JSONRPC: "2.0", ID: id, Result: tx}
}

func (t *Tools) verifyChain(ctx context.Context, id any) JSONRPCResponse {
	if err := t.engine.VerifyChain(ctx); err != nil {
		return JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      id,
			Result:  map[string]any{"valid": false, "error": err.Error()},
		}
	}
	return JSONRPCResponse{JSONRPC: "2.0", ID: id, Result: map[string]bool{"valid": true}}
}

func (t *Tools) detectFraudRings(ctx context.Context, id any, args json.RawMessage) JSONRPCResponse {
	var in FraudRingInput
	if err := json.Unmarshal(args, &in); err != nil {
		return errorResponse(id, -32602, "invalid params: "+err.Error())
	}
	if err := in.Validate(); err != nil {
		return errorResponse(id, -32602, "validation failed: "+err.Error())
	}

	txs, err := t.engine.Store().ListTransactions(ctx)
	if err != nil {
		return errorResponse(id, -32000, "list transactions: "+err.Error())
	}

	// Build directed graph: account → account for each transaction entry pair.
	// A→B if A debits and B credits in the same transaction (money flows from A to B).
	type edge struct{ from, to string }
	edgeSet := make(map[edge]int64)
	for _, tx := range txs {
		var debitors, creditors []engine.Entry
		for _, e := range tx.Entries {
			if e.IsDebit {
				debitors = append(debitors, e)
			} else {
				creditors = append(creditors, e)
			}
		}
		for _, d := range debitors {
			for _, c := range creditors {
				key := edge{d.AccountID.String(), c.AccountID.String()}
				edgeSet[key] += d.AmountMinor
			}
		}
	}

	// Filter by min flow.
	adjList := make(map[string][]string)
	for e, flow := range edgeSet {
		if flow >= in.MinFlowMinor {
			adjList[e.from] = append(adjList[e.from], e.to)
		}
	}

	// Tarjan's SCC to find fraud rings.
	rings := tarjanSCC(adjList, in.MinCycleSize)
	return JSONRPCResponse{JSONRPC: "2.0", ID: id, Result: map[string]any{"rings": rings, "count": len(rings)}}
}

// tarjanSCC runs Tarjan's strongly connected components algorithm on adjList
// and returns components with size >= minSize.
func tarjanSCC(adjList map[string][]string, minSize int) [][]string {
	index := 0
	stack := []string{}
	onStack := map[string]bool{}
	indices := map[string]int{}
	lowlink := map[string]int{}
	var sccs [][]string

	var strongconnect func(v string)
	strongconnect = func(v string) {
		indices[v] = index
		lowlink[v] = index
		index++
		stack = append(stack, v)
		onStack[v] = true

		for _, w := range adjList[v] {
			if _, seen := indices[w]; !seen {
				strongconnect(w)
				if lowlink[w] < lowlink[v] {
					lowlink[v] = lowlink[w]
				}
			} else if onStack[w] {
				if indices[w] < lowlink[v] {
					lowlink[v] = indices[w]
				}
			}
		}

		if lowlink[v] == indices[v] {
			var scc []string
			for {
				w := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				onStack[w] = false
				scc = append(scc, w)
				if w == v {
					break
				}
			}
			if len(scc) >= minSize {
				sccs = append(sccs, scc)
			}
		}
	}

	for v := range adjList {
		if _, seen := indices[v]; !seen {
			strongconnect(v)
		}
	}
	return sccs
}
