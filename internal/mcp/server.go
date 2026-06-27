package mcp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// JSONRPCRequest is a JSON-RPC 2.0 request.
type JSONRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

// JSONRPCResponse is a JSON-RPC 2.0 response.
type JSONRPCResponse struct {
	JSONRPC string    `json:"jsonrpc"`
	ID      any       `json:"id"`
	Result  any       `json:"result,omitempty"`
	Error   *RPCError `json:"error,omitempty"`
}

// RPCError is a JSON-RPC 2.0 error object.
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Server implements a minimal MCP-compliant JSON-RPC 2.0 handler.
// MCP wire protocol is JSON-RPC 2.0 with two methods: "tools/list" and "tools/call".
type Server struct {
	tools *Tools
}

// NewServer returns a Server wired to the given Tools handler.
func NewServer(t *Tools) *Server {
	return &Server{tools: t}
}

// Handle dispatches a single JSON-RPC 2.0 request.
func (s *Server) Handle(req JSONRPCRequest) JSONRPCResponse {
	switch req.Method {
	case "tools/list":
		return JSONRPCResponse{JSONRPC: "2.0", ID: req.ID, Result: s.tools.List()}
	case "tools/call":
		return s.tools.Call(req)
	default:
		return errorResponse(req.ID, -32601, "method not found: "+req.Method)
	}
}

// ServeStdio reads newline-delimited JSON-RPC requests from r and writes responses to w.
// Blocks until r is closed.
func (s *Server) ServeStdio(r io.Reader, w io.Writer) error {
	scanner := bufio.NewScanner(r)
	enc := json.NewEncoder(w)
	for scanner.Scan() {
		var req JSONRPCRequest
		if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
			resp := errorResponse(nil, -32700, "parse error: "+err.Error())
			_ = enc.Encode(resp)
			continue
		}
		resp := s.Handle(req)
		if err := enc.Encode(resp); err != nil {
			return fmt.Errorf("encode response: %w", err)
		}
	}
	return scanner.Err()
}

// ServeHTTP implements http.Handler so the server can be mounted on a Chi router.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var req JSONRPCRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(errorResponse(nil, -32700, "parse error: "+err.Error()))
		return
	}
	resp := s.Handle(req)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func errorResponse(id any, code int, msg string) JSONRPCResponse {
	return JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error:   &RPCError{Code: code, Message: msg},
	}
}
