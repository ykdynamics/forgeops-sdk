package runtimecontract

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// rawCapability is a MINIMAL NON-SDK implementation of runtime.v1: it imports
// only the standard library + the dependency-free runtimecontract types, so
// the spec (docs/runtime-contract-v1.md) is provably implementable without the
// Go SDK.
func rawCapability(respond map[string]any) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+PathHealth, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("POST "+PathRun, func(w http.ResponseWriter, r *http.Request) {
		var req RunRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(ErrorResponse{Error: "invalid request body", ErrorClass: ClassInvalidInput})
			return
		}
		// The raw server never invents its own input: it acts on exactly the
		// fields the executor authorized.
		if !strings.Contains(string(req.Input), "service") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(ErrorResponse{Error: "service is required", ErrorClass: ClassInvalidInput})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(respond)
	})
	return mux
}

// TestNonSDKServerConformsToRawContract proves a capability written from the
// spec alone (no SDK) is executed correctly by the same raw executor client —
// SDK and non-SDK capabilities are interchangeable at the wire.
func TestNonSDKServerConformsToRawContract(t *testing.T) {
	srv := httptest.NewServer(rawCapability(map[string]any{"healthy": true}))
	defer srv.Close()

	c := NewClient(5 * time.Second)
	ctx := context.Background()
	if !c.Health(ctx, srv.URL) {
		t.Fatal("raw non-SDK /health did not report healthy")
	}
	ok, err := c.Run(ctx, srv.URL, RunRequest{
		RunID: "act-1", Input: json.RawMessage(`{"service":"acme"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if ok.StatusCode != http.StatusOK || ok.Error != nil || !strings.Contains(string(ok.Output), "true") {
		t.Fatalf("non-SDK success run: %+v", ok)
	}
	bad, err := c.Run(ctx, srv.URL, RunRequest{
		RunID: "act-2", Input: json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if bad.Error == nil || bad.Error.ErrorClass != ClassInvalidInput {
		t.Fatalf("non-SDK invalid-input run: %+v", bad)
	}
}
