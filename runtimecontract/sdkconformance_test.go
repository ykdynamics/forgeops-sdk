package runtimecontract_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ykdynamics/forgeops-sdk/runtimecontract"
	"github.com/ykdynamics/forgeops-sdk/sdk"
)

// TestSDKHandlerConformsToRawContract proves the Go SDK (the REFERENCE
// implementation of runtime.v1) matches the raw contract exactly — driven by
// the dependency-free runtimecontract client as an external consumer would,
// with no sdk test helpers.
func TestSDKHandlerConformsToRawContract(t *testing.T) {
	handler := sdk.NewHandler(func(ctx context.Context, rc *sdk.Context) (any, error) {
		var in struct {
			Service string `json:"service"`
		}
		if err := rc.Bind(&in); err != nil {
			return nil, err
		}
		return map[string]any{"healthy": in.Service != ""}, nil
	}, sdk.WithContract(&sdk.Contract{
		InputSchema:  json.RawMessage(`{"type":"object","required":["service"],"properties":{"service":{"type":"string"}}}`),
		OutputSchema: json.RawMessage(`{"type":"object","required":["healthy"],"properties":{"healthy":{"type":"boolean"}}}`),
	}))
	srv := httptest.NewServer(handler)
	defer srv.Close()

	c := runtimecontract.NewClient(5 * time.Second)
	ctx := context.Background()

	if !c.Health(ctx, srv.URL) {
		t.Fatal("raw /health did not report healthy")
	}

	// Successful run → 200 + the output JSON directly (no wrapper).
	good, err := c.Run(ctx, srv.URL, runtimecontract.RunRequest{
		RunID: "act-1", Input: json.RawMessage(`{"service":"acme"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if good.StatusCode != http.StatusOK || good.Error != nil {
		t.Fatalf("success run: %+v", good)
	}
	var out struct {
		Healthy bool `json:"healthy"`
	}
	if err := json.Unmarshal(good.Output, &out); err != nil || !out.Healthy {
		t.Fatalf("success output = %s (err %v)", good.Output, err)
	}

	// Invalid input → 400 + the structured error envelope; the class is the
	// machine-readable contract value.
	bad, err := c.Run(ctx, srv.URL, runtimecontract.RunRequest{
		RunID: "act-2", Input: json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if bad.StatusCode != http.StatusBadRequest || bad.Error == nil || bad.Error.ErrorClass != runtimecontract.ClassInvalidInput {
		t.Fatalf("invalid-input run: %+v", bad)
	}
}

// TestRunContextDeliveredToCapability: the canonical attempt identity
// rides the run envelope and the SDK exposes it — the capability takes its
// authoritative action id from the context, never one assembled from input.
func TestRunContextDeliveredToCapability(t *testing.T) {
	var gotActionID, gotTenant string
	var gotAttempt int
	handler := sdk.NewHandler(func(ctx context.Context, rc *sdk.Context) (any, error) {
		if rc.Attempt != nil {
			gotActionID = rc.Attempt.ActionID
			gotTenant = rc.Attempt.TenantID
			gotAttempt = rc.Attempt.AttemptNumber
		}
		return map[string]any{"ok": true}, nil
	})
	srv := httptest.NewServer(handler)
	defer srv.Close()

	c := runtimecontract.NewClient(5 * time.Second)
	res, err := c.Run(context.Background(), srv.URL, runtimecontract.RunRequest{
		RunID: "act-lineage",
		Input: json.RawMessage(`{"service":"acme"}`),
		Context: &runtimecontract.RunContext{
			ActionID: "act-9", TenantID: "tenant-a", Environment: "env-1",
			AttemptNumber: 3, IdempotencyKey: "req-77",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusOK || res.Error != nil {
		t.Fatalf("context run: %+v", res)
	}
	if gotActionID != "act-9" || gotTenant != "tenant-a" || gotAttempt != 3 {
		t.Fatalf("capability received action=%q tenant=%q attempt=%d", gotActionID, gotTenant, gotAttempt)
	}
}
