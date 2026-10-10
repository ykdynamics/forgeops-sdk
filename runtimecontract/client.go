// Package runtimecontract is the machine-readable, dependency-free form of the
// normative capability runtime contract v1 (WP-R5.2b, capabilities#42) — see
// docs/runtime-contract-v1.md. The Go SDK (sdk/) is the REFERENCE
// implementation of this contract; this package exists so any implementation
// (any language) can be built and verified against the same wire semantics
// without importing the SDK.
//
// It intentionally imports only the Go standard library.
package runtimecontract

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Version is the normative contract version a capability declares in its
// canonical package (runtime.runtimeContract) and the SDK speaks.
const Version = "runtime.v1"

// Endpoint paths a capability serves.
const (
	PathHealth = "/health"
	PathRun    = "/run"
)

// Error classes a structured run failure carries (mirrors sdk.ErrorClass).
const (
	ClassInvalidInput  = "invalid_input"
	ClassInvalidOutput = "invalid_output"
	ClassTimeout       = "timeout"
	ClassDenied        = "denied"
	ClassInternal      = "internal"
)

// RunRequest is the executor -> capability envelope (POST /run body).
type RunRequest struct {
	RunID        string          `json:"run_id"`
	Input        json.RawMessage `json:"input"`
	RuntimeToken string          `json:"runtime_token"`
	RuntimeURL   string          `json:"runtime_url"`
	Deadline     string          `json:"deadline,omitempty"`
	// Context (WP-R5.2b) is the canonical attempt identity the executor
	// delivers with the run. The capability takes its authoritative action id
	// from HERE — never one assembled from the input. Optional: executors that
	// predate the context send only run_id + input.
	Context *RunContext `json:"context,omitempty"`
}

// RunContext is the canonical attempt/action identity of one run (WP-R5.2b).
// It mirrors the agent's canonical dispatch bindings so a capability knows the
// exact action lineage it is being asked to perform and can keep its
// intended-effect receipt stable across retries.
type RunContext struct {
	ActionID           string `json:"action_id"`
	TenantID           string `json:"tenant_id"`
	Environment        string `json:"environment"`
	AttemptNumber      int    `json:"attempt_number"`
	IdempotencyKey     string `json:"idempotency_key"`
	WorkflowInstanceID string `json:"workflow_instance_id,omitempty"`
	StepID             string `json:"step_id,omitempty"`
}

// ErrorResponse is the structured failure body a capability returns.
type ErrorResponse struct {
	Error      string `json:"error"`
	ErrorClass string `json:"error_class"`
}

// Client executes runs against a capability speaking runtime.v1, using only
// the raw contract (stdlib http) — the non-SDK executor perspective (the
// ForgeOps edge's runtime client mirrors this).
type Client struct {
	HTTP *http.Client
}

// NewClient builds a raw runtime.v1 executor client.
func NewClient(timeout time.Duration) *Client {
	return &Client{HTTP: &http.Client{Timeout: timeout}}
}

// Health reports whether the capability is serving.
func (c *Client) Health(ctx context.Context, baseURL string) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+PathHealth, nil)
	if err != nil {
		return false
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// RunResult is the outcome of one raw run.
type RunResult struct {
	StatusCode int
	// Output is the 200 response body when the run succeeded.
	Output json.RawMessage
	// Error is the structured failure when the run failed.
	Error *ErrorResponse
}

// Run POSTs one invocation per the raw contract. A 200 means the output is the
// run's result; any other status MUST carry a structured error body.
func (c *Client) Run(ctx context.Context, baseURL string, req RunRequest) (*RunResult, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("runtime.v1: marshal run request: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+PathRun, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("runtime.v1: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("runtime.v1: read response: %w", err)
	}
	if resp.StatusCode == http.StatusOK {
		return &RunResult{StatusCode: resp.StatusCode, Output: raw}, nil
	}
	var e ErrorResponse
	if json.Unmarshal(raw, &e) == nil && e.Error != "" {
		return &RunResult{StatusCode: resp.StatusCode, Error: &e}, nil
	}
	return &RunResult{StatusCode: resp.StatusCode, Error: &ErrorResponse{Error: string(raw), ErrorClass: ClassInternal}}, nil
}
