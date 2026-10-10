package sdk

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func runRequest(t *testing.T, h http.Handler, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader([]byte(body)))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

// TestConformance_InvalidInputRejectedBeforeImplementation: invalid input fails
// the run and the implementation never runs.
func TestConformance_InvalidInputRejectedBeforeImplementation(t *testing.T) {
	var invoked atomic.Bool
	h := NewHandler(func(ctx context.Context, rc *Context) (any, error) {
		invoked.Store(true)
		return map[string]any{"appointments": []any{}}, nil
	}, WithContract(&Contract{
		Version:     "1.0.0",
		Risk:        "allow",
		InputSchema: json.RawMessage(`{"type":"object","required":["date"],"additionalProperties":false,"properties":{"date":{"type":"string"}}}`),
	}))

	w := runRequest(t, h, `{"run_id":"r","input":{"slot_start":"2026-09-02"}}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("code = %d body = %s", w.Code, w.Body.String())
	}
	if invoked.Load() {
		t.Fatal("the implementation must not run for invalid input")
	}
	var resp struct {
		Class string `json:"error_class"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Class != string(ClassInvalidInput) {
		t.Fatalf("error_class = %q, want invalid_input", resp.Class)
	}
}

// TestConformance_InvalidOutputCannotCrossAsSuccess: output violating the declared schema fails the run — it never crosses the
// boundary as success.
func TestConformance_InvalidOutputCannotCrossAsSuccess(t *testing.T) {
	h := NewHandler(func(ctx context.Context, rc *Context) (any, error) {
		// appointments must be an array; this returns an object.
		return map[string]any{"appointments": map[string]any{"nope": true}}, nil
	}, WithContract(&Contract{
		Version:      "1.0.0",
		Risk:         "allow",
		OutputSchema: json.RawMessage(`{"type":"object","required":["appointments"],"properties":{"appointments":{"type":"array"}}}`),
	}))

	w := runRequest(t, h, `{"run_id":"r","input":{}}`)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("code = %d body = %s (invalid output must fail the run)", w.Code, w.Body.String())
	}
	var resp struct {
		Class string `json:"error_class"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Class != string(ClassInvalidOutput) {
		t.Fatalf("error_class = %q, want invalid_output", resp.Class)
	}
}

func TestConformance_ValidInputAndOutputSucceed(t *testing.T) {
	h := NewHandler(func(ctx context.Context, rc *Context) (any, error) {
		return map[string]any{"appointments": []any{}}, nil
	}, WithContract(&Contract{
		Version:      "1.0.0",
		Risk:         "allow",
		InputSchema:  json.RawMessage(`{"type":"object","required":["date"],"properties":{"date":{"type":"string"}}}`),
		OutputSchema: json.RawMessage(`{"type":"object","required":["appointments"],"properties":{"appointments":{"type":"array"}}}`),
	}))
	w := runRequest(t, h, `{"run_id":"r","input":{"date":"2026-09-02"}}`)
	if w.Code != http.StatusOK {
		t.Fatalf("code = %d body = %s", w.Code, w.Body.String())
	}
}

// TestConformance_DeadlineTerminatesImplementationWithinBound: a run deadline that passes terminates the implementation
// and the run fails with the timeout class — within the bound.
func TestConformance_DeadlineTerminatesImplementationWithinBound(t *testing.T) {
	h := NewHandler(func(ctx context.Context, rc *Context) (any, error) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(10 * time.Second): // would run forever without the deadline
			return map[string]any{}, nil
		}
	})

	start := time.Now()
	deadline := time.Now().UTC().Add(300 * time.Millisecond).Format(time.RFC3339)
	w := runRequest(t, h, `{"run_id":"r","input":{},"deadline":"`+deadline+`"}`)
	elapsed := time.Since(start)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("code = %d body = %s", w.Code, w.Body.String())
	}
	if elapsed > 3*time.Second {
		t.Fatalf("implementation was not terminated within the bound (%s)", elapsed)
	}
	var resp struct {
		Class string `json:"error_class"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Class != string(ClassTimeout) {
		t.Fatalf("error_class = %q, want timeout", resp.Class)
	}
}

// mutationCapability is the book-style conformance subject: a mutation that
// records one external effect per stable idempotency key, rejects changed
// content reusing a key, and reports duplicates.
type mutationCapability struct {
	mu       sync.Mutex
	bookings map[string]string // key -> appointment id
	content  map[string]string // key -> bound content
	effects  int
}

func newMutationCapability() *mutationCapability {
	return &mutationCapability{bookings: map[string]string{}, content: map[string]string{}}
}

func (m *mutationCapability) book(ctx context.Context, rc *Context) (any, error) {
	var in struct {
		RequestID string `json:"request_id"`
		SlotStart string `json:"slot_start"`
		PatientID string `json:"patient_id"`
	}
	if err := rc.Bind(&in); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if id, ok := m.bookings[in.RequestID]; ok {
		// Changed content cannot reuse an existing idempotency key.
		if m.content[in.RequestID] != in.PatientID {
			return nil, NewError(ClassInvalidInput, "idempotency key %q was already used with different content", in.RequestID)
		}
		return map[string]any{"appointment_id": id, "duplicate": true}, nil
	}
	id := "apt-" + in.RequestID
	m.bookings[in.RequestID] = id
	m.content[in.RequestID] = in.PatientID
	m.effects++
	return map[string]any{"appointment_id": id, "duplicate": false}, nil
}

// TestConformance_MutationIdempotency: repeated
// identical idempotency keys produce one external mutation; changed content
// cannot reuse an existing key.
func TestConformance_MutationIdempotency(t *testing.T) {
	c := newMutationCapability()
	h := NewHandler(c.book, WithContract(&Contract{
		Version:        "1.0.0",
		Risk:           "ask",
		IdempotencyKey: "request_id",
		InputSchema: json.RawMessage(`{"type":"object","required":["request_id","slot_start"],"additionalProperties":false,` +
			`"properties":{"request_id":{"type":"string"},"slot_start":{"type":"string"},"patient_id":{"type":"string"}}}`),
	}))

	body := `{"run_id":"r","input":{"request_id":"booking-1","slot_start":"2026-09-02T10:00","patient_id":"p-1"}}`
	w1 := runRequest(t, h, body)
	if w1.Code != http.StatusOK {
		t.Fatalf("first booking: code=%d body=%s", w1.Code, w1.Body.String())
	}
	// The SAME key delivered again (at-least-once redelivery): one external
	// effect, duplicate marked.
	w2 := runRequest(t, h, body)
	if w2.Code != http.StatusOK || !bytes.Contains(w2.Body.Bytes(), []byte(`"duplicate":true`)) {
		t.Fatalf("duplicate delivery must be a duplicate: code=%d body=%s", w2.Code, w2.Body.String())
	}
	if c.effects != 1 {
		t.Fatalf("external effects = %d, want exactly 1", c.effects)
	}

	// Changed content reusing the key is rejected.
	w3 := runRequest(t, h, `{"run_id":"r","input":{"request_id":"booking-1","slot_start":"2026-09-02T10:00","patient_id":"p-2"}}`)
	if w3.Code != http.StatusBadRequest {
		t.Fatalf("changed content with the same key must be rejected: code=%d body=%s", w3.Code, w3.Body.String())
	}
	if c.effects != 1 {
		t.Fatalf("rejected key reuse must not create an effect: %d", c.effects)
	}
}

// TestConformance_MutationRequiresIdempotencyKey: the declared input schema
// makes the key required, so a keyless mutation is rejected before the
// implementation runs.
func TestConformance_MutationRequiresIdempotencyKey(t *testing.T) {
	c := newMutationCapability()
	var invoked atomic.Bool
	h := NewHandler(func(ctx context.Context, rc *Context) (any, error) {
		invoked.Store(true)
		return c.book(ctx, rc)
	}, WithContract(&Contract{
		Version:        "1.0.0",
		Risk:           "ask",
		IdempotencyKey: "request_id",
		InputSchema:    json.RawMessage(`{"type":"object","required":["request_id","slot_start"],"properties":{"request_id":{"type":"string"},"slot_start":{"type":"string"}}}`),
	}))
	w := runRequest(t, h, `{"run_id":"r","input":{"slot_start":"2026-09-02T10:00"}}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("missing idempotency key must be rejected: code=%d body=%s", w.Code, w.Body.String())
	}
	if invoked.Load() {
		t.Fatal("implementation must not run for a keyless mutation")
	}
}
