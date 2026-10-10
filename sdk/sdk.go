// Package sdk is the ForgeOps capability Runtime SDK (Go). Write a capability as
// a function over a Context; the SDK speaks the ForgeOps http-runtime contract
// for you: it parses the worker's request ({run_id, input, runtime_token,
// runtime_url}), gives you the input + typed callbacks (progress, logs, secrets),
// and turns your return value into the run's output.
//
// This is the first slice of the "platform layer" — the thing that turns
// "send us a manifest" into "write code, get lifecycle + audit for free."
package sdk

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ykdynamics/forgeops-sdk/runtimecontract"
)

// Context is one capability invocation: the input the caller (or an LLM) supplied,
// plus callbacks into the ForgeOps Runtime API for the current run.
type Context struct {
	RunID string
	Input json.RawMessage
	// Attempt (WP-R5.2b) is the canonical attempt identity the executor
	// delivered (action_id, tenant, attempt_number, idempotency_key) — the
	// authoritative lineage a capability uses for its intended-effect receipt.
	// Nil for executors that predate the run context.
	Attempt *runtimecontract.RunContext

	// deadline is the run's action deadline when the worker delivered one
	// (WP-05E): the handler terminates the implementation when it fires.
	deadline time.Time

	runtimeURL string
	token      string
	http       *http.Client
}

// Bind unmarshals the invocation input into v.
func (c *Context) Bind(v any) error {
	if len(c.Input) == 0 {
		return nil
	}
	return json.Unmarshal(c.Input, v)
}

// Progress reports completion percent + a message (surfaced on the run's timeline).
func (c *Context) Progress(ctx context.Context, percent int, message string) error {
	return c.post(ctx, "/progress", map[string]any{"percent": percent, "message": message})
}

// Log appends log lines to the run (stdout stream).
func (c *Context) Log(ctx context.Context, lines ...string) error {
	if len(lines) == 0 {
		return nil
	}
	return c.post(ctx, "/logs", map[string]any{"lines": lines, "stream": "stdout"})
}

// ChildRun spawns a child run from this run, addressed by capability_key (ADR-017
// — resolved like a job: offering then platform, input + required_secrets
// enforced). The child is linked to this run (triggered_by=child). Lets a parent
// capability fan out to other capabilities without knowing their template ids.
func (c *Context) ChildRun(ctx context.Context, capabilityKey string, input any) error {
	return c.post(ctx, "/child-runs", map[string]any{"capability_key": capabilityKey, "input": input})
}

// Secrets returns the decrypted values of the capability's declared
// required_secrets (and only those). Empty when none are declared/configured.
func (c *Context) Secrets(ctx context.Context) (map[string]string, error) {
	if c.runtimeURL == "" {
		return map[string]string{}, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.runtimeURL+"/runtime/runs/"+c.RunID+"/secrets", nil)
	if err != nil {
		return nil, err
	}
	c.auth(req)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("secrets -> %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var out map[string]string
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// post is a fire-and-report helper for the runtime callbacks. When no runtime_url
// was provided (e.g. local testing), callbacks are silent no-ops.
func (c *Context) post(ctx context.Context, path string, body any) error {
	if c.runtimeURL == "" {
		return nil
	}
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	url := c.runtimeURL + "/runtime/runs/" + c.RunID + path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	c.auth(req)
	resp, err := c.http.Do(req)
	if err != nil {
		// Callbacks are non-fatal, but failing silently hides real misconfig
		// (wrong runtime_url, bad token). Log so it's visible in the capability's
		// logs without breaking the run.
		log.Printf("sdk: runtime callback POST %s failed: %v", url, err)
		return err
	}
	defer resp.Body.Close()
	body2, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		log.Printf("sdk: runtime callback POST %s -> %d: %s", url, resp.StatusCode, strings.TrimSpace(string(body2)))
		return fmt.Errorf("runtime%s -> %d", path, resp.StatusCode)
	}
	return nil
}

// normalizeRuntimeURL turns the worker-supplied runtime_url into a bare base the
// callbacks append "/runtime/runs/{id}/..." to. RUNTIME_URL may arrive as a bare
// host (http://forgeops-runtime:8081) or already include /runtime
// (https://host/runtime, when callbacks route through the public proxy) — strip
// the suffix so we never double it. Mirrors cmd/lab-api's normalization.
func normalizeRuntimeURL(raw string) string {
	base := strings.TrimRight(raw, "/")
	base = strings.TrimSuffix(base, "/runtime")
	return base
}

func (c *Context) auth(req *http.Request) {
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
}

// Handler is a capability implementation: given the invocation Context, return
// the output (any JSON-serialisable value) or an error. A returned error fails
// the run; the returned value becomes the run's output.
type Handler func(ctx context.Context, rc *Context) (any, error)

// payload mirrors what the ForgeOps http executor POSTs to a capability target.
type payload struct {
	RunID        string          `json:"run_id"`
	Input        json.RawMessage `json:"input"`
	RuntimeToken string          `json:"runtime_token"`
	RuntimeURL   string          `json:"runtime_url"`
	// Deadline is the run's action deadline (RFC3339), when the worker sent
	// one. The handler terminates the implementation when it fires (WP-05E).
	Deadline string `json:"deadline,omitempty"`
	// Context is the canonical attempt identity (WP-R5.2b): the authoritative
	// action id + lineage the implementation acts under. Executors that predate
	// the context leave it nil.
	Context *runtimecontract.RunContext `json:"context,omitempty"`
}

// HandlerOption configures a capability handler.
type HandlerOption func(*handlerConfig)

type handlerConfig struct {
	contract *Contract
}

// WithContract declares the capability's exact input/output contract (WP-05A):
// the SDK rejects invalid input before the implementation runs and fails the
// run when the output violates the declared schema.
func WithContract(c *Contract) HandlerOption {
	return func(hc *handlerConfig) { hc.contract = c }
}

// NewHandler returns an http.Handler implementing the http-runtime contract on
// POST /run, plus GET /health. Exposed (vs only Serve) so it can be tested.
func NewHandler(h Handler, opts ...HandlerOption) http.Handler {
	cfg := &handlerConfig{}
	for _, o := range opts {
		o(cfg)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("POST /run", func(w http.ResponseWriter, r *http.Request) {
		var p payload
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			writeStructured(w, http.StatusBadRequest, ClassInvalidInput, "invalid request body")
			return
		}
		rc := &Context{
			RunID: p.RunID, Input: p.Input,
			Attempt:    p.Context,
			runtimeURL: normalizeRuntimeURL(p.RuntimeURL), token: p.RuntimeToken,
			http: &http.Client{Timeout: 15 * time.Second},
		}
		if p.Deadline != "" {
			if d, err := time.Parse(time.RFC3339, p.Deadline); err == nil {
				rc.deadline = d
			}
		}
		// One line per invocation — reveals whether the worker delivered a
		// runtime_url (callbacks no-op without it) and a token.
		log.Printf("sdk: run=%s input=%dB runtime_url=%q token=%v deadline=%v", p.RunID, len(p.Input), rc.runtimeURL, p.RuntimeToken != "", rc.deadline)

		// WP-05A / SC-10: reject invalid input BEFORE the implementation runs.
		if cfg.contract != nil && len(cfg.contract.InputSchema) > 0 {
			var in any
			if len(rc.Input) > 0 {
				if err := json.Unmarshal(rc.Input, &in); err != nil {
					writeStructured(w, http.StatusBadRequest, ClassInvalidInput, "input is not valid JSON: "+err.Error())
					return
				}
			}
			if err := validateSchema(cfg.contract.InputSchema, in); err != nil {
				writeStructured(w, http.StatusBadRequest, ClassInvalidInput, err.Error())
				return
			}
		}

		// WP-05E: bound the implementation to the run deadline.
		implCtx := r.Context()
		if !rc.deadline.IsZero() {
			var cancel context.CancelFunc
			implCtx, cancel = context.WithDeadline(implCtx, rc.deadline)
			defer cancel()
		}
		out, err := h(implCtx, rc)
		if err != nil {
			// Non-2xx → the executor records the run as failed.
			class := ClassInternal
			status := http.StatusInternalServerError
			if se, ok := err.(*StructuredError); ok {
				class = se.Class
				status = statusForClass(class)
			}
			if err == context.DeadlineExceeded || implCtx.Err() == context.DeadlineExceeded {
				class = ClassTimeout
			}
			writeStructured(w, status, class, err.Error())
			return
		}

		// WP-05A / SC-10: invalid output can never cross the boundary as success.
		if cfg.contract != nil && len(cfg.contract.OutputSchema) > 0 {
			outJSON, err := json.Marshal(out)
			if err == nil {
				var outAny any
				if json.Unmarshal(outJSON, &outAny) == nil {
					if err := validateSchema(cfg.contract.OutputSchema, outAny); err != nil {
						writeStructured(w, http.StatusInternalServerError, ClassInvalidOutput,
							"output violates the declared contract: "+err.Error())
						return
					}
				}
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(out)
	})
	return mux
}

// Serve runs a capability as an http service (the http-runtime transport).
func Serve(addr string, h Handler, opts ...HandlerOption) error {
	log.Printf("capability listening on %s (POST /run)", addr)
	return http.ListenAndServe(addr, NewHandler(h, opts...))
}

// HealthcheckMain probes the local /health endpoint and exits 0 (healthy) or 1.
// Use it as a container healthcheck on distroless images that have no shell:
//
//	if len(os.Args) >= 2 && os.Args[1] == "healthcheck" { sdk.HealthcheckMain(addr) }
func HealthcheckMain(addr string) {
	host := addr
	if strings.HasPrefix(host, ":") {
		host = "127.0.0.1" + host
	}
	c := &http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get("http://" + host + "/health")
	if err != nil || resp.StatusCode < 200 || resp.StatusCode >= 300 {
		os.Exit(1)
	}
	resp.Body.Close()
	os.Exit(0)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// writeStructured writes a safe, classed run error (WP-05A): the machine-
// readable error_class plus a human-safe message.
func writeStructured(w http.ResponseWriter, status int, class ErrorClass, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": msg, "error_class": string(class)})
}

// statusForClass maps an error class to the HTTP status the runtime contract
// reports. It is a table rather than a chain of ifs so that adding a class
// without deciding its status is visibly incomplete rather than silently a 500.
//
// The refusal classes are DELIBERATELY not 5xx (capabilities#68): a capability
// declining on authority grounds is not a fault, and reporting it as one makes a
// boundary being enforced indistinguishable from a crash — in logs, in metrics,
// and to a retry policy that treats 5xx as transient.
func statusForClass(class ErrorClass) int {
	switch class {
	case ClassInvalidInput:
		return http.StatusBadRequest
	case ClassRefused, ClassDenied:
		return http.StatusConflict
	default:
		return http.StatusInternalServerError
	}
}
