package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/ykdynamics/forgeops-sdk/capability"
	"github.com/ykdynamics/forgeops-sdk/internal/jsonschema"
	"github.com/ykdynamics/forgeops-sdk/runtimecontract"
)

// cmdConformance checks YOUR capability against the contract its own
// capability.yaml declares, on this machine: it builds the project, starts it,
// and drives it through runtime.v1 as an edge would. Every expectation is
// derived from capability.yaml, not from how the capability was written, so a
// capability that does not enforce what it declares fails here rather than on
// a customer's edge.
//
// What it checks:
//   - the manifest is a valid capability.v1 document speaking runtime.v1;
//   - the capability builds and becomes healthy;
//   - a valid input (--input, itself checked against your inputSchema) runs,
//     and the answer matches your outputSchema;
//   - input your inputSchema forbids (a missing required field, an unknown
//     field when additionalProperties is false) is refused as invalid_input,
//     with a structured error;
//   - with --refuse-input, an input your capability must decline (e.g. an
//     undeclared target) is refused or denied — and not reported as a fault.
//
// What it does not: decide anything. Passing means the capability keeps its
// declared contract here; what may run on a customer's edge is decided there,
// by the customer's policy and approver.
func cmdConformance(args []string) error {
	fs := flag.NewFlagSet("conformance", flag.ExitOnError)
	input := fs.String("input", "", "a valid sample input (JSON); without it the valid-run check is skipped")
	refuse := fs.String("refuse-input", "", "an input the capability must decline (JSON), e.g. an undeclared target")
	addr := fs.String("addr", "", "local address to start the capability on (default: a free port)")
	dir, flagArgs := splitPositional(args)
	_ = fs.Parse(flagArgs)
	if dir == "" {
		return fmt.Errorf("conformance needs a project directory containing capability.yaml")
	}

	r := &report{}
	pkg := r.manifest(dir)
	if pkg == nil {
		return r.finish()
	}
	for _, sample := range []struct{ flag, value string }{{"--input", *input}, {"--refuse-input", *refuse}} {
		if sample.value != "" && !json.Valid([]byte(sample.value)) {
			return fmt.Errorf("%s is not valid JSON: %s", sample.flag, sample.value)
		}
	}

	bin, cleanup, ok := r.build(dir)
	defer cleanup()
	if !ok {
		return r.finish()
	}
	if *addr == "" {
		*addr = freeLocalAddr()
	}
	base := "http://" + *addr
	stop, logs, ok := r.start(bin, *addr, base)
	defer stop()
	if !ok {
		return r.finish()
	}
	client := runtimecontract.NewClient(15 * time.Second)

	// A valid input runs, and the answer keeps the declared output contract.
	if *input == "" {
		r.skip("valid input runs", "give --input with a valid sample to check a real run and its output")
	} else {
		var sample any
		_ = json.Unmarshal([]byte(*input), &sample)
		if err := jsonschema.Validate(pkg.Contract.InputSchema, sample); err != nil {
			r.fail("valid input runs", "your --input does not match your own inputSchema: %v", err)
		} else {
			res, err := client.Run(context.Background(), base, runRequest(*input))
			switch {
			case err != nil:
				r.fail("valid input runs", "%v", err)
			case res.StatusCode != 200:
				r.fail("valid input runs", "HTTP %d %s: %s", res.StatusCode, res.Error.ErrorClass, res.Error.Error)
			default:
				var out any
				if err := json.Unmarshal(res.Output, &out); err != nil {
					r.fail("output matches outputSchema", "the answer is not JSON: %v", err)
				} else if err := jsonschema.Validate(pkg.Contract.OutputSchema, out); err != nil {
					r.fail("output matches outputSchema", "%v (answer: %s)", err, oneLine(res.Output))
				} else {
					r.pass("valid input runs", "HTTP 200")
					r.pass("output matches outputSchema", oneLine(res.Output))
				}
			}
		}
	}

	// Input the declared schema forbids is refused before anything acts on it.
	invalid := forbiddenInputs(pkg.Contract.InputSchema, *input)
	if len(invalid) == 0 {
		r.skip("forbidden input is refused", "your inputSchema declares no required field and allows unknown fields: nothing to forbid")
	}
	for _, c := range invalid {
		res, err := client.Run(context.Background(), base, runRequest(c.input))
		name := "forbidden input is refused (" + c.why + ")"
		switch {
		case err != nil:
			r.fail(name, "%v", err)
		case res.StatusCode == 200:
			r.fail(name, "it ran (HTTP 200) on %s; declare the contract with sdk.WithContract, or check the input yourself", c.input)
		case res.Error.ErrorClass != runtimecontract.ClassInvalidInput || res.StatusCode != 400:
			r.fail(name, "HTTP %d class %q, want 400 %q: %s", res.StatusCode, res.Error.ErrorClass, runtimecontract.ClassInvalidInput, res.Error.Error)
		default:
			r.pass(name, "HTTP 400 invalid_input")
		}
	}

	// Declining is not a fault: an authority refusal must not look like a crash.
	if *refuse == "" {
		r.skip("refusal is not a fault", "give --refuse-input with an input your capability must decline (e.g. an undeclared target)")
	} else {
		res, err := client.Run(context.Background(), base, runRequest(*refuse))
		switch {
		case err != nil:
			r.fail("refusal is not a fault", "%v", err)
		case res.StatusCode == 200:
			r.fail("refusal is not a fault", "it ran (HTTP 200) on %s", *refuse)
		case res.Error.ErrorClass != runtimecontract.ClassRefused && res.Error.ErrorClass != runtimecontract.ClassDenied:
			r.fail("refusal is not a fault", "HTTP %d class %q, want %q or %q (sdk.RefuseUndeclaredTarget)", res.StatusCode, res.Error.ErrorClass, runtimecontract.ClassRefused, runtimecontract.ClassDenied)
		case res.StatusCode >= 500:
			r.fail("refusal is not a fault", "class %q but HTTP %d: a refusal reported as 5xx reads as a crash", res.Error.ErrorClass, res.StatusCode)
		default:
			r.pass("refusal is not a fault", fmt.Sprintf("HTTP %d %s", res.StatusCode, res.Error.ErrorClass))
		}
	}

	if r.failed > 0 && logs.Len() > 0 {
		fmt.Println("\ncapability output (last lines):")
		fmt.Println(lastLines(logs.String(), 12))
	}
	return r.finish()
}

type invalidInput struct{ input, why string }

// forbiddenInputs derives inputs the declared inputSchema forbids: the sample
// (or {}) without its first required field, and the sample with an unknown
// field when additionalProperties is false.
func forbiddenInputs(schema json.RawMessage, sample string) []invalidInput {
	var s map[string]any
	if json.Unmarshal(schema, &s) != nil {
		return nil
	}
	base := map[string]any{}
	if sample != "" {
		var m map[string]any
		if json.Unmarshal([]byte(sample), &m) == nil && m != nil {
			base = m
		}
	}
	var out []invalidInput
	if req, ok := s["required"].([]any); ok && len(req) > 0 {
		if field, ok := req[0].(string); ok {
			in := clone(base)
			delete(in, field)
			b, _ := json.Marshal(in)
			out = append(out, invalidInput{string(b), "missing required " + field})
		}
	}
	if ap, ok := s["additionalProperties"].(bool); ok && !ap {
		in := clone(base)
		in["forgeops_conformance_unknown_field"] = true
		b, _ := json.Marshal(in)
		out = append(out, invalidInput{string(b), "unknown field"})
	}
	return out
}

func clone(m map[string]any) map[string]any {
	out := make(map[string]any, len(m)+1)
	for k, v := range m {
		out[k] = v
	}
	return out
}

func runRequest(input string) runtimecontract.RunRequest {
	return runtimecontract.RunRequest{RunID: "forgeops-cap-conformance", Input: json.RawMessage(input)}
}

// report collects the checks and prints them as they happen.
type report struct{ passed, failed, skipped int }

func (r *report) pass(name, detail string) {
	r.passed++
	fmt.Printf("[PASS] %s — %s\n", name, detail)
}

func (r *report) fail(name, format string, args ...any) {
	r.failed++
	fmt.Printf("[FAIL] %s — %s\n", name, fmt.Sprintf(format, args...))
}

func (r *report) skip(name, why string) {
	r.skipped++
	fmt.Printf("[SKIP] %s — %s\n", name, why)
}

func (r *report) finish() error {
	fmt.Printf("\nconformance: %d passed, %d failed, %d skipped — your capability against its own capability.yaml, on this machine.\n", r.passed, r.failed, r.skipped)
	fmt.Println("It grants nothing: what runs on a customer's edge is decided there, by the customer's policy and approver.")
	if r.failed > 0 {
		return fmt.Errorf("%d check(s) failed", r.failed)
	}
	return nil
}

func (r *report) manifest(dir string) *capability.Package {
	data, err := os.ReadFile(filepath.Join(dir, "capability.yaml"))
	if err != nil {
		r.fail("manifest", "%v", err)
		return nil
	}
	pkg, errs, err := capability.ValidateDocument(data)
	switch {
	case err != nil:
		r.fail("manifest", "capability.yaml does not parse: %v", err)
		return nil
	case len(errs) != 0:
		r.fail("manifest", "capability.yaml does not conform to capability.v1: %v", errs)
		return nil
	case pkg.Runtime.RuntimeContract != runtimecontract.Version:
		r.fail("manifest", "runtime.runtimeContract is %q; this check speaks %s", pkg.Runtime.RuntimeContract, runtimecontract.Version)
		return nil
	}
	r.pass("manifest", fmt.Sprintf("%s@%s, capability.v1, %s", pkg.Identity.Key, pkg.Identity.Version, runtimecontract.Version))
	return pkg
}

// build compiles the project for THIS machine, as `run` does: conformance runs
// the capability here, so host bytes are the right ones, and nothing is pinned.
func (r *report) build(dir string) (string, func(), bool) {
	work, err := os.MkdirTemp("", "forgeops-cap-conformance-")
	if err != nil {
		r.fail("build", "%v", err)
		return "", func() {}, false
	}
	cleanup := func() { _ = os.RemoveAll(work) }
	bin := filepath.Join(work, "capability")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		r.fail("build", "%v\n%s", err, out)
		return "", cleanup, false
	}
	r.pass("build", "go build (this machine)")
	return bin, cleanup, true
}

func (r *report) start(bin, addr, base string) (func(), *bytes.Buffer, bool) {
	logs := &bytes.Buffer{}
	cmd := exec.Command(bin)
	cmd.Env = append(os.Environ(), "CAPABILITY_ADDR="+addr)
	cmd.Stdout, cmd.Stderr = logs, logs
	if err := cmd.Start(); err != nil {
		r.fail("health", "start: %v", err)
		return func() {}, logs, false
	}
	stop := func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }
	client := runtimecontract.NewClient(2 * time.Second)
	for i := 0; i < 50; i++ {
		if client.Health(context.Background(), base) {
			r.pass("health", "GET /health 200 at "+addr)
			return stop, logs, true
		}
		time.Sleep(100 * time.Millisecond)
	}
	r.fail("health", "no GET /health 200 at %s within 5s (does it listen on CAPABILITY_ADDR?)\n%s", addr, lastLines(logs.String(), 8))
	return stop, logs, false
}

func freeLocalAddr() string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "127.0.0.1:18098"
	}
	defer l.Close()
	return l.Addr().String()
}

func oneLine(b []byte) string {
	s := strings.Join(strings.Fields(string(b)), " ")
	if len(s) > 160 {
		s = s[:157] + "..."
	}
	return s
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}
