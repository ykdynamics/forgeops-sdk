package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// conformanceProject scaffolds a project against this SDK tree and, when main
// is given, replaces its implementation: the same capability.yaml, a different
// behaviour, so each test isolates what conformance must notice.
func conformanceProject(t *testing.T, main string) string {
	t.Helper()
	if testing.Short() {
		t.Skip("builds and runs a capability")
	}
	// The module root from this file's own path, not the working directory:
	// a test that builds two projects has already moved into the first one.
	_, self, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(self), "..", "..")
	dir := inTempDir(t)
	if err := cmdInit([]string{"acme.demo.status", "--sdk-replace", root}); err != nil {
		t.Fatalf("init: %v", err)
	}
	project := filepath.Join(dir, "acme-demo-status")
	if main != "" {
		if err := os.WriteFile(filepath.Join(project, "main.go"), []byte(main), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return project
}

// The scaffold keeps the contract it declares.
func TestConformancePassesTheScaffold(t *testing.T) {
	project := conformanceProject(t, "")
	if err := cmdConformance([]string{project, "--input", `{"service":"acme"}`}); err != nil {
		t.Fatalf("the scaffold fails its own conformance: %v", err)
	}
}

// A capability that does not enforce what its capability.yaml declares — the
// scaffold before it declared its contract to the SDK — must fail: it ran on
// an unknown field and reported missing input as an internal fault.
func TestConformanceCatchesAnUnenforcedContract(t *testing.T) {
	project := conformanceProject(t, capabilityMain(`
	var in struct{ Service string `+"`json:\"service\"`"+` }
	if err := rc.Bind(&in); err != nil {
		return nil, err
	}
	if in.Service == "" {
		return nil, fmt.Errorf("service is required")
	}
	return map[string]any{"healthy": true}, nil`, false))
	err := cmdConformance([]string{project, "--input", `{"service":"acme"}`})
	// Both forbidden-input checks fail (missing field as a 500, unknown field
	// accepted), and nothing else: it built, answered and kept its output.
	if err == nil || err.Error() != "2 check(s) failed" {
		t.Fatalf("want exactly the two forbidden-input checks to fail, got: %v", err)
	}
}

// Declining an undeclared target is a refusal, not a fault.
func TestConformanceRefusalIsNotAFault(t *testing.T) {
	refusing := capabilityMain(`
	var in struct{ Service string `+"`json:\"service\"`"+` }
	if err := rc.Bind(&in); err != nil {
		return nil, sdk.NewError(sdk.ClassInvalidInput, "input: %v", err)
	}
	if in.Service != "acme" {
		return nil, sdk.RefuseUndeclaredTarget("service", in.Service)
	}
	return map[string]any{"healthy": true}, nil`, true)
	project := conformanceProject(t, refusing)
	if err := cmdConformance([]string{project, "--input", `{"service":"acme"}`, "--refuse-input", `{"service":"other"}`}); err != nil {
		t.Fatalf("a proper refusal failed conformance: %v", err)
	}

	// The same decision reported as a plain error reads as a crash (HTTP 500).
	faulting := strings.Replace(refusing, `sdk.RefuseUndeclaredTarget("service", in.Service)`, `fmt.Errorf("not my target: %s", in.Service)`, 1)
	project = conformanceProject(t, faulting)
	err := cmdConformance([]string{project, "--input", `{"service":"acme"}`, "--refuse-input", `{"service":"other"}`})
	if err == nil {
		t.Fatal("conformance passed a refusal reported as an internal fault")
	}
	// Exactly one check fails, the refusal: the project built and kept the rest
	// of its contract, so the failure is the one this test is about.
	if err.Error() != "1 check(s) failed" {
		t.Fatalf("want only the refusal check to fail, got: %v", err)
	}
}

// capabilityMain is a whole main.go around body; withContract declares the
// scaffold's schemas to the SDK.
func capabilityMain(body string, withContract bool) string {
	serve := "sdk.Serve(addr, handle)"
	if withContract {
		serve = "sdk.Serve(addr, handle, sdk.WithContract(&sdk.Contract{InputSchema: json.RawMessage(`" + scaffoldInputSchema + "`), OutputSchema: json.RawMessage(`" + scaffoldOutputSchema + "`)}))"
	}
	return `package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/ykdynamics/forgeops-sdk/sdk"
)

var _ = json.RawMessage(nil)
var _ = fmt.Errorf

func main() {
	addr := os.Getenv("CAPABILITY_ADDR")
	if err := ` + serve + `; err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func handle(ctx context.Context, rc *sdk.Context) (any, error) {` + body + `
}
`
}
