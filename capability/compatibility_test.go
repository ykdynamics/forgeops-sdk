package capability

import (
	"fmt"
	"strings"
	"testing"
)

// typedDoc renders a conforming canonical document whose
// executionBoundary.compatibleTargetTypes is the given YAML inline list.
func typedDoc(types string) string {
	return fmt.Sprintf(`schemaVersion: capability.v1
identity:
  key: acme.service.restart
  version: 2.0.0
  artifactDigest: sha256:52b350d25777409fe32df0dc1ca6809f74dade7355b8e79a39bcc87e38a9e3be
contract:
  description: restarts the acme service (compatibility conformance fixture)
  inputSchema:
    type: object
    required: [service]
    additionalProperties: false
    properties:
      service: {type: string, minLength: 1}
  outputSchema:
    type: object
    required: [restarted]
    additionalProperties: false
    properties:
      restarted: {type: boolean}
executionBoundary:
  risk: ask
  requiredSecrets: [SERVICE_TOKEN]
  compatibleTargetTypes: %s
runtime:
  interface: mcp
  runtimeContract: runtime.v1
`, types)
}

func TestNormalizeTargetTypeMirrorsTypedTargetModel(t *testing.T) {
	// The grammar/vector set mirrors the tests of ForgeOps' own target model,
	// so the two copies cannot drift silently.
	valid := map[string]string{
		"kubernetes.cluster":    "kubernetes.cluster/v1",
		"kubernetes.cluster/v1": "kubernetes.cluster/v1",
		"sap.system/v2":         "sap.system/v2",
		"postgres.database/v3":  "postgres.database/v3",
		"industrial.gateway":    "industrial.gateway/v1",
		"payment.account/v4":    "payment.account/v4",
		"a":                     "a/v1",
		"a.b.c.d/v9":            "a.b.c.d/v9",
	}
	for raw, want := range valid {
		got, err := NormalizeTargetType(raw)
		if err != nil {
			t.Fatalf("NormalizeTargetType(%q) = %v", raw, err)
		}
		if got != want {
			t.Fatalf("NormalizeTargetType(%q) = %q, want %q", raw, got, want)
		}
	}
	invalid := []string{
		"", "Kubernetes.cluster", "kubernetes..cluster", ".kubernetes", "kubernetes.",
		"1kubernetes", "kubernetes_cluster", "kubernetes.cluster/v0", "/v1",
		"kubernetes.cluster/v01", "kubernetes.cluster/v1x", "postgres database",
	}
	for _, raw := range invalid {
		if _, err := NormalizeTargetType(raw); err == nil {
			t.Fatalf("NormalizeTargetType(%q) accepted a malformed type", raw)
		}
	}
}

func TestCompatibleTargetTypesDeclarationConformsAndProjects(t *testing.T) {
	doc := typedDoc("[kubernetes.cluster, sap.system/v2, payment.account/v4]")
	p, errs, err := ValidateDocument([]byte(doc))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(errs) != 0 {
		t.Fatalf("typed declaration should conform, got %v", errs)
	}
	if len(p.ExecutionBoundary.CompatibleTargetTypes) != 3 {
		t.Fatalf("declared count = %d, want 3", len(p.ExecutionBoundary.CompatibleTargetTypes))
	}
	contracts, err := p.CompatibleTargetTypeContracts()
	if err != nil {
		t.Fatalf("CompatibleTargetTypeContracts: %v", err)
	}
	want := []string{"kubernetes.cluster/v1", "payment.account/v4", "sap.system/v2"}
	if len(contracts) != len(want) {
		t.Fatalf("contracts = %v, want %v", contracts, want)
	}
	for i := range want {
		if contracts[i] != want[i] {
			t.Fatalf("contracts[%d] = %q, want %q", i, contracts[i], want[i])
		}
	}
}

func TestLegacyDocsWithoutDeclarationStillConform(t *testing.T) {
	// Backward compatibility: capability.v1 documents authored before typed
	// compatibility existed (no compatibleTargetTypes, only the free-form legacy target class) must
	// keep validating unchanged.
	if errs := mustValidate(t, positive); len(errs) != 0 {
		t.Fatalf("legacy fixture should still conform, got %v", errs)
	}
	if errs := mustValidate(t, typedDoc("[]")); len(errs) != 0 {
		t.Fatalf("empty declaration should conform, got %v", errs)
	}
}

func TestCompatibleTargetTypesValidationRefusesMalformed(t *testing.T) {
	tooLong := strings.Repeat("x", MaxTargetTypeLength) + "/v1"
	cases := []struct {
		name  string
		types string
		field string
		want  string
	}{
		{"invalid name", "[Kubernetes.cluster]", "executionBoundary.compatibleTargetTypes[0]", "not a dotted lowercase name"},
		{"invalid version", "[sap.system/v0]", "executionBoundary.compatibleTargetTypes[0]", "not vN"},
		{"empty entry", "[\"\"]", "executionBoundary.compatibleTargetTypes[0]", "is required"},
		{"oversized entry", fmt.Sprintf("[%s]", tooLong), "executionBoundary.compatibleTargetTypes[0]", "limit is"},
		{"exact duplicate", "[sap.system/v2, sap.system/v2]", "executionBoundary.compatibleTargetTypes[1]", "duplicates target-type contract"},
		{"normalization collision", "[kubernetes.cluster, kubernetes.cluster/v1]", "executionBoundary.compatibleTargetTypes[1]", "duplicates target-type contract"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			errs := mustValidate(t, typedDoc(tc.types))
			found := false
			for _, e := range errs {
				if e.Field == tc.field && strings.Contains(e.Message, tc.want) {
					found = true
				}
			}
			if !found {
				t.Fatalf("expected %q error on %s, got %v", tc.want, tc.field, errs)
			}
		})
	}
}

func TestCompatibleTargetTypesCountBound(t *testing.T) {
	var b strings.Builder
	b.WriteString("[")
	for i := 0; i < MaxCompatibleTargetTypes+1; i++ {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "tgt.n%d", i)
	}
	b.WriteString("]")
	errs := mustValidate(t, typedDoc(b.String()))
	found := false
	for _, e := range errs {
		if e.Field == "executionBoundary.compatibleTargetTypes" && strings.Contains(e.Message, "limit is 16") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a count-limit error on executionBoundary.compatibleTargetTypes, got %v", errs)
	}
}
