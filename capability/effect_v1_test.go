package capability

import (
	"fmt"
	"strings"
	"testing"
)

// docWithEffect renders a conforming canonical document whose top-level
// `effect` block is the given YAML fragment.
func docWithEffect(effect string) string {
	return fmt.Sprintf(`schemaVersion: capability.v1
identity:
  key: acme.service.restart
  version: 2.0.0
  artifactDigest: sha256:52b350d25777409fe32df0dc1ca6809f74dade7355b8e79a39bcc87e38a9e3be
contract:
  inputSchema: {type: object}
  outputSchema: {type: object}
executionBoundary:
  risk: ask
  requiredSecrets: [SERVICE_TOKEN]
effect:
  %s
runtime:
  interface: mcp
  runtimeContract: runtime.v1
`, strings.ReplaceAll(effect, "\n", "\n  "))
}

const validEffect = `contract: effect.v1
sideEffect: mutation
reversibility: irreversible
idempotency: key_required
verification: required`

func TestEffectV1BlockConformsAndRoundTrips(t *testing.T) {
	doc := docWithEffect(validEffect)
	p, errs, err := ValidateDocument([]byte(doc))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(errs) != 0 {
		t.Fatalf("effect v1 block should conform, got %v", errs)
	}
	e := p.Effect
	if e.Contract != "effect.v1" || e.SideEffect != "mutation" ||
		e.Reversibility != "irreversible" || e.Idempotency != "key_required" ||
		e.Verification != "required" {
		t.Fatalf("effect fields wrong: %+v", e)
	}
}

func TestEffectAbsentIsLegacyLane(t *testing.T) {
	// Documents without an effect block (the whole pre-R6.4 population) stay
	// valid on the untyped lane.
	if errs := mustValidate(t, positive); len(errs) != 0 {
		t.Fatalf("legacy fixture should still conform, got %v", errs)
	}
}

func TestEffectV1ValidationRefusesInvalidValues(t *testing.T) {
	cases := []struct {
		name        string
		replaceFrom string
		replaceTo   string
		field       string
		want        string
	}{
		{"unknown sideEffect", "sideEffect: mutation", "sideEffect: restart", "effect.sideEffect", "not one of"},
		{"unknown reversibility", "reversibility: irreversible", "reversibility: maybe", "effect.reversibility", "not one of"},
		{"unknown idempotency", "idempotency: key_required", "idempotency: always", "effect.idempotency", "not one of"},
		{"unknown verification", "verification: required", "verification: sometimes", "effect.verification", "not one of"},
		{"missing sideEffect", "sideEffect: mutation", "", "effect.sideEffect", "required"},
		{"missing verification", "verification: required", "", "effect.verification", "required"},
		{"missing contract", "contract: effect.v1", "", "effect.contract", "required"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			effect := strings.Replace(validEffect, tc.replaceFrom, tc.replaceTo, 1)
			errs := mustValidate(t, docWithEffect(effect))
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
	// Unknown effect contract version is refused (versioning is strict).
	badContract := strings.Replace(validEffect, "effect.v1", "effect.v2", 1)
	errs := mustValidate(t, docWithEffect(badContract))
	found := false
	for _, e := range errs {
		if e.Field == "effect.contract" && strings.Contains(e.Message, "unsupported effect contract") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected an unsupported effect contract error, got %v", errs)
	}
}

func TestEffectIsNotPolicy(t *testing.T) {
	// Effect semantics never conflict with the allow/ask/deny authority class:
	// a mutation effect under risk ask (human-gated) conforms; the two are
	// different axes and never folded together.
	doc := strings.Replace(docWithEffect(validEffect), "risk: ask", "risk: allow", 1)
	if errs := mustValidate(t, doc); len(errs) != 0 {
		t.Fatalf("effect + risk should be independent axes, got %v", errs)
	}
}

func TestCanonicalDigestCoversEffect(t *testing.T) {
	// The manifest digest (revision identity) covers the effect block: changing
	// Effect semantics requires a new capability revision/package identity.
	none := docWithEffect(validEffect)
	mutated := strings.Replace(none, "sideEffect: mutation", "sideEffect: external", 1)
	a, err := CanonicalJSON([]byte(none))
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	b, err := CanonicalJSON([]byte(mutated))
	if err != nil {
		t.Fatalf("canonicalize mutated: %v", err)
	}
	if string(a) == string(b) {
		t.Fatal("effect change did not change the canonical digest")
	}
	if !strings.Contains(string(a), `"effect":{`) {
		t.Fatalf("canonical form lost the effect block: %s", a)
	}
}
