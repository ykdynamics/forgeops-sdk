package capability

import (
	"strings"
	"testing"
)

// Conformance vectors for namespaced, versioned Effect
// extensions and the fail-closed rule for authority-relevant ones.

const effectWithExtensions = `contract: effect.v1
sideEffect: mutation
reversibility: irreversible
idempotency: key_required
verification: required
extensions:
  - name: acme.settlement/v1
    authority: authority_relevant
    attributes:
      window: t_plus_2
      clearing_house: acme_clearing
  - name: acme.telemetry/v2
    authority: informational`

func TestEffectExtensionsConformAndRoundTrip(t *testing.T) {
	p, errs, err := ValidateDocument([]byte(docWithEffect(effectWithExtensions)))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(errs) != 0 {
		t.Fatalf("namespaced effect extensions should conform, got %v", errs)
	}
	if got := len(p.Effect.Extensions); got != 2 {
		t.Fatalf("want 2 extensions, got %d", got)
	}
	contracts, err := p.EffectExtensionContracts()
	if err != nil {
		t.Fatalf("contracts: %v", err)
	}
	if strings.Join(contracts, ",") != "acme.settlement/v1,acme.telemetry/v2" {
		t.Fatalf("contract projection is not the sorted canonical set: %v", contracts)
	}
	authority, err := p.AuthorityRelevantEffectExtensions()
	if err != nil {
		t.Fatalf("authority-relevant: %v", err)
	}
	if strings.Join(authority, ",") != "acme.settlement/v1" {
		t.Fatalf("want only the authority-relevant contract, got %v", authority)
	}
	informational, err := p.InformationalEffectExtensions()
	if err != nil {
		t.Fatalf("informational: %v", err)
	}
	if strings.Join(informational, ",") != "acme.telemetry/v2" {
		t.Fatalf("want only the informational contract, got %v", informational)
	}
	attrs, declared, err := p.EffectExtensionAttributes("acme.settlement/v1")
	if err != nil || !declared {
		t.Fatalf("settlement attributes: declared=%v err=%v", declared, err)
	}
	if attrs["window"] != "t_plus_2" || attrs["clearing_house"] != "acme_clearing" {
		t.Fatalf("attribute payload lost: %v", attrs)
	}
	if _, declared, err := p.EffectExtensionAttributes("acme.absent/v1"); err != nil || declared {
		t.Fatalf("undeclared extension should not report declared: declared=%v err=%v", declared, err)
	}
}

func TestEffectExtensionsAbsentStaysValid(t *testing.T) {
	// Every document written before extensions existed — including effect
	// blocks with no extensions — keeps conforming.
	if errs := mustValidate(t, docWithEffect(validEffect)); len(errs) != 0 {
		t.Fatalf("effect block without extensions should conform, got %v", errs)
	}
	if errs := mustValidate(t, positive); len(errs) != 0 {
		t.Fatalf("legacy fixture should still conform, got %v", errs)
	}
}

func TestEffectExtensionValidationRefusals(t *testing.T) {
	cases := []struct {
		name  string
		ext   string
		field string
		want  string
	}{
		{
			name:  "missing authority class",
			ext:   "  - name: acme.settlement/v1",
			field: "effect.extensions[0].authority",
			want:  "never defaults to informational",
		},
		{
			name: "unknown authority class",
			ext: `  - name: acme.settlement/v1
    authority: advisory`,
			field: "effect.extensions[0].authority",
			want:  "is not one of",
		},
		{
			name: "unversioned extension",
			ext: `  - name: acme.settlement
    authority: informational`,
			field: "effect.extensions[0].name",
			want:  "must declare an explicit version",
		},
		{
			name: "version with leading zero",
			ext: `  - name: acme.settlement/v01
    authority: informational`,
			field: "effect.extensions[0].name",
			want:  "no leading zeros",
		},
		{
			name: "not namespaced",
			ext: `  - name: settlement/v1
    authority: informational`,
			field: "effect.extensions[0].name",
			want:  "namespaced dotted lowercase name",
		},
		{
			name: "reserved core namespace",
			ext: `  - name: effect.core/v1
    authority: informational`,
			field: "effect.extensions[0].name",
			want:  "is reserved for the core contracts",
		},
		{
			name:  "missing name",
			ext:   `  - authority: informational`,
			field: "effect.extensions[0].name",
			want:  "is required",
		},
		{
			name: "duplicate contract",
			ext: `  - name: acme.settlement/v1
    authority: informational
  - name: acme.settlement/v1
    authority: authority_relevant`,
			field: "effect.extensions[1].name",
			want:  "duplicates effect extension contract",
		},
		{
			name: "attribute key grammar",
			ext: `  - name: acme.settlement/v1
    authority: informational
    attributes:
      Window-Days: "2"`,
			field: `effect.extensions[0].attributes["Window-Days"]`,
			want:  "bounded lowercase name",
		},
		{
			name: "attribute value length",
			ext: `  - name: acme.settlement/v1
    authority: informational
    attributes:
      window: ` + strings.Repeat("x", MaxEffectExtensionAttributeValueLength+1),
			field: `effect.extensions[0].attributes["window"]`,
			want:  "limit is",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			errs := mustValidate(t, docWithEffect(validEffect+"\nextensions:\n"+tc.ext))
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

func TestEffectExtensionCountIsBounded(t *testing.T) {
	var b strings.Builder
	b.WriteString(validEffect)
	b.WriteString("\nextensions:")
	for i := 0; i <= MaxEffectExtensions; i++ {
		b.WriteString("\n  - name: acme.ext")
		b.WriteString(string(rune('a' + i)))
		b.WriteString("/v1\n    authority: informational")
	}
	errs := mustValidate(t, docWithEffect(b.String()))
	found := false
	for _, e := range errs {
		if e.Field == "effect.extensions" && strings.Contains(e.Message, "limit is") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a bounded-count error, got %v", errs)
	}
}

func TestExtensionsNeverReplaceCoreEffectFields(t *testing.T) {
	// An extensions list alone makes the effect block present: the four core
	// Effect v1 semantics stay mandatory, so a package can never ship domain
	// extensions in place of the typed core contract.
	onlyExtensions := `extensions:
  - name: acme.settlement/v1
    authority: authority_relevant`
	errs := mustValidate(t, docWithEffect(onlyExtensions))
	for _, field := range []string{
		"effect.contract", "effect.sideEffect", "effect.reversibility",
		"effect.idempotency", "effect.verification",
	} {
		found := false
		for _, e := range errs {
			if e.Field == field && strings.Contains(e.Message, "required") {
				found = true
			}
		}
		if !found {
			t.Fatalf("extensions without core Effect v1 must require %s, got %v", field, errs)
		}
	}
}

func TestUnknownAuthorityRelevantExtensionFailsClosed(t *testing.T) {
	p, errs, err := ValidateDocument([]byte(docWithEffect(effectWithExtensions)))
	if err != nil || len(errs) != 0 {
		t.Fatalf("fixture should conform: errs=%v err=%v", errs, err)
	}

	// A consumer that understands nothing refuses: the authority-relevant
	// extension may be exactly what qualifies the core semantics.
	decision, err := p.AdmitEffectExtensions(nil)
	if err != nil {
		t.Fatalf("admit: %v", err)
	}
	if decision.Admitted {
		t.Fatal("unknown authority-relevant extension must fail closed")
	}
	if strings.Join(decision.Unrecognized, ",") != "acme.settlement/v1" {
		t.Fatalf("want the settlement contract reported unrecognized, got %v", decision.Unrecognized)
	}
	if !strings.Contains(decision.Reason, "acme.settlement/v1") {
		t.Fatalf("refusal reason should name the contract: %q", decision.Reason)
	}

	// Understanding a DIFFERENT version of the same extension is not
	// understanding it — versions are distinct contracts.
	decision, err = p.AdmitEffectExtensions([]string{"acme.settlement/v2"})
	if err != nil {
		t.Fatalf("admit: %v", err)
	}
	if decision.Admitted {
		t.Fatal("a different extension version must not be treated as understood")
	}

	// Understanding the declared contract admits; the unknown informational
	// extension never blocks.
	decision, err = p.AdmitEffectExtensions([]string{"acme.settlement/v1"})
	if err != nil {
		t.Fatalf("admit: %v", err)
	}
	if !decision.Admitted || len(decision.Unrecognized) != 0 {
		t.Fatalf("understood authority-relevant extension should admit: %+v", decision)
	}
	if strings.Join(decision.Informational, ",") != "acme.telemetry/v2" {
		t.Fatalf("informational extensions should be reported, got %v", decision.Informational)
	}
}

func TestAdmissionErrorsFailClosed(t *testing.T) {
	p, _, err := ValidateDocument([]byte(docWithEffect(effectWithExtensions)))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	// A malformed understood-set entry is a refusal, never a pass.
	decision, err := p.AdmitEffectExtensions([]string{"acme.settlement"})
	if err == nil {
		t.Fatal("an unversioned understood entry must be an error")
	}
	if decision.Admitted {
		t.Fatal("a failed admission computation must not admit")
	}
	// So is a nil package.
	var missing *Package
	decision, err = missing.AdmitEffectExtensions([]string{"acme.settlement/v1"})
	if err == nil || decision.Admitted {
		t.Fatalf("nil package must fail closed: %+v err=%v", decision, err)
	}
}

func TestExtensionsCarryNoPolicyAuthority(t *testing.T) {
	// "authority_relevant" means policy must UNDERSTAND the extension before
	// trusting the effect facts — it never encodes allow/ask/deny. The same
	// extension set conforms under every risk class, and the declared risk is
	// unchanged by it.
	for _, risk := range []string{"allow", "ask", "deny"} {
		doc := strings.Replace(docWithEffect(effectWithExtensions), "risk: ask", "risk: "+risk, 1)
		p, errs, err := ValidateDocument([]byte(doc))
		if err != nil {
			t.Fatalf("parse %s: %v", risk, err)
		}
		if len(errs) != 0 {
			t.Fatalf("extensions and risk are independent axes, got %v", errs)
		}
		if p.ExecutionBoundary.Risk != risk {
			t.Fatalf("risk rewritten by an extension: %q", p.ExecutionBoundary.Risk)
		}
	}
}

func TestCanonicalDigestCoversEffectExtensions(t *testing.T) {
	// Extensions live inside the canonical document, so changing one changes
	// the manifest digest: an extension change is a new package/revision
	// identity, never a re-pointed one.
	base := docWithEffect(effectWithExtensions)
	cases := map[string]string{
		"version bump":     strings.Replace(base, "acme.settlement/v1", "acme.settlement/v2", 1),
		"authority change": strings.Replace(base, "authority: authority_relevant", "authority: informational", 1),
		"attribute change": strings.Replace(base, "window: t_plus_2", "window: t_plus_0", 1),
		"extension removed": docWithEffect(strings.Replace(effectWithExtensions,
			"\n  - name: acme.telemetry/v2\n    authority: informational", "", 1)),
	}
	a, err := CanonicalJSON([]byte(base))
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	if !strings.Contains(string(a), `"extensions":[`) {
		t.Fatalf("canonical form lost the extensions: %s", a)
	}
	for name, mutated := range cases {
		if mutated == base {
			t.Fatalf("%s: fixture mutation did not apply", name)
		}
		b, err := CanonicalJSON([]byte(mutated))
		if err != nil {
			t.Fatalf("%s: canonicalize: %v", name, err)
		}
		if string(a) == string(b) {
			t.Fatalf("%s did not change the canonical digest", name)
		}
	}
}

func TestNormalizeEffectExtension(t *testing.T) {
	ok, err := NormalizeEffectExtension("acme.payments.settlement/v12")
	if err != nil || ok != "acme.payments.settlement/v12" {
		t.Fatalf("canonical spelling should round-trip: %q %v", ok, err)
	}
	for _, bad := range []string{
		"", "acme.settlement", "acme.settlement/", "acme.settlement/v0",
		"acme.settlement/1", "Acme.Settlement/v1", "settlement/v1",
		"capability.identity/v1", "effect.core/v1",
		strings.Repeat("a", MaxEffectExtensionLength) + ".x/v1",
	} {
		if _, err := NormalizeEffectExtension(bad); err == nil {
			t.Fatalf("%q should not normalize", bad)
		}
	}
}
