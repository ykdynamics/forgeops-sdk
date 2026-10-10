package capability

import (
	"strings"
	"testing"
)

// R6.4f (capabilities#62): the shared admission helper is the fail-closed
// boundary on its own. Every test here builds the Package DIRECTLY and never
// calls Parse, Validate or Conforms first — that is the whole point: consumers
// reach this helper from read/storage paths that deliberately do not re-run
// manifest validation, so the guarantee cannot depend on validation having run.

// admissionPackage builds an unvalidated package carrying the given extensions.
func admissionPackage(exts ...EffectExtension) *Package {
	return &Package{Effect: Effect{
		Contract:      EffectContract,
		SideEffect:    "none",
		Reversibility: "reversible",
		Idempotency:   "safe",
		Verification:  "none",
		Extensions:    exts,
	}}
}

func TestAdmissionRefusesUnclassifiableDeclarations(t *testing.T) {
	cases := []struct {
		name      string
		ext       EffectExtension
		wantNamed string
	}{
		{
			name:      "authority class outside the vocabulary",
			ext:       EffectExtension{Name: "acme.settlement/v1", Authority: "advisory"},
			wantNamed: "acme.settlement/v1",
		},
		{
			name:      "missing authority class",
			ext:       EffectExtension{Name: "acme.settlement/v1"},
			wantNamed: "acme.settlement/v1",
		},
		{
			name:      "unversioned name",
			ext:       EffectExtension{Name: "acme.settlement", Authority: "informational"},
			wantNamed: "acme.settlement",
		},
		{
			name:      "name outside the grammar",
			ext:       EffectExtension{Name: "Acme Settlement/v1", Authority: "authority_relevant"},
			wantNamed: "Acme Settlement/v1",
		},
		{
			name:      "empty name",
			ext:       EffectExtension{Authority: "informational"},
			wantNamed: "(unnamed extension)",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Understanding everything the package could possibly mean must not
			// rescue a declaration that cannot be classified.
			decision, err := admissionPackage(tc.ext).AdmitEffectExtensions([]string{"acme.settlement/v1"})
			if err == nil {
				t.Fatal("an unclassifiable declaration must report an error")
			}
			if decision.Admitted {
				t.Fatalf("unclassifiable declaration was admitted: %+v", decision)
			}
			if strings.Join(decision.Malformed, ",") != tc.wantNamed {
				t.Fatalf("Malformed = %v, want [%s]", decision.Malformed, tc.wantNamed)
			}
			// The single complete blocking list carries it too, so a consumer
			// gating only on Unrecognized is equally safe.
			if strings.Join(decision.Unrecognized, ",") != tc.wantNamed {
				t.Fatalf("Unrecognized = %v, want [%s]", decision.Unrecognized, tc.wantNamed)
			}
			if !strings.Contains(decision.Reason, tc.wantNamed) {
				t.Fatalf("reason should name the declaration: %q", decision.Reason)
			}
		})
	}
}

func TestAdmissionKeepsConformingBehavior(t *testing.T) {
	authority := EffectExtension{Name: "acme.settlement/v1", Authority: ExtensionAuthorityRelevant}
	informational := EffectExtension{Name: "acme.telemetry/v2", Authority: ExtensionInformational}

	// Unknown but VALID authority-relevant extension: refused as before, and
	// not reported as malformed — "unsupported" and "corrupt" stay distinct.
	decision, err := admissionPackage(authority).AdmitEffectExtensions(nil)
	if err != nil {
		t.Fatalf("a well-formed unknown extension is a refusal, not an error: %v", err)
	}
	if decision.Admitted {
		t.Fatalf("unknown authority-relevant extension must refuse: %+v", decision)
	}
	if len(decision.Malformed) != 0 {
		t.Fatalf("a well-formed declaration must not be reported malformed: %+v", decision)
	}
	if strings.Join(decision.Unrecognized, ",") != "acme.settlement/v1" {
		t.Fatalf("Unrecognized = %v", decision.Unrecognized)
	}

	// Unknown informational extension: admitted, as before.
	decision, err = admissionPackage(informational).AdmitEffectExtensions(nil)
	if err != nil || !decision.Admitted {
		t.Fatalf("unknown informational extension must not block: %+v err=%v", decision, err)
	}
	if strings.Join(decision.Informational, ",") != "acme.telemetry/v2" {
		t.Fatalf("Informational = %v", decision.Informational)
	}

	// Recognized authority-relevant extension: admitted.
	decision, err = admissionPackage(authority, informational).
		AdmitEffectExtensions([]string{"acme.settlement/v1"})
	if err != nil || !decision.Admitted {
		t.Fatalf("recognized extension must admit: %+v err=%v", decision, err)
	}
	if len(decision.Unrecognized) != 0 || len(decision.Malformed) != 0 {
		t.Fatalf("nothing should block: %+v", decision)
	}
	if !strings.Contains(decision.Reason, "acme.settlement/v1") {
		t.Fatalf("reason should name what was understood: %q", decision.Reason)
	}

	// No extensions at all: admitted, unchanged.
	decision, err = admissionPackage().AdmitEffectExtensions(nil)
	if err != nil || !decision.Admitted {
		t.Fatalf("a package with no extensions must admit: %+v err=%v", decision, err)
	}
}

func TestAdmissionReportsMalformedAndUnknownTogether(t *testing.T) {
	decision, err := admissionPackage(
		EffectExtension{Name: "acme.settlement/v1", Authority: ExtensionAuthorityRelevant},
		EffectExtension{Name: "acme.consent/v1", Authority: "advisory"},
		EffectExtension{Name: "acme.telemetry/v2", Authority: ExtensionInformational},
	).AdmitEffectExtensions(nil)
	if err == nil || decision.Admitted {
		t.Fatalf("mixed malformed + unknown must refuse: %+v err=%v", decision, err)
	}
	if strings.Join(decision.Unrecognized, ",") != "acme.consent/v1,acme.settlement/v1" {
		t.Fatalf("Unrecognized should carry both, sorted: %v", decision.Unrecognized)
	}
	if strings.Join(decision.Malformed, ",") != "acme.consent/v1" {
		t.Fatalf("Malformed should carry only the unclassifiable one: %v", decision.Malformed)
	}
	if !strings.Contains(decision.Reason, "unclassifiable") || !strings.Contains(decision.Reason, "unrecognized") {
		t.Fatalf("reason should distinguish both causes: %q", decision.Reason)
	}
	// The informational extension is still reported and still never blocks.
	if strings.Join(decision.Informational, ",") != "acme.telemetry/v2" {
		t.Fatalf("Informational = %v", decision.Informational)
	}
}

func TestAdmissionIsDeterministicAndDeduplicated(t *testing.T) {
	pkg := admissionPackage(
		EffectExtension{Name: "acme.settlement/v1", Authority: ExtensionAuthorityRelevant},
		EffectExtension{Name: "acme.settlement/v1", Authority: ExtensionAuthorityRelevant},
		EffectExtension{Name: "acme.consent/v1", Authority: ExtensionAuthorityRelevant},
	)
	first, _ := pkg.AdmitEffectExtensions(nil)
	second, _ := pkg.AdmitEffectExtensions(nil)
	if strings.Join(first.Unrecognized, ",") != "acme.consent/v1,acme.settlement/v1" {
		t.Fatalf("not sorted/deduplicated: %v", first.Unrecognized)
	}
	if strings.Join(first.Unrecognized, ",") != strings.Join(second.Unrecognized, ",") ||
		first.Reason != second.Reason {
		t.Fatalf("admission is not deterministic: %+v vs %+v", first, second)
	}
}

func TestAdmissionRefusesMalformedUnderstoodSetAndNilPackage(t *testing.T) {
	pkg := admissionPackage(EffectExtension{Name: "acme.settlement/v1", Authority: ExtensionAuthorityRelevant})
	decision, err := pkg.AdmitEffectExtensions([]string{"acme.settlement"})
	if err == nil || decision.Admitted {
		t.Fatalf("a malformed understood entry must fail closed: %+v err=%v", decision, err)
	}
	var missing *Package
	decision, err = missing.AdmitEffectExtensions(nil)
	if err == nil || decision.Admitted {
		t.Fatalf("nil package must fail closed: %+v err=%v", decision, err)
	}
}
