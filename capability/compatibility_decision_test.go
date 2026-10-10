package capability

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestDeclaresCompatibleTargetType(t *testing.T) {
	p, errs, err := ValidateDocument([]byte(typedDoc("[kubernetes.cluster, sap.system/v2]")))
	if err != nil || len(errs) != 0 {
		t.Fatalf("fixture must conform: %v %v", errs, err)
	}
	for _, candidate := range []string{"kubernetes.cluster", "kubernetes.cluster/v1", "sap.system/v2"} {
		got, err := p.DeclaresCompatibleTargetType(candidate)
		if err != nil {
			t.Fatalf("DeclaresCompatibleTargetType(%q) = %v", candidate, err)
		}
		if !got {
			t.Fatalf("DeclaresCompatibleTargetType(%q) = false, want true", candidate)
		}
	}
	for _, candidate := range []string{"kubernetes.cluster/v3", "postgres.database", "sap.system"} {
		got, err := p.DeclaresCompatibleTargetType(candidate)
		if err != nil {
			t.Fatalf("DeclaresCompatibleTargetType(%q) = %v", candidate, err)
		}
		if got {
			t.Fatalf("DeclaresCompatibleTargetType(%q) = true, want false", candidate)
		}
	}
	if _, err := p.DeclaresCompatibleTargetType("BAD TYPE"); err == nil {
		t.Fatal("malformed candidate should error, not silently refuse")
	}
}

func TestNoDeclarationFailsClosedForTypedBinding(t *testing.T) {
	legacy, errs, err := ValidateDocument([]byte(positive))
	if err != nil || len(errs) != 0 {
		t.Fatalf("legacy fixture must conform: %v %v", errs, err)
	}
	// A legacy revision with only the free-form target class declares no typed
	// contract, so a typed binding to it is refused (fail closed), never
	// guessed compatible.
	got, err := legacy.DeclaresCompatibleTargetType("acme-service")
	if err != nil {
		t.Fatalf("DeclaresCompatibleTargetType: %v", err)
	}
	if got {
		t.Fatal("legacy free-form target class was treated as a typed compatible contract")
	}
	var nilPkg *Package
	if got, err := nilPkg.DeclaresCompatibleTargetType("acme-service"); err != nil || got {
		t.Fatalf("nil package should decline typed compatibility (got=%v err=%v)", got, err)
	}
}

func TestEmptyAndAbsentDeclarationsProjectToTheSameSet(t *testing.T) {
	// [] and an omitted declaration are the same empty compatibility set
	// (both conform; both fail closed for typed binding) even though their raw
	// canonical bytes differ. The projection, not the raw spelling, is the
	// semantic identity binding checks use.
	empty, errs, err := ValidateDocument([]byte(typedDoc("[]")))
	if err != nil || len(errs) != 0 {
		t.Fatalf("empty declaration must conform: %v %v", errs, err)
	}
	absent, errs, err := ValidateDocument([]byte(typedDoc("")))
	if err != nil || len(errs) != 0 {
		t.Fatalf("absent declaration must conform: %v %v", errs, err)
	}
	cEmpty, err := empty.CompatibleTargetTypeContracts()
	if err != nil {
		t.Fatalf("project empty: %v", err)
	}
	cAbsent, err := absent.CompatibleTargetTypeContracts()
	if err != nil {
		t.Fatalf("project absent: %v", err)
	}
	if len(cEmpty) != 0 || len(cAbsent) != 0 {
		t.Fatalf("empty declarations must project to an empty set: %v %v", cEmpty, cAbsent)
	}
}

func TestCanonicalDigestCoversCompatibilityDeclaration(t *testing.T) {
	// The manifest digest (sha256 of CanonicalJSON) is the immutable revision
	// identity in platform adoption and control caprevision. A document that
	// differs ONLY in its compatibleTargetTypes must therefore produce a
	// different digest — changing compatibility can never ride under the same
	// revision identity.
	none := typedDoc("")
	a := typedDoc("[sap.system/v2]")
	b := typedDoc("[kubernetes.cluster, sap.system/v2]")

	digest := func(doc string) string {
		canonical, err := CanonicalJSON([]byte(doc))
		if err != nil {
			t.Fatalf("canonicalize: %v", err)
		}
		sum := sha256.Sum256(canonical)
		return hex.EncodeToString(sum[:])
	}
	if digest(none) == digest(a) || digest(a) == digest(b) {
		t.Fatal("compatibleTargetTypes changes did not change the revision digest")
	}
}

func TestTypedDocCanonicalJSONDeterministic(t *testing.T) {
	// YAML and JSON documents with the same typed declaration but different key
	// order/whitespace must canonicalize to identical bytes (the digest input).
	yamlDoc := typedDoc("[kubernetes.cluster, sap.system/v2]")
	jsonDoc := `{"schemaVersion":"capability.v1","runtime":{"interface":"mcp","runtimeContract":"runtime.v1"},"identity":{"key":"acme.service.restart","version":"2.0.0","artifactDigest":"sha256:52b350d25777409fe32df0dc1ca6809f74dade7355b8e79a39bcc87e38a9e3be"},"contract":{"description":"restarts the acme service (R6.2b conformance fixture)","inputSchema":{"type":"object","required":["service"],"additionalProperties":false,"properties":{"service":{"type":"string","minLength":1}}},"outputSchema":{"type":"object","required":["restarted"],"additionalProperties":false,"properties":{"restarted":{"type":"boolean"}}}},"executionBoundary":{"risk":"ask","requiredSecrets":["SERVICE_TOKEN"],"compatibleTargetTypes":["kubernetes.cluster","sap.system/v2"]}}`
	a, err := CanonicalJSON([]byte(yamlDoc))
	if err != nil {
		t.Fatalf("canonicalize YAML: %v", err)
	}
	b, err := CanonicalJSON([]byte(jsonDoc))
	if err != nil {
		t.Fatalf("canonicalize JSON: %v", err)
	}
	if string(a) != string(b) {
		t.Fatalf("canonical forms differ:\nYAML: %s\nJSON: %s", a, b)
	}
	if !strings.Contains(string(a), `"compatibleTargetTypes":["kubernetes.cluster","sap.system/v2"]`) {
		t.Fatalf("canonical form lost the declaration: %s", a)
	}
}
