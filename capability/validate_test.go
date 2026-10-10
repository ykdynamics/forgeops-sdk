package capability

import (
	"encoding/json"
	"strings"
	"testing"
)

// positive is a conforming document exercising every section.
const positive = `schemaVersion: capability.v1
identity:
  key: acme.service.restart
  version: 1.0.0
  artifactDigest: sha256:52b350d25777409fe32df0dc1ca6809f74dade7355b8e79a39bcc87e38a9e3be
  implementationPlatform: linux/arm64
contract:
  description: restarts the acme service (conformance fixture)
  inputSchema:
    type: object
    required: [service]
    additionalProperties: false
    properties:
      service:
        type: string
        minLength: 1
  outputSchema:
    type: object
    required: [restarted]
    additionalProperties: false
    properties:
      restarted:
        type: boolean
      receipt:
        type: string
  idempotencyKey: receipt
executionBoundary:
  risk: ask
  requiredSecrets: [SERVICE_TOKEN]
  egress: []
  target: acme-service
runtime:
  interface: mcp
  runtimeContract: runtime.v1
`

func mustValidate(t *testing.T, doc string) []Error {
	t.Helper()
	p, errs, err := ValidateDocument([]byte(doc))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if p == nil {
		t.Fatal("parse returned nil package")
	}
	return errs
}

func TestPositiveConforms(t *testing.T) {
	if errs := mustValidate(t, positive); len(errs) != 0 {
		t.Fatalf("positive fixture should conform, got %v", errs)
	}
}

func TestPositiveReadCapabilityConforms(t *testing.T) {
	// A safe read: allow risk, no secrets, no idempotency key.
	const readDoc = `schemaVersion: capability.v1
identity:
  key: acme.service.status
  version: 1.0.0
  artifactDigest: sha256:0fd3864653fe40ce985d2fb2e5cb8ec195c2f4d8ae9bd14e7204283ec8169035
contract:
  inputSchema:
    type: object
    required: [service]
    additionalProperties: false
    properties:
      service:
        type: string
        minLength: 1
  outputSchema:
    type: object
    required: [healthy]
    additionalProperties: false
    properties:
      healthy:
        type: boolean
executionBoundary:
  risk: allow
  egress: []
  target: acme-service
runtime:
  interface: mcp
  runtimeContract: runtime.v1
`
	if errs := mustValidate(t, readDoc); len(errs) != 0 {
		t.Fatalf("read fixture should conform, got %v", errs)
	}
}

func TestSchemaVersion(t *testing.T) {
	if errs := mustValidate(t, strings.ReplaceAll(positive, "schemaVersion: capability.v1\n", "")); len(errs) == 0 {
		t.Fatal("missing schemaVersion should be refused")
	} else if errs[0].Field != "schemaVersion" {
		t.Fatalf("first error should be schemaVersion, got %v", errs[0])
	}
	if errs := mustValidate(t, strings.ReplaceAll(positive, "capability.v1", "capability.v2")); len(errs) != 1 {
		t.Fatalf("unknown schemaVersion should be the only error, got %v", errs)
	}
}

func TestIdentityValidation(t *testing.T) {
	cases := []struct {
		name  string
		field string
		good  string
		bad   string
		want  string
	}{
		{"missing key", "identity.key", "  key: acme.service.restart\n", "  key: acme.service.restart\n", "required"},
		{"bad key", "identity.key", "  key: acme.service.restart\n", "  key: Acme.Service\n", "not a valid capability key"},
		{"missing version", "identity.version", "  version: 1.0.0\n", "  version: 1.0.0\n", "required"},
		{"bad version", "identity.version", "  version: 1.0.0\n", "  version: one\n", "not valid semver"},
		{"missing digest", "identity.artifactDigest", "  artifactDigest: sha256:52b350d25777409fe32df0dc1ca6809f74dade7355b8e79a39bcc87e38a9e3be\n", "  artifactDigest: sha256:52b350d25777409fe32df0dc1ca6809f74dade7355b8e79a39bcc87e38a9e3be\n", "required"},
		{"tampered digest", "identity.artifactDigest", "  artifactDigest: sha256:52b350d25777409fe32df0dc1ca6809f74dade7355b8e79a39bcc87e38a9e3be\n", "  artifactDigest: sha256:52b350d25777\n", "not a supported digest"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var doc string
			if tc.want == "required" {
				doc = strings.ReplaceAll(positive, tc.good, "")
			} else {
				doc = strings.ReplaceAll(positive, tc.good, tc.bad)
			}
			errs := mustValidate(t, doc)
			found := false
			for _, e := range errs {
				if e.Field == tc.field && strings.Contains(e.Message, tc.want) {
					found = true
				}
			}
			if !found {
				t.Fatalf("expected a %q error on %s, got %v", tc.want, tc.field, errs)
			}
		})
	}
}

func TestBoundaryValidation(t *testing.T) {
	doc := strings.ReplaceAll(positive, "risk: ask", "risk: escalate")
	if errs := mustValidate(t, doc); len(errs) == 0 {
		t.Fatal("unknown risk should be refused")
	}
	doc = strings.ReplaceAll(positive, "requiredSecrets: [SERVICE_TOKEN]", "requiredSecrets: [SERVICE_TOKEN, SERVICE_TOKEN]")
	errs := mustValidate(t, doc)
	found := false
	for _, e := range errs {
		if strings.Contains(e.Field, "requiredSecrets") && strings.Contains(e.Message, "duplicate") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a duplicate-secret error, got %v", errs)
	}
}

func TestContractValidation(t *testing.T) {
	doc := strings.ReplaceAll(positive, "  inputSchema:\n    type: object\n    required: [service]\n    additionalProperties: false\n    properties:\n      service:\n        type: string\n        minLength: 1\n", "  inputSchema: not-json\n")
	errs := mustValidate(t, doc)
	found := false
	for _, e := range errs {
		if e.Field == "contract.inputSchema" {
			found = true
		}
	}
	if !found {
		t.Fatalf("malformed input schema should be refused, got %v", errs)
	}
}

func TestRuntimeValidation(t *testing.T) {
	doc := strings.ReplaceAll(positive, "runtimeContract: runtime.v1", "runtimeContract: runtime.v2")
	errs := mustValidate(t, doc)
	found := false
	for _, e := range errs {
		if e.Field == "runtime.runtimeContract" {
			found = true
		}
	}
	if !found {
		t.Fatalf("unknown runtime contract should be refused, got %v", errs)
	}
}

func TestDeterministicOrdering(t *testing.T) {
	doc := "schemaVersion: capability.v1\nidentity: {}\ncontract: {}\nexecutionBoundary: {}\nruntime: {}\n"
	errs := mustValidate(t, doc)
	if len(errs) == 0 {
		t.Fatal("empty-sections doc should fail")
	}
	if errs[0].Field != "identity.key" {
		t.Fatalf("errors should be section-ordered, first=%v", errs[0])
	}
	sorted := SortErrors(errs)
	for i := 1; i < len(sorted); i++ {
		if sorted[i].Field != "" && sorted[i].Field < sorted[i-1].Field {
			t.Fatalf("SortErrors is not sorted: %v then %v", sorted[i-1], sorted[i])
		}
	}
}

func TestRoundTripConformanceFixture(t *testing.T) {
	p, errs, err := ValidateDocument([]byte(positive))
	if err != nil {
		t.Fatal(err)
	}
	if len(errs) != 0 {
		t.Fatalf("unexpected: %v", errs)
	}
	if p.Identity.Key != "acme.service.restart" {
		t.Fatalf("key = %q", p.Identity.Key)
	}
	if p.ExecutionBoundary.Risk != "ask" {
		t.Fatalf("risk = %q", p.ExecutionBoundary.Risk)
	}
	if p.Contract.IdempotencyKey != "receipt" {
		t.Fatalf("idempotency key = %q", p.Contract.IdempotencyKey)
	}
}

func TestCanonicalJSONDeterministic(t *testing.T) {
	// YAML and JSON documents with different key order/whitespace must
	// canonicalize to the same bytes (the manifest-digest input).
	yamlDoc := `schemaVersion: capability.v1
identity:
  key: acme.service.status
  version: 1.2.3
  artifactDigest: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
contract:
  description: x
  inputSchema:
    type: object
    properties:
      service: {type: string}
    required: [service]
  outputSchema:
    type: object
    properties:
      healthy: {type: boolean}
    required: [healthy]
executionBoundary:
  risk: allow
runtime:
  interface: mcp
  runtimeContract: runtime.v1
`
	jsonDoc := `{"schemaVersion":"capability.v1","runtime":{"runtimeContract":"runtime.v1","interface":"mcp"},"identity":{"version":"1.2.3","artifactDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","key":"acme.service.status"},"contract":{"description":"x","outputSchema":{"type":"object","properties":{"healthy":{"type":"boolean"}},"required":["healthy"]},"inputSchema":{"type":"object","properties":{"service":{"type":"string"}},"required":["service"]}},"executionBoundary":{"risk":"allow"}}`
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
	if !json.Valid(a) {
		t.Fatalf("canonical form is not valid JSON: %s", a)
	}
	// Malformed input errors.
	if _, err := CanonicalJSON([]byte("{not yaml")); err == nil {
		t.Fatal("malformed document canonicalized without error")
	}
}
