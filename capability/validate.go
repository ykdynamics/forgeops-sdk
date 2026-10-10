package capability

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Parse decodes a capability.yaml document into a Package. It does not
// validate semantics; call Validate for the normative checks. A document whose
// schemaVersion is missing or unknown is still returned (Validate reports it)
// so callers always see the raw doc plus the findings.
//
// The document may be authored as YAML or JSON. The schemas are normalized to
// their canonical JSON form on parse.
func Parse(data []byte) (*Package, error) {
	norm, err := CanonicalJSON(data)
	if err != nil {
		return nil, err
	}
	var p Package
	if err := json.Unmarshal(norm, &p); err != nil {
		return nil, fmt.Errorf("capability.yaml does not match the schema shape: %w", err)
	}
	return &p, nil
}

// CanonicalJSON normalizes a capability.yaml document (authored as YAML or
// JSON) to its canonical JSON form: YAML is decoded, re-encoded as JSON with
// deterministic key order, and the embedded schemas land in their canonical
// JSON shape. Two semantically identical documents (any key order, any
// whitespace) canonicalize identically — this is the exact bytes a manifest
// digest covers, so consumers (the registry in forgeops-platform, revision
// admission in forgeops-control) can verify that a declared digest is the
// digest of the actual package.
func CanonicalJSON(data []byte) ([]byte, error) {
	var v any
	if err := yaml.Unmarshal(data, &v); err != nil {
		return nil, fmt.Errorf("capability.yaml is not valid YAML: %w", err)
	}
	norm, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("capability.yaml does not normalize to JSON: %w", err)
	}
	return norm, nil
}

// Validate runs the normative checks and returns the findings in a
// deterministic order. An empty slice means the document conforms.
func Validate(p *Package) []Error {
	var errs []Error
	if p == nil {
		return []Error{{Message: "document is empty"}}
	}
	errs = append(errs, validateSchemaVersion(p.SchemaVersion)...)
	errs = append(errs, validateIdentity(p.Identity)...)
	errs = append(errs, validateContract(p.Contract)...)
	errs = append(errs, validateBoundary(p.ExecutionBoundary)...)
	errs = append(errs, validateEffect(p.Effect)...)
	errs = append(errs, validateRuntime(p.Runtime)...)
	return errs
}

// ValidateDocument parses + validates in one call.
func ValidateDocument(data []byte) (*Package, []Error, error) {
	p, err := Parse(data)
	if err != nil {
		return nil, nil, err
	}
	return p, Validate(p), nil
}

var keyRe = regexp.MustCompile(`^[a-z0-9]+([._-][a-z0-9]+)*$`)
var digestRe = regexp.MustCompile(`^(sha256|sha512):[0-9a-f]{64,128}$`)

func validateIdentity(id Identity) []Error {
	var errs []Error
	if id.Key == "" {
		errs = append(errs, Error{Field: "identity.key", Message: "is required"})
	} else if !keyRe.MatchString(id.Key) {
		errs = append(errs, Error{Field: "identity.key", Message: fmt.Sprintf("%q is not a valid capability key (lowercase alphanumeric dotted segments)", id.Key)})
	}
	if id.Version == "" {
		errs = append(errs, Error{Field: "identity.version", Message: "is required (semver)"})
	} else if !isSemver(id.Version) {
		errs = append(errs, Error{Field: "identity.version", Message: fmt.Sprintf("%q is not valid semver", id.Version)})
	}
	if id.ArtifactDigest == "" {
		errs = append(errs, Error{Field: "identity.artifactDigest", Message: "is required (the immutable implementation digest binds identity to execution bytes)"})
	} else if !digestRe.MatchString(id.ArtifactDigest) {
		errs = append(errs, Error{Field: "identity.artifactDigest", Message: fmt.Sprintf("%q is not a supported digest (want sha256:<hex> or sha512:<hex>)", id.ArtifactDigest)})
	}
	return errs
}

func validateContract(c Contract) []Error {
	var errs []Error
	if len(c.InputSchema) == 0 {
		errs = append(errs, Error{Field: "contract.inputSchema", Message: "is required"})
	} else if msg := jsonSchemaShape(c.InputSchema); msg != "" {
		errs = append(errs, Error{Field: "contract.inputSchema", Message: msg})
	}
	if len(c.OutputSchema) == 0 {
		errs = append(errs, Error{Field: "contract.outputSchema", Message: "is required"})
	} else if msg := jsonSchemaShape(c.OutputSchema); msg != "" {
		errs = append(errs, Error{Field: "contract.outputSchema", Message: msg})
	}
	return errs
}

func validateBoundary(b ExecutionBoundary) []Error {
	var errs []Error
	if b.Risk == "" {
		errs = append(errs, Error{Field: "executionBoundary.risk", Message: "is required (allow | ask | deny)"})
	} else if !contains(AllowedRisk, b.Risk) {
		errs = append(errs, Error{Field: "executionBoundary.risk", Message: fmt.Sprintf("%q is not one of %v", b.Risk, AllowedRisk)})
	}
	seen := map[string]bool{}
	for i, s := range b.RequiredSecrets {
		field := fmt.Sprintf("executionBoundary.requiredSecrets[%d]", i)
		if strings.TrimSpace(s) == "" {
			errs = append(errs, Error{Field: field, Message: "secret name must not be empty"})
			continue
		}
		if seen[s] {
			errs = append(errs, Error{Field: field, Message: fmt.Sprintf("duplicate secret name %q", s)})
		}
		seen[s] = true
	}
	errs = append(errs, validateCompatibleTargetTypes(b.CompatibleTargetTypes)...)
	return errs
}

// validateCompatibleTargetTypes enforces the R6.2b declaration rules
// deterministically (slice order): bounded count, bounded per-entry grammar
// (mirroring the typed Target model), and no two entries that normalize to the
// same name/vN contract — a type may be spelled once only, so the declaration
// set is unambiguous.
func validateCompatibleTargetTypes(list []string) []Error {
	var errs []Error
	if len(list) > MaxCompatibleTargetTypes {
		errs = append(errs, Error{
			Field: "executionBoundary.compatibleTargetTypes",
			Message: fmt.Sprintf("declares %d compatible target types, limit is %d",
				len(list), MaxCompatibleTargetTypes),
		})
	}
	seen := map[string]int{}
	for i, raw := range list {
		field := fmt.Sprintf("executionBoundary.compatibleTargetTypes[%d]", i)
		if strings.TrimSpace(raw) == "" {
			errs = append(errs, Error{Field: field, Message: "target type is required (dotted lowercase name with optional /vN)"})
			continue
		}
		normalized, err := NormalizeTargetType(raw)
		if err != nil {
			errs = append(errs, Error{Field: field, Message: err.Error()})
			continue
		}
		if first, dup := seen[normalized]; dup {
			errs = append(errs, Error{
				Field:   field,
				Message: fmt.Sprintf("duplicates target-type contract %q (already declared at [%d])", normalized, first),
			})
			continue
		}
		seen[normalized] = i
	}
	return errs
}

// validateEffect enforces the R6.4a Effect v1 block deterministically. The
// effect block is optional (legacy documents stay on the untyped lane); when
// present, the contract must be effect.v1 and all four semantics must be one of
// the closed vocabularies. A lone R6.4d extensions list makes the block present
// too: an extension can never enter a document that declares no core contract.
func validateEffect(e Effect) []Error {
	var errs []Error
	if !e.Declared() {
		return nil
	}
	if e.Contract == "" {
		errs = append(errs, Error{Field: "effect.contract", Message: "is required when an effect block is present (effect.v1)"})
	} else if e.Contract != EffectContract {
		errs = append(errs, Error{Field: "effect.contract", Message: fmt.Sprintf("unsupported effect contract %q (want %q)", e.Contract, EffectContract)})
	}
	for _, f := range []struct {
		field   string
		value   string
		allowed []string
	}{
		{"effect.sideEffect", e.SideEffect, AllowedSideEffects},
		{"effect.reversibility", e.Reversibility, AllowedReversibilities},
		{"effect.idempotency", e.Idempotency, AllowedIdempotencies},
		{"effect.verification", e.Verification, AllowedVerifications},
	} {
		if f.value == "" {
			errs = append(errs, Error{Field: f.field, Message: "is required when an effect block is present"})
			continue
		}
		if !contains(f.allowed, f.value) {
			errs = append(errs, Error{Field: f.field, Message: fmt.Sprintf("%q is not one of %v", f.value, f.allowed)})
		}
	}
	errs = append(errs, validateEffectExtensions(e.Extensions)...)
	return errs
}

// validateEffectExtensions enforces the R6.4d extension rules deterministically
// (slice order, then sorted attribute keys): a bounded count, a namespaced and
// explicitly versioned contract spelled once, and an explicit authority class —
// an extension that declares no class is refused rather than read as
// informational, so nothing authority-bearing enters through omission.
func validateEffectExtensions(list []EffectExtension) []Error {
	var errs []Error
	if len(list) > MaxEffectExtensions {
		errs = append(errs, Error{
			Field:   "effect.extensions",
			Message: fmt.Sprintf("declares %d effect extensions, limit is %d", len(list), MaxEffectExtensions),
		})
	}
	seen := map[string]int{}
	for i, ext := range list {
		field := fmt.Sprintf("effect.extensions[%d]", i)
		name := strings.TrimSpace(ext.Name)
		if name == "" {
			errs = append(errs, Error{Field: field + ".name", Message: "is required (namespaced, versioned contract, e.g. acme.settlement/v1)"})
		} else if normalized, err := NormalizeEffectExtension(name); err != nil {
			errs = append(errs, Error{Field: field + ".name", Message: err.Error()})
		} else if first, dup := seen[normalized]; dup {
			errs = append(errs, Error{
				Field:   field + ".name",
				Message: fmt.Sprintf("duplicates effect extension contract %q (already declared at [%d])", normalized, first),
			})
		} else {
			seen[normalized] = i
		}
		switch {
		case ext.Authority == "":
			errs = append(errs, Error{
				Field:   field + ".authority",
				Message: fmt.Sprintf("is required (%v) — an extension never defaults to informational", AllowedExtensionAuthorities),
			})
		case !contains(AllowedExtensionAuthorities, ext.Authority):
			errs = append(errs, Error{
				Field:   field + ".authority",
				Message: fmt.Sprintf("%q is not one of %v", ext.Authority, AllowedExtensionAuthorities),
			})
		}
		errs = append(errs, validateEffectExtensionAttributes(field, ext.Attributes)...)
	}
	return errs
}

// validateEffectExtensionAttributes bounds one extension's payload. Attributes
// are flat, bounded strings by construction (the schema type carries no nested
// form), so an extension cannot smuggle an arbitrary metadata document past the
// core contract; this enforces the count, key grammar and length limits in
// sorted key order for deterministic findings.
func validateEffectExtensionAttributes(field string, attrs map[string]string) []Error {
	var errs []Error
	if len(attrs) == 0 {
		return nil
	}
	if len(attrs) > MaxEffectExtensionAttributes {
		errs = append(errs, Error{
			Field:   field + ".attributes",
			Message: fmt.Sprintf("declares %d attributes, limit is %d", len(attrs), MaxEffectExtensionAttributes),
		})
	}
	keys := make([]string, 0, len(attrs))
	for k := range attrs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		keyField := fmt.Sprintf("%s.attributes[%q]", field, k)
		switch {
		case len(k) > MaxEffectExtensionAttributeKeyLength:
			errs = append(errs, Error{
				Field:   keyField,
				Message: fmt.Sprintf("attribute key is %d bytes, limit is %d", len(k), MaxEffectExtensionAttributeKeyLength),
			})
		case !effectExtensionAttributeKeyRe.MatchString(k):
			errs = append(errs, Error{
				Field:   keyField,
				Message: "attribute key must be a bounded lowercase name (letters, digits, . or _ separators)",
			})
		}
		if v := attrs[k]; len(v) > MaxEffectExtensionAttributeValueLength {
			errs = append(errs, Error{
				Field:   keyField,
				Message: fmt.Sprintf("attribute value is %d bytes, limit is %d", len(v), MaxEffectExtensionAttributeValueLength),
			})
		}
	}
	return errs
}

// Conforms reports whether the document conforms.
func Conforms(p *Package) bool {
	return p != nil && len(Validate(p)) == 0
}

func validateSchemaVersion(v string) []Error {
	if v == "" {
		return []Error{{Field: "schemaVersion", Message: "is required (the normative contract version)"}}
	}
	if v != SchemaVersion {
		return []Error{{Field: "schemaVersion", Message: fmt.Sprintf("unsupported schema version %q (want %q)", v, SchemaVersion)}}
	}
	return nil
}

func validateRuntime(r Runtime) []Error {
	var errs []Error
	if r.Interface == "" {
		errs = append(errs, Error{Field: "runtime.interface", Message: "is required (mcp)"})
	}
	if r.RuntimeContract == "" {
		errs = append(errs, Error{Field: "runtime.runtimeContract", Message: "is required"})
	} else if !contains(KnownRuntimeContracts, r.RuntimeContract) {
		errs = append(errs, Error{Field: "runtime.runtimeContract", Message: fmt.Sprintf("%q is not a known runtime contract version (%v)", r.RuntimeContract, KnownRuntimeContracts)})
	}
	return errs
}

// isSemver is a permissive semantic-version check (major.minor.patch with
// optional prerelease/build). Full semver resolution is out of scope for the
// validator; this refuses obvious non-versions deterministically.
func isSemver(v string) bool {
	return regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$`).MatchString(v)
}

// jsonSchemaShape verifies a declared schema is valid JSON and, at minimum, an
// object (deep JSON-Schema conformance is the SDK's job at runtime).
func jsonSchemaShape(raw json.RawMessage) string {
	trimmed := bytes.TrimSpace(raw)
	if !json.Valid(trimmed) {
		return "must be valid JSON"
	}
	var v any
	if err := json.Unmarshal(trimmed, &v); err != nil {
		return "must be a valid JSON document"
	}
	if _, ok := v.(map[string]any); !ok {
		return "must be a JSON Schema object"
	}
	return ""
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

// SortErrors returns a stable ordering (document-level first, then by field,
// then by message) for deterministic output.
func SortErrors(errs []Error) []Error {
	out := append([]Error(nil), errs...)
	sort.SliceStable(out, func(i, j int) bool {
		// Empty field (document-level) sorts first.
		if (out[i].Field == "") != (out[j].Field == "") {
			return out[i].Field == ""
		}
		if out[i].Field != out[j].Field {
			return out[i].Field < out[j].Field
		}
		return out[i].Message < out[j].Message
	})
	return out
}
