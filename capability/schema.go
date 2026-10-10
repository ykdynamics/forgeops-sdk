// Package capability is the normative Capability Package v1 contract: the one
// canonical capability.yaml identity that spans developer build ->
// registry/adoption -> customer review -> edge admission -> execution ->
// evidence.
//
// The package is intentionally dependency-free (stdlib + YAML only), so the
// same validator serves edge admission, registry identity, developer tooling
// and qualification alike: what it accepts and refuses is the contract.
package capability

import (
	"encoding/json"
	"fmt"
)

// SchemaVersion is the explicit, versioned contract identity of the canonical
// capability.yaml document. A document whose schemaVersion differs is refused
// before any field is interpreted.
const SchemaVersion = "capability.v1"

// EffectContract is the versioned contract identity of the Effect v1
// block. A present effect block must declare exactly this
// contract; the four semantics below are the closed effect.v1 vocabulary.
const EffectContract = "effect.v1"

// KnownRuntimeContracts lists the accepted runtime contract versions. The SDK
// speaks runtime.v1 (sdk.RuntimeContractVersion).
var KnownRuntimeContracts = []string{"runtime.v1"}

// AllowedRisk values mirror the policy classes: allow (autonomous), ask
// (bounded human authority), deny (never executes).
var AllowedRisk = []string{"allow", "ask", "deny"}

// Package is the canonical Capability Package v1 document.
type Package struct {
	// SchemaVersion is the normative contract version (must equal SchemaVersion).
	SchemaVersion string `json:"schemaVersion" yaml:"schemaVersion"`
	// Identity is the immutable package identity: the same value a developer
	// builds, a registry publishes, a customer reviews, an edge admits, and an
	// evidence chain names.
	Identity Identity `json:"identity" yaml:"identity"`
	// Contract is the typed input/output contract of the capability.
	Contract Contract `json:"contract" yaml:"contract"`
	// ExecutionBoundary is what the capability requests permission to touch:
	// risk class, secrets, egress, target class. Binding happens separately
	// (install != execution authorization).
	ExecutionBoundary ExecutionBoundary `json:"executionBoundary" yaml:"executionBoundary"`
	// Effect is the minimum immutable effect.v1
	// contract: DESCRIPTIVE operation semantics (side effect, reversibility,
	// idempotency, verification) — never allow/ask/deny policy, which stays in
	// ExecutionBoundary.Risk. Additive and optional: legacy documents without
	// it stay valid on the untyped lane.
	Effect Effect `json:"effect,omitempty" yaml:"effect,omitempty"`
	// Runtime declares the execution interface + runtime contract version.
	Runtime Runtime `json:"runtime" yaml:"runtime"`
}

// Identity is the immutable package identity.
type Identity struct {
	// Key is the capability key (e.g. acme.service.restart). Stable across
	// versions; the pair (key, version) is the human identity.
	Key string `json:"key" yaml:"key"`
	// Version is the semantic version of THIS contract (semver).
	Version string `json:"version" yaml:"version"`
	// ArtifactDigest is the immutable implementation digest
	// (e.g. sha256:<hex>). Tamper detection binds the identity to the bytes
	// that will execute.
	ArtifactDigest string `json:"artifactDigest" yaml:"artifactDigest"`
	// ImplementationPlatform is the execution platform metadata
	// (e.g. linux/arm64).
	ImplementationPlatform string `json:"implementationPlatform,omitempty" yaml:"implementationPlatform,omitempty"`
}

// Contract is the typed input/output contract of the capability.
type Contract struct {
	// Description is the human-safe purpose statement.
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	// InputSchema is the JSON Schema for the caller input (the SDK subset:
	// type, required, properties, items, additionalProperties, enum, const).
	InputSchema json.RawMessage `json:"inputSchema" yaml:"inputSchema"`
	// OutputSchema is the JSON Schema for the result.
	OutputSchema json.RawMessage `json:"outputSchema" yaml:"outputSchema"`
	// IdempotencyKey is the required input field (dotted path) mutation
	// capabilities use as their stable intended-effect key.
	IdempotencyKey string `json:"idempotencyKey,omitempty" yaml:"idempotencyKey,omitempty"`
}

// ExecutionBoundary is what the capability requests permission to touch.
type ExecutionBoundary struct {
	// Risk is the policy class: allow | ask | deny.
	Risk string `json:"risk" yaml:"risk"`
	// RequiredSecrets names the customer-local secrets the capability needs at
	// the edge (never values, never names beyond the declared set).
	RequiredSecrets []string `json:"requiredSecrets,omitempty" yaml:"requiredSecrets,omitempty"`
	// Egress declares allowed outbound destinations (allowlist semantics).
	Egress []string `json:"egress,omitempty" yaml:"egress,omitempty"`
	// Target is the v1 legacy declared target class the capability may act on
	// (one free-form class label, kept unchanged for documents already
	// written). Typed Target v2 compatibility is declared separately in
	// CompatibleTargetTypes; this field is never reinterpreted as a typed
	// target-type contract.
	Target string `json:"target,omitempty" yaml:"target,omitempty"`
	// CompatibleTargetTypes declares, deterministically, the versioned
	// target-type schema contracts this immutable capability revision is
	// compatible with — e.g. "kubernetes.cluster" or "sap.system/v2" — NOT
	// concrete customer targets and NOT invocation resources. The declaration
	// is part of the canonical document, so the manifest digest (revision
	// identity) covers it: changing compatibility requires a new capability
	// revision. Grammar is that of ForgeOps' typed target model (dotted
	// lowercase type name + optional /vN; the canonical form spells name/vN).
	CompatibleTargetTypes []string `json:"compatibleTargetTypes,omitempty" yaml:"compatibleTargetTypes,omitempty"`
}

// Runtime declares the execution interface + runtime contract version.
type Runtime struct {
	// Interface is the execution interface (mcp).
	Interface string `json:"interface" yaml:"interface"`
	// RuntimeContract is the runtime contract version (runtime.v1).
	RuntimeContract string `json:"runtimeContract" yaml:"runtimeContract"`
}

// Effect is the minimum immutable Effect v1 contract:
// descriptive semantics of what an operation does and how verifiable that is.
// It is NOT policy — the allow/ask/deny authority class lives in
// ExecutionBoundary.Risk. All four fields are required when the effect block is
// present; every value must be one of the closed effect.v1 vocabularies below.
type Effect struct {
	// Contract must equal EffectContract ("effect.v1").
	Contract string `json:"contract,omitempty" yaml:"contract,omitempty"`
	// SideEffect is the observable external consequence class.
	// none | mutation | external
	SideEffect string `json:"sideEffect" yaml:"sideEffect"`
	// Reversibility is whether the intended effect can be undone.
	// reversible | irreversible | unknown
	Reversibility string `json:"reversibility" yaml:"reversibility"`
	// Idempotency is how the operation behaves under repeated delivery.
	// safe | key_required | unsafe
	Idempotency string `json:"idempotency" yaml:"idempotency"`
	// Verification is what the capability offers to prove its intended
	// effect occurred. none | supported | required
	Verification string `json:"verification" yaml:"verification"`
	// Extensions are bounded, namespaced, versioned
	// domain extensions of these semantics. They never replace or relax the
	// four core fields above, and an authority-relevant extension a consumer
	// does not understand fails closed (AdmitEffectExtensions). Optional.
	Extensions []EffectExtension `json:"extensions,omitempty" yaml:"extensions,omitempty"`
}

// Closed effect.v1 vocabularies (strict enums — unknown values are refused).
var (
	AllowedSideEffects     = []string{"none", "mutation", "external"}
	AllowedReversibilities = []string{"reversible", "irreversible", "unknown"}
	AllowedIdempotencies   = []string{"safe", "key_required", "unsafe"}
	AllowedVerifications   = []string{"none", "supported", "required"}
)

// Error is one deterministic, structured validation finding. Order is stable:
// the validator reports section by section, field by field, never map order.
type Error struct {
	// Field is the dotted path of the offending field ("" for document-level).
	Field string `json:"field"`
	// Message is the human-safe explanation.
	Message string `json:"message"`
}

func (e Error) String() string {
	if e.Field == "" {
		return e.Message
	}
	return fmt.Sprintf("%s: %s", e.Field, e.Message)
}
