# Package capability — the normative Capability Package v1 contract (WP-R5.1a)

- **Issue:** forgeops-control#389 (WP-R5.1a), parent #360 (WP-R5.1 Capability Package v1).
- **Status:** IMPLEMENTED (schema + validator). Consumed next by R5.1b
  (platform registry identity), R5.1c (edge admission binding), and R5.2
  (developer tooling package workflow).
- **R6.2b (capabilities#56):** IMPLEMENTED — typed target-type compatibility
  declaration (`executionBoundary.compatibleTargetTypes`) with deterministic
  validation; see [Compatibility declaration](#compatibility-declaration-r62b).
- **R6.4a (capabilities#57):** IMPLEMENTED — immutable Effect v1 block
  (`effect`) with strict enums; see [Effect v1](#effect-v1-r64a).
- **R6.4d (capabilities#58):** IMPLEMENTED — namespaced, versioned Effect
  extensions with fail-closed admission; see
  [Effect extensions](#effect-extensions-r64d).
- **R6.4f (capabilities#62):** IMPLEMENTED — admission also fails closed on
  unclassifiable extension declarations, independently of validation.

One canonical `capability.yaml` identity spans developer build → registry
adoption → customer review → edge admission → execution → evidence. This
package is the single validator those consumers share.

## Design

- **Dependency-free:** stdlib + YAML only, so any repo (forgeops-control,
  forgeops-platform, the R5.2 CLI, the R5.9 qualification harness) can import
  it. If a non-Go consumer or OCI distribution later needs an independent
  module, this package extracts as-is.
- **Home:** `forgeops-capabilities` — the repo that already owns the capability
  domain (SDK, manifests, versioning). Control/platform import it; no cycles.
- **Document form:** YAML or JSON authored, normalized to JSON on parse.

## The document shape

```yaml
schemaVersion: capability.v1        # the explicit normative contract version
identity:                           # immutable package identity
  key: acme.service.restart         # stable capability key
  version: 1.0.0                    # semver of THIS contract
  artifactDigest: sha256:<hex>      # binds identity to the execution bytes
  implementationPlatform: linux/arm64
contract:
  description: ...
  inputSchema: {...}                # JSON Schema (typed input)
  outputSchema: {...}               # JSON Schema (typed output)
  idempotencyKey: receipt           # mutation intended-effect key (optional)
executionBoundary:                  # what the capability requests to touch
  risk: ask                         # allow | ask | deny
  requiredSecrets: [SERVICE_TOKEN]  # names only, never values
  egress: []                        # declared destinations (allowlist)
  target: acme-service              # v1 target class it may act on (legacy label)
  compatibleTargetTypes: [acme.service/v1]   # R6.2b typed schema contracts
runtime:
  interface: mcp
  runtimeContract: runtime.v1
```

## Migration mapping from the current manifest form

| Current `manifests/*.yaml` field | Canonical field |
|---|---|
| `key` | `identity.key` |
| `version` | `identity.version` |
| `implementation_sha256` | `identity.artifactDigest` |
| `implementation_platform` | `identity.implementationPlatform` |
| `description` | `contract.description` |
| `input_schema` / `output_schema` | `contract.inputSchema` / `outputSchema` |
| (SDK `Contract.IdempotencyKey`) | `contract.idempotencyKey` |
| `risk` | `executionBoundary.risk` |
| `required_secrets` | `executionBoundary.requiredSecrets` |
| `egress` | `executionBoundary.egress` |
| `target` | `executionBoundary.target` |
| (new in R6.2b — no legacy form) | `executionBoundary.compatibleTargetTypes` |
| (fabric Capability `interface`) | `runtime.interface` |

## A capability can have both forms, and they must not drift

A capability that has been canonicalized carries a legacy `manifests/*.yaml`
(the edge's install form: `capabilityctl install --manifest … --binary …`) *and*
a canonical `cmd/<name>/capability.yaml`. They are two descriptions of one
immutable revision, so they must not become two truths.

They are **not** equivalent to the platform, but the difference is not "legacy is
refused at the registry" — a manifest with no `schemaVersion` is accepted there
on a migration lane. What differs is what each form can PROVE:

| | registry registration | typed binding | adoption |
|---|---|---|---|
| legacy manifest (no `schemaVersion`) | accepted, migration lane | **not verifiable → fails closed** | needs a declared `artifact.digest` |
| canonical `capability.v1` | validated canonically | compatibility provable | reads `identity.artifactDigest` |

Only the canonical form can declare `executionBoundary.compatibleTargetTypes`, so
only it can be bound under a typed target: `DeclaredCompatibleTargetTypes` reports
`ok=false` for a legacy manifest and the binding fails closed rather than binding
against a revision whose compatibility cannot be checked. The legacy form also
pins the edge's `implementation_sha256` rather than the registry's
`artifact.digest`, so it cannot be adopted without that declaration either. A
capability the architecture binds TYPED therefore needs both forms.

`internal/capstore/canonical_drift_test.go` enforces that they agree. It joins the
two forms on `identity.key`, compares key/version/risk/target/required
secrets/egress/schemas/digest/platform, and fails when a change to one
representation changes the executable contract without changing the other. Adding
a canonical document for a key that already has a legacy manifest forces a
decision rather than silently skipping the comparison.

`target` and `compatibleTargetTypes` are different things and both are required:
`target` is the runtime **access-scope class** this package may reach,
`compatibleTargetTypes` is the **authority target type** a binding must match,
and the concrete target a binding names (`CapabilityBinding.Target`) is neither.

## Compatibility declaration (R6.2b)

`executionBoundary.compatibleTargetTypes` declares the versioned target-type
schema contracts this immutable capability revision may operate against —
NOT concrete customer targets and NOT invocation resources (those stay in typed
canonical input). Grammar mirrors the R6.2a typed Target model
(`forgeops-platform/internal/target`): a dotted lowercase type name with an
optional `/vN` qualifier that defaults to `v1` and is always spelled in the
canonical form (`kubernetes.cluster` ≡ `kubernetes.cluster/v1`).

- Declarations are bounded (≤ 16 contracts, ≤ 128 bytes each) and each contract
  must be spelled once — two entries that normalize to the same `name/vN` are
  refused.
- The declaration is part of the canonical document, so the manifest digest
  (the immutable revision identity in platform adoption and control
  caprevision) covers it: **changing compatibility requires a new capability
  revision**.
- A revision with no typed declaration (only the legacy free-form `target`
  class) is compatible with nothing typed — a typed binding to it fails closed.
- `NormalizeTargetType`, `Package.CompatibleTargetTypeContracts`, and
  `Package.DeclaresCompatibleTargetType` expose the canonical comparison set.

## Effect v1 (R6.4a)

`effect` is the minimum immutable Effect v1 contract (capabilities#57): four
DESCRIPTIVE operation semantics — never allow/ask/deny policy (that stays in
`executionBoundary.risk`).

```yaml
effect:
  contract: effect.v1          # versioned contract identity
  sideEffect: mutation         # none | mutation | external
  reversibility: irreversible  # reversible | irreversible | unknown
  idempotency: key_required    # safe | key_required | unsafe
  verification: required       # none | supported | required
```

- Strict closed enums: unknown or missing values are refused with stable field
  errors when the block is present.
- Additive and optional: documents without an `effect` block stay valid on the
  legacy lane.
- The block is part of the canonical document, so the manifest digest (the
  revision identity in platform adoption and control caprevision) covers the
  exact Effect semantics: **changing Effect requires a new capability
  revision/package identity**.

## Effect extensions (R6.4d)

`effect.extensions` declares bounded, namespaced, versioned domain extensions of
the Effect v1 semantics — the semantics core Effect v1 deliberately does not
model (settlement windows, consent classes, blast-radius conventions) — without
letting arbitrary authority-bearing metadata bypass the core contract.

```yaml
effect:
  contract: effect.v1
  sideEffect: mutation
  reversibility: irreversible
  idempotency: key_required
  verification: required
  extensions:
    - name: acme.settlement/v1       # namespace.name/vN — version is mandatory
      authority: authority_relevant  # informational | authority_relevant
      attributes:                    # bounded flat string payload
        window: t_plus_2
    - name: acme.telemetry/v2
      authority: informational
```

- **Namespaced and versioned.** The contract is `namespace.name/vN`: at least
  two dotted lowercase segments and an explicit `/vN` (N ≥ 1, no leading zeros).
  Unlike R6.2b target types, the version is never defaulted — `acme.settlement`
  is refused, and `acme.settlement/v2` is a *different* contract from
  `acme.settlement/v1`, so a consumer can never half-understand an extension.
  The `capability` and `effect` namespaces are reserved for the core contracts.
- **The authority class is declared, never inferred.** `authority` is required:
  `informational` (a consumer may ignore it) or `authority_relevant` (a consumer
  must understand it before trusting this package's effect facts). An extension
  with no class is refused rather than read as informational, so nothing
  authority-bearing enters through omission.
- **Unknown authority-relevant extensions fail closed.**
  `Package.AdmitEffectExtensions(understood)` is the rule every consumer of
  Effect facts (policy, review, admission) applies: a package declaring an
  authority-relevant extension the consumer does not understand is REFUSED —
  the extension may be exactly what qualifies the core semantics. Informational
  extensions never block, and a failed computation (malformed understood entry,
  nil package) returns `Admitted: false` with the error.
- **Unclassifiable declarations fail closed too (R6.4f).** Admission is a
  standalone guarantee: it does not assume `Validate` ever ran. A declaration
  with an unreadable name, or an `authority` outside the closed vocabulary, is
  neither informational nor authority-relevant — so exact classification alone
  would silently omit it from the check. Such a declaration is treated as
  authority-bearing and refused, reported in `decision.Malformed` (verbatim when
  it has no canonical form) and in `decision.Unrecognized`. This matters because
  consumers reach the helper from read/storage paths that deliberately do not
  re-validate the manifest; an extension that cannot be classified is strictly
  more dangerous than an unknown-but-valid one.
- **Extensions never replace core Effect v1.** A lone `extensions` list makes
  the effect block present, so the four core semantics stay typed and mandatory.
  Payloads are flat, bounded `string` attributes (≤ 8 extensions, ≤ 16
  attributes each, ≤ 64-byte keys, ≤ 256-byte values) — not free-form JSON.
- **Extensions are part of the revision identity.** They live inside the
  canonical document, so the manifest digest covers them: changing an
  extension's contract, authority class or attributes is a **new package
  revision**, never a re-pointed one.
- **Still not policy.** `authority_relevant` means policy must *understand* the
  extension, not that the extension decides anything: allow/ask/deny stays in
  `executionBoundary.risk`.

## Validation guarantees

- Deterministic, section-ordered structured errors (`Error{Field, Message}`).
- An unknown `schemaVersion` is refused before any field semantics.
- Tampered/invalid identity (`artifactDigest`, `key`, semver) fails validation
  — the same validator runs at admission, so invalid/tampered identity inputs
  fail before runtime execution.
- Conformance fixtures (positive + negative) live in `validate_test.go` and are
  runnable by any consumer via `go test ./capability/`.

## API

```go
p, errs, err := capability.ValidateDocument(data) // parse + validate
if len(errs) > 0 { /* refuse */ }
```

`capability.Validate(p)`, `capability.Conforms(p)`, `capability.SortErrors(errs)`.

R6.4d effect extensions:

```go
contract, err := capability.NormalizeEffectExtension("acme.settlement/v1")
contracts, err := p.EffectExtensionContracts()          // sorted canonical set
authority, err := p.AuthorityRelevantEffectExtensions() // must-understand subset
attrs, declared, err := p.EffectExtensionAttributes("acme.settlement/v1")

decision, err := p.AdmitEffectExtensions(understood) // fail-closed admission
if err != nil || !decision.Admitted {
	// refuse: decision.Unrecognized is the complete blocking list (unknown
	// authority-relevant contracts + malformed declarations),
	// decision.Malformed is the unclassifiable subset, and decision.Reason
	// explains which cause applied.
}
```

R6.2b compatibility:

```go
contract, err := capability.NormalizeTargetType("kubernetes.cluster") // "kubernetes.cluster/v1"
contracts, err := p.CompatibleTargetTypeContracts()                   // sorted canonical set
ok, err := p.DeclaresCompatibleTargetType("kubernetes.cluster/v1")    // binding refusal predicate
```
