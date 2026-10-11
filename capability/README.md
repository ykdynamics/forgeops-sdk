# Package capability — the Capability Package v1 contract

One canonical `capability.yaml` describes a capability from the developer's
build, through registry admission, the customer's review and the edge's
admission, to execution and evidence. This package is the validator all of
them share: what it accepts and refuses is the contract.

- **Small dependency surface:** the standard library and YAML only, so any Go
  tool can import it.
- **Document form:** authored as YAML or JSON, normalized to JSON on parse.

## The document shape

```yaml
schemaVersion: capability.v1        # the explicit contract version
identity:                           # immutable package identity
  key: acme.service.restart         # stable capability key
  version: 1.0.0                    # semver of THIS contract
  artifactDigest: sha256:<hex>      # binds identity to the execution bytes
  implementationPlatform: linux/arm64
contract:
  description: ...
  inputSchema: {...}                # JSON Schema (typed input)
  outputSchema: {...}               # JSON Schema (typed output)
  requesterOutputSchema: {...}      # what it proposes to disclose to the requester (optional)
  idempotencyKey: receipt           # mutation intended-effect key (optional)
executionBoundary:                  # what the capability requests to touch
  risk: ask                         # allow | ask | deny
  requiredSecrets: [SERVICE_TOKEN]  # names only, never values
  egress: []                        # declared destinations (allowlist)
  target: acme-service              # the access-scope class it may reach
  compatibleTargetTypes: [acme.service/v1]   # typed target contracts
runtime:
  interface: mcp
  runtimeContract: runtime.v1
```

`requesterOutputSchema` is what the capability **proposes** to disclose to
whoever requested the operation: an object schema naming a subset of
`outputSchema`'s properties (it can only narrow the output, never widen it).
Absent, nothing is proposed: a requester receives the status and no result.
Declared, the result still reaches a requester only if the customer approves
this disclosure for this exact package when binding it; what is then returned
is `ProjectRequesterOutput`: the result must first satisfy `outputSchema`, then
only the named properties are kept and validated against the declaration.
Diagnostics, logs and any other output stay with the customer. Projection is
one level deep, so a declared property must be a scalar (`string`, `number`,
`integer`, `boolean`, `null`) or an array of scalars; nested objects and arrays
of them are refused, at validation and again at projection.

The declaration is part of the canonical document, so it is covered by the
manifest digest (the revision identity) and by the publisher's signature:
changing what is proposed for disclosure is a new revision, and an existing
signature does not cover it.

**Compatibility rule.** `requesterOutputSchema` only ever *restricts* what
leaves a customer's edge. A consumer that does not implement it — an older
SDK, registry or platform — must treat every package as proposing **no**
requester-facing output and disclose no result to requesters; it must never
fall back to passing the full result on. A consumer that implements it applies
`ProjectRequesterOutput` (or the same rules) together with the customer's
binding decision.

`target` and `compatibleTargetTypes` are different things: `target` is the
runtime **access-scope class** this package may reach, `compatibleTargetTypes`
is the **target type** a binding must match, and the concrete target a binding
names is neither.

Every field is part of the immutable revision: the manifest digest covers the
whole canonical document, so changing any of it — compatibility, effect,
extensions — means a **new capability revision**, never a re-pointed one.

## Compatibility declaration

`executionBoundary.compatibleTargetTypes` declares the versioned target-type
contracts this capability revision may operate against — NOT concrete customer
targets and NOT invocation resources (those stay in typed input). A contract is
a dotted lowercase type name with an optional `/vN` qualifier that defaults to
`v1` and is always spelled in canonical form (`kubernetes.cluster` ≡
`kubernetes.cluster/v1`).

- Declarations are bounded (≤ 16 contracts, ≤ 128 bytes each) and each contract
  must be spelled once: two entries that normalize to the same `name/vN` are
  refused.
- A revision with no typed declaration is compatible with nothing typed: a
  typed binding to it fails closed.
- `NormalizeTargetType`, `Package.CompatibleTargetTypeContracts` and
  `Package.DeclaresCompatibleTargetType` expose the canonical comparison set.

## Effect v1

`effect` states four DESCRIPTIVE operation semantics — never allow/ask/deny
policy, which stays in `executionBoundary.risk`.

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
- Optional: a document without an `effect` block stays valid.

## Effect extensions

`effect.extensions` declares bounded, namespaced, versioned domain extensions of
Effect v1 — semantics the core contract deliberately does not model
(settlement windows, consent classes, blast-radius conventions) — without
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
  Unlike target types, the version is never defaulted — `acme.settlement` is
  refused, and `acme.settlement/v2` is a *different* contract from
  `acme.settlement/v1`, so a consumer can never half-understand an extension.
  The `capability` and `effect` namespaces are reserved.
- **The authority class is declared, never inferred.** `authority` is required:
  `informational` (a consumer may ignore it) or `authority_relevant` (a consumer
  must understand it before trusting this package's effect facts). An extension
  with no class is refused rather than read as informational.
- **Unknown authority-relevant extensions fail closed.**
  `Package.AdmitEffectExtensions(understood)` is the rule every consumer of
  Effect facts applies: a package declaring an authority-relevant extension the
  consumer does not understand is REFUSED. Informational extensions never
  block, and a failed computation (malformed understood entry, nil package)
  returns `Admitted: false` with the error.
- **Unclassifiable declarations fail closed too.** Admission does not assume
  `Validate` ever ran. A declaration with an unreadable name, or an `authority`
  outside the closed vocabulary, is treated as authority-bearing and refused,
  reported in `decision.Malformed` (verbatim when it has no canonical form) and
  in `decision.Unrecognized`.
- **Extensions never replace core Effect v1.** A lone `extensions` list makes
  the effect block present, so the four core semantics stay mandatory. Payloads
  are flat, bounded strings (≤ 8 extensions, ≤ 16 attributes each, ≤ 64-byte
  keys, ≤ 256-byte values), not free-form JSON.
- **Still not policy.** `authority_relevant` means policy must *understand* the
  extension, not that the extension decides anything.

## Validation guarantees

- Deterministic, section-ordered structured errors (`Error{Field, Message}`).
- An unknown `schemaVersion` is refused before any field semantics.
- Tampered or invalid identity (`artifactDigest`, `key`, semver) fails
  validation. The same validator runs at admission, so such inputs fail before
  anything executes.
- Positive and negative conformance fixtures live in `validate_test.go`:
  `go test ./capability/`.

## API

```go
p, errs, err := capability.ValidateDocument(data) // parse + validate
if len(errs) > 0 { /* refuse */ }
```

`capability.Validate(p)`, `capability.Conforms(p)`, `capability.SortErrors(errs)`.

Effect extensions:

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

Compatibility:

```go
contract, err := capability.NormalizeTargetType("kubernetes.cluster") // "kubernetes.cluster/v1"
contracts, err := p.CompatibleTargetTypeContracts()                   // sorted canonical set
ok, err := p.DeclaresCompatibleTargetType("kubernetes.cluster/v1")    // binding refusal predicate
```
