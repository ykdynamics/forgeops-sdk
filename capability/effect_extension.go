package capability

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Namespaced Effect extension contract and fail-closed rules, on top of the
// Effect v1 block.
//
// Domains need effect semantics core Effect v1 deliberately does not model
// (settlement windows, clinical consent, blast radius conventions). The rule
// that keeps that from becoming a bypass:
//
//   - an extension is NAMESPACED and explicitly VERSIONED (acme.settlement/v1)
//     — never a bare key, never an implied version;
//   - the capability declares, per extension, whether it is `informational` or
//     `authority_relevant`; the class is REQUIRED, so an authority-bearing
//     extension can never arrive as an unlabeled (and therefore ignorable) one;
//   - a consumer that does not understand a declared authority_relevant
//     extension FAILS CLOSED (AdmitEffectExtensions) — it never proceeds on the
//     core fields alone, because the extension may be exactly what narrows them;
//   - extensions never replace or relax core Effect v1: the four core semantics
//     stay typed and mandatory whenever the effect block is present, and
//     extension payloads are bounded string attributes, not arbitrary
//     authority-bearing metadata;
//   - the declaration lives inside the canonical document, so the manifest
//     digest (sha256 of CanonicalJSON — the immutable revision identity when
//     a package is adopted and recorded) covers it: changing an
//     extension is a new capability revision, never a re-pointed one.
//
// Effect stays descriptive throughout. An extension — informational or
// authority-relevant — never encodes allow/ask/deny; that authority class stays
// in ExecutionBoundary.Risk. "Authority-relevant" means policy MUST understand
// the extension before it can trust the effect facts, not that the extension
// carries a decision.

const (
	// MaxEffectExtensions bounds how many extensions one revision declares.
	MaxEffectExtensions = 8
	// MaxEffectExtensionLength bounds one extension contract string including
	// its /vN qualifier.
	MaxEffectExtensionLength = 128
	// MaxEffectExtensionAttributes bounds one extension's attribute map.
	MaxEffectExtensionAttributes = 16
	// MaxEffectExtensionAttributeKeyLength bounds one attribute key.
	MaxEffectExtensionAttributeKeyLength = 64
	// MaxEffectExtensionAttributeValueLength bounds one attribute value.
	MaxEffectExtensionAttributeValueLength = 256
)

// Extension authority classes (closed enum, always explicit).
const (
	// ExtensionInformational is context a consumer may safely ignore: not
	// understanding it never changes what the core Effect v1 facts mean.
	ExtensionInformational = "informational"
	// ExtensionAuthorityRelevant is an extension whose semantics a consumer
	// MUST understand before trusting this package's effect facts. An
	// unrecognized one fails closed.
	ExtensionAuthorityRelevant = "authority_relevant"
)

// AllowedExtensionAuthorities is the closed authority-class vocabulary. There
// is no default: an extension with no declared class is refused, so nothing
// authority-bearing can enter through omission.
var AllowedExtensionAuthorities = []string{ExtensionInformational, ExtensionAuthorityRelevant}

// ReservedEffectExtensionNamespaces are first segments an extension may never
// claim — they name the core contracts themselves, and an extension must not be
// able to spell itself as core Effect or core package metadata.
var ReservedEffectExtensionNamespaces = []string{"capability", "effect"}

var (
	// effectExtensionNameRe requires at least two dotted lowercase segments:
	// a namespace and a name (acme.settlement), never a bare word.
	effectExtensionNameRe = regexp.MustCompile(`^[a-z][a-z0-9]*(?:\.[a-z][a-z0-9]*)+$`)
	// effectExtensionVersionRe is vN with N >= 1 and no leading zeros.
	effectExtensionVersionRe = regexp.MustCompile(`^v([1-9][0-9]*)$`)
	// effectExtensionAttributeKeyRe is a bounded lowercase attribute key.
	effectExtensionAttributeKeyRe = regexp.MustCompile(`^[a-z][a-z0-9]*(?:[._][a-z0-9]+)*$`)
)

// EffectExtension is one bounded, namespaced, versioned domain extension of the
// Effect v1 block. It carries domain semantics core Effect v1 does not model —
// never policy, and never a replacement for a core field.
type EffectExtension struct {
	// Name is the namespaced, explicitly versioned contract identity
	// (namespace.name/vN, e.g. acme.settlement/v1). The version is mandatory:
	// an unversioned extension cannot be understood or refused deterministically.
	Name string `json:"name" yaml:"name"`
	// Authority declares whether a consumer may ignore this extension
	// (informational) or must understand it before trusting the package's
	// effect facts (authority_relevant). Required — never defaulted.
	Authority string `json:"authority" yaml:"authority"`
	// Attributes is the extension's bounded payload: flat string key/value
	// pairs only. Deliberately not free-form JSON — an extension carries
	// bounded domain semantics, not arbitrary authority-bearing metadata.
	Attributes map[string]string `json:"attributes,omitempty" yaml:"attributes,omitempty"`
}

// Declared reports whether an effect block is present at all. Any field —
// including a lone extensions list — makes the block present, which is what
// keeps the four core semantics mandatory: an extension can never ride into a
// document that declares no core Effect v1 contract.
func (e Effect) Declared() bool {
	return e.Contract != "" || e.SideEffect != "" || e.Reversibility != "" ||
		e.Idempotency != "" || e.Verification != "" || len(e.Extensions) > 0
}

// NormalizeEffectExtension validates a declared or candidate extension contract
// and returns its canonical namespace.name/vN form. Unlike the target-type
// grammar, the version is NOT defaulted: an extension must spell
// its version, so a consumer's understood set and a package's declaration can
// never silently agree across two different revisions of one extension.
func NormalizeEffectExtension(raw string) (string, error) {
	if raw == "" {
		return "", errors.New("effect extension is required (namespaced, versioned contract, e.g. acme.settlement/v1)")
	}
	if len(raw) > MaxEffectExtensionLength {
		return "", fmt.Errorf("effect extension is %d bytes, limit is %d", len(raw), MaxEffectExtensionLength)
	}
	i := strings.LastIndexByte(raw, '/')
	if i < 0 {
		return "", fmt.Errorf("effect extension %q must declare an explicit version (namespace.name/vN)", raw)
	}
	name, versionRaw := raw[:i], raw[i+1:]
	m := effectExtensionVersionRe.FindStringSubmatch(versionRaw)
	if m == nil {
		return "", fmt.Errorf("effect extension version %q is not vN with N >= 1 and no leading zeros", versionRaw)
	}
	version, err := strconv.Atoi(m[1])
	if err != nil {
		return "", fmt.Errorf("effect extension version %q is out of range", versionRaw)
	}
	if !effectExtensionNameRe.MatchString(name) {
		return "", fmt.Errorf("effect extension name %q is not a namespaced dotted lowercase name (e.g. acme.settlement)", name)
	}
	if ns := name[:strings.IndexByte(name, '.')]; contains(ReservedEffectExtensionNamespaces, ns) {
		return "", fmt.Errorf("effect extension namespace %q is reserved for the core contracts (%v)", ns, ReservedEffectExtensionNamespaces)
	}
	return fmt.Sprintf("%s/v%d", name, version), nil
}

// EffectExtensionContracts returns the deterministic, sorted, de-duplicated set
// of canonical extension contracts this revision declares.
func (p *Package) EffectExtensionContracts() ([]string, error) {
	return p.effectExtensionsWithAuthority("")
}

// AuthorityRelevantEffectExtensions returns the sorted canonical contracts a
// consumer MUST understand before trusting this package's effect facts.
func (p *Package) AuthorityRelevantEffectExtensions() ([]string, error) {
	return p.effectExtensionsWithAuthority(ExtensionAuthorityRelevant)
}

// InformationalEffectExtensions returns the sorted canonical contracts a
// consumer may safely ignore.
func (p *Package) InformationalEffectExtensions() ([]string, error) {
	return p.effectExtensionsWithAuthority(ExtensionInformational)
}

// effectExtensionsWithAuthority projects the declared extensions of one
// authority class ("" means every class) into the canonical comparison set.
// Duplicate spellings are the validator's concern (refused with a field error);
// this projection de-duplicates so programmatic construction cannot produce two
// spellings of one contract.
func (p *Package) effectExtensionsWithAuthority(authority string) ([]string, error) {
	if p == nil {
		return nil, nil
	}
	seen := make(map[string]bool, len(p.Effect.Extensions))
	out := make([]string, 0, len(p.Effect.Extensions))
	for _, ext := range p.Effect.Extensions {
		normalized, err := NormalizeEffectExtension(strings.TrimSpace(ext.Name))
		if err != nil {
			return nil, err
		}
		if authority != "" && ext.Authority != authority {
			continue
		}
		if seen[normalized] {
			continue
		}
		seen[normalized] = true
		out = append(out, normalized)
	}
	sort.Strings(out)
	return out, nil
}

// EffectExtensionAttributes returns a copy of the bounded payload the package
// declares for one extension contract, and whether that contract is declared at
// all. Only a consumer that understands the contract should read it.
func (p *Package) EffectExtensionAttributes(contract string) (map[string]string, bool, error) {
	if p == nil {
		return nil, false, nil
	}
	wanted, err := NormalizeEffectExtension(contract)
	if err != nil {
		return nil, false, err
	}
	for _, ext := range p.Effect.Extensions {
		normalized, err := NormalizeEffectExtension(strings.TrimSpace(ext.Name))
		if err != nil {
			return nil, false, err
		}
		if normalized != wanted {
			continue
		}
		attrs := make(map[string]string, len(ext.Attributes))
		for k, v := range ext.Attributes {
			attrs[k] = v
		}
		return attrs, true, nil
	}
	return nil, false, nil
}

// EffectExtensionAdmission is the fail-closed decision a consumer makes before
// treating a package's Effect v1 facts as complete.
type EffectExtensionAdmission struct {
	// Admitted is true only when every declared extension is well formed and
	// every authority-relevant one is understood. It is false on any error — an
	// admission decision that could not be computed is a refusal, never a pass.
	Admitted bool
	// Unrecognized lists everything blocking admission, sorted: the
	// authority-relevant contracts the consumer does not understand PLUS every
	// malformed declaration. It is the single complete list a consumer can gate
	// on without having to know the difference.
	Unrecognized []string
	// Malformed lists the declarations that could not be normalized or
	// classified at all — an unreadable name, or an authority class outside the
	// closed vocabulary. Reported verbatim when there is no canonical form.
	// These also appear in Unrecognized; this field is the typed detail for an
	// operator surface that wants to say "this package is malformed" rather
	// than "this contract is unsupported".
	Malformed []string
	// Informational lists the sorted contracts the consumer may ignore, whether
	// or not it understands them.
	Informational []string
	// Reason is the deterministic, human-safe explanation of the decision.
	Reason string
}

// AdmitEffectExtensions is the fail-closed rule every consumer of Effect facts — policy, review, admission — applies before
// trusting them. A package is REFUSED when it declares either:
//
//   - an authority_relevant extension the consumer does not understand — the
//     extension may be exactly what qualifies the core semantics; or
//   - an extension that cannot be classified at all: an unreadable name, or an
//     authority class outside the closed vocabulary.
//
// The second rule is the one a caller cannot safely be left to add itself. For
// a CONFORMING document it is unreachable — Validate refuses both shapes — but
// consumers reach this helper from read/storage paths that deliberately do not
// re-run manifest validation, and there an unreadable authority class is
// neither informational nor authority-relevant, so exact classification would
// silently omit it from the check. An extension that cannot be classified is
// strictly more dangerous than an unknown-but-valid one (ADR-006), so it fails
// closed here, at the shared boundary, rather than in each consumer.
//
// Informational extensions never block, understood or not.
//
// understood is the consumer's own declared set of extension contracts, spelled
// canonically (namespace.name/vN). A malformed declaration or understood entry
// returns Admitted false together with an error — the decision is still fully
// populated, so a consumer that gates only on Admitted (or only on
// Unrecognized) is equally safe.
func (p *Package) AdmitEffectExtensions(understood []string) (EffectExtensionAdmission, error) {
	if p == nil {
		return EffectExtensionAdmission{Reason: "no capability package to admit"}, errors.New("package is required")
	}
	set := make(map[string]bool, len(understood))
	for _, raw := range understood {
		normalized, err := NormalizeEffectExtension(strings.TrimSpace(raw))
		if err != nil {
			return EffectExtensionAdmission{Reason: "understood effect extension set is not spelled canonically"}, err
		}
		set[normalized] = true
	}

	var authority, informational, malformed, unknown []string
	for _, ext := range p.Effect.Extensions {
		raw := strings.TrimSpace(ext.Name)
		contract, err := NormalizeEffectExtension(raw)
		if err != nil {
			// No canonical form exists, so report the declaration verbatim.
			malformed = append(malformed, unreadableName(raw))
			continue
		}
		switch ext.Authority {
		case ExtensionInformational:
			informational = append(informational, contract)
		case ExtensionAuthorityRelevant:
			authority = append(authority, contract)
			if !set[contract] {
				unknown = append(unknown, contract)
			}
		default:
			// An extension whose class is unreadable must never be dismissed as
			// informational: treat it as authority-bearing and refuse.
			malformed = append(malformed, contract)
		}
	}

	malformed = sortedUniqueExtensions(malformed)
	unknown = sortedUniqueExtensions(unknown)
	decision := EffectExtensionAdmission{
		Unrecognized:  sortedUniqueExtensions(append(append([]string(nil), unknown...), malformed...)),
		Malformed:     malformed,
		Informational: sortedUniqueExtensions(informational),
	}
	decision.Admitted = len(decision.Unrecognized) == 0
	switch {
	case len(malformed) > 0 && len(unknown) > 0:
		decision.Reason = fmt.Sprintf("unclassifiable effect extension declarations: %s; unrecognized authority-relevant effect extensions: %s",
			strings.Join(malformed, ", "), strings.Join(unknown, ", "))
	case len(malformed) > 0:
		decision.Reason = fmt.Sprintf("unclassifiable effect extension declarations: %s", strings.Join(malformed, ", "))
	case len(unknown) > 0:
		decision.Reason = fmt.Sprintf("unrecognized authority-relevant effect extensions: %s", strings.Join(unknown, ", "))
	case len(authority) == 0:
		decision.Reason = "no authority-relevant effect extensions declared"
	default:
		decision.Reason = fmt.Sprintf("all authority-relevant effect extensions understood: %s",
			strings.Join(sortedUniqueExtensions(authority), ", "))
	}
	if len(malformed) > 0 {
		return decision, fmt.Errorf("effect extension declaration cannot be classified: %s", strings.Join(malformed, ", "))
	}
	return decision, nil
}

// unreadableName renders a declaration that has no canonical form, keeping the
// refusal deterministic even for an empty name.
func unreadableName(raw string) string {
	if raw == "" {
		return "(unnamed extension)"
	}
	return raw
}

// sortedUniqueExtensions returns the deterministic, de-duplicated set, or nil
// when empty.
func sortedUniqueExtensions(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(values))
	out := make([]string, 0, len(values))
	for _, v := range values {
		if seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
