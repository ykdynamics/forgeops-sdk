package capability

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Capability target-type compatibility.
//
// A capability revision may declare the versioned target-type schema contracts
// it is compatible with. The grammar and normalization rules below are those of
// ForgeOps' typed target model: a dotted lowercase type name with an optional
// /vN qualifier that defaults to v1 and is always materialized in the canonical
// contract form (name/vN). ForgeOps' own target model keeps the same rules, held
// in lockstep by mirrored conformance vectors.
//
// The declaration is part of the canonical capability.v1 document, so the
// manifest digest (sha256 of capability.CanonicalJSON) — the immutable revision
// identity when a registry adopts a package and a control plane records it —
// covers it.
// Changing compatibility therefore requires a new capability revision; it can
// never be re-pointed under the same (key, version, digest).

const (
	// MaxCompatibleTargetTypes bounds the declared compatible type set.
	MaxCompatibleTargetTypes = 16
	// MaxTargetTypeLength bounds one declared type string including its /vN
	// qualifier (the same bound as ForgeOps' target model).
	MaxTargetTypeLength = 128
)

var (
	// targetTypeNameRe is the target model's type-name grammar: dotted
	// lowercase words, each starting with a letter.
	targetTypeNameRe = regexp.MustCompile(`^[a-z][a-z0-9]*(?:\.[a-z][a-z0-9]*)*$`)
	// targetTypeVersionRe is the target model's type-version grammar:
	// vN with N >= 1 and no leading zeros.
	targetTypeVersionRe = regexp.MustCompile(`^v([1-9][0-9]*)$`)
)

// NormalizeTargetType resolves a declared or candidate target-type contract to
// its canonical name/vN form. A missing /vN resolves to v1 by rule, exactly as
// the typed Target model canonicalizes, so "kubernetes.cluster" and
// "kubernetes.cluster/v1" are the same contract.
func NormalizeTargetType(raw string) (string, error) {
	if raw == "" {
		return "", errors.New("target type is required (dotted lowercase name with optional /vN)")
	}
	if len(raw) > MaxTargetTypeLength {
		return "", fmt.Errorf("target type is %d bytes, limit is %d", len(raw), MaxTargetTypeLength)
	}
	name, version := raw, 1
	if i := strings.LastIndexByte(raw, '/'); i >= 0 {
		name = raw[:i]
		versionRaw := raw[i+1:]
		m := targetTypeVersionRe.FindStringSubmatch(versionRaw)
		if m == nil {
			return "", fmt.Errorf("target type version %q is not vN with N >= 1 and no leading zeros", versionRaw)
		}
		v, err := strconv.Atoi(m[1])
		if err != nil {
			return "", fmt.Errorf("target type version %q is out of range", versionRaw)
		}
		version = v
	}
	if name == "" {
		return "", errors.New("target type name is required")
	}
	if !targetTypeNameRe.MatchString(name) {
		return "", fmt.Errorf("target type name %q is not a dotted lowercase name starting with a letter (e.g. kubernetes.cluster)", name)
	}
	return fmt.Sprintf("%s/v%d", name, version), nil
}

// CompatibleTargetTypeContracts returns the deterministic, sorted,
// de-duplicated set of canonical target-type schema contracts (name/vN) this
// package revision declares in executionBoundary.compatibleTargetTypes. It is
// the projection binding checks compare against — never the raw declaration,
// which may spell a type without its version. An unparseable declaration
// returns an error (a conforming document cannot reach that state).
func (p *Package) CompatibleTargetTypeContracts() ([]string, error) {
	if p == nil {
		return nil, nil
	}
	return normalizeContracts(p.ExecutionBoundary.CompatibleTargetTypes)
}

// DeclaresCompatibleTargetType reports whether this package revision declares
// the candidate target type compatible. Both sides are normalized to canonical
// name/vN before comparison. A revision with NO compatibleTargetTypes
// declaration is compatible with nothing typed (it only carries the legacy
// free-form executionBoundary.target class label, which is not a typed
// contract), so a typed binding to it fails closed. A malformed candidate is
// an error, never a silent refusal reason.
func (p *Package) DeclaresCompatibleTargetType(candidate string) (bool, error) {
	contracts, err := p.CompatibleTargetTypeContracts()
	if err != nil {
		return false, err
	}
	if len(contracts) == 0 {
		return false, nil
	}
	normalized, err := NormalizeTargetType(candidate)
	if err != nil {
		return false, err
	}
	i := sort.SearchStrings(contracts, normalized)
	return i < len(contracts) && contracts[i] == normalized, nil
}

// normalizeContracts normalizes a declared list into the canonical sorted,
// de-duplicated contract set. Declaration-list duplicates are the validator's
// concern (they are refused with a field error); this projection deduplicates
// silently so programmatic construction cannot produce two spellings of one
// contract in the comparison set.
func normalizeContracts(declared []string) ([]string, error) {
	seen := make(map[string]bool, len(declared))
	out := make([]string, 0, len(declared))
	for _, raw := range declared {
		normalized, err := NormalizeTargetType(raw)
		if err != nil {
			return nil, err
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
