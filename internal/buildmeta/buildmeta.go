// Package buildmeta generates minimal, honest supply-chain metadata for a
// packaged capability (WP-R5.2c, capabilities#43): a CycloneDX SBOM of the Go
// modules the implementation is built from + a build provenance statement.
// The payloads are the shape the platform registry's BuildEvidence (WP-22.4)
// accepts (kind sbom|provenance; format cyclonedx|slsa-provenance).
package buildmeta

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"time"
)

// SBOMDocument is the CycloneDX 1.5 shape emitted.
type SBOMDocument struct {
	BOMFormat   string      `json:"bomFormat"`
	SpecVersion string      `json:"specVersion"`
	Version     int         `json:"version"`
	Components  []Component `json:"components"`
	Metadata    struct {
		Timestamp string     `json:"timestamp"`
		Component *Component `json:"component,omitempty"`
	} `json:"metadata"`
}

// Component is one CycloneDX component (a Go module the build imports).
type Component struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

// GoModulesSBOM returns a CycloneDX 1.5 JSON SBOM listing the Go modules the
// project at dir builds from (`go list -m -json all`).
func GoModulesSBOM(dir string) ([]byte, error) {
	cmd := exec.Command("go", "list", "-m", "-json", "all")
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("go list -m -json all: %w", err)
	}
	// go list -m -json all emits a stream of JSON objects.
	dec := json.NewDecoder(bytes.NewReader(out))
	var doc SBOMDocument
	doc.BOMFormat = "CycloneDX"
	doc.SpecVersion = "1.5"
	doc.Version = 1
	doc.Metadata.Timestamp = time.Now().UTC().Format(time.RFC3339)
	for dec.More() {
		var m struct {
			Path    string `json:"Path"`
			Version string `json:"Version"`
			Main    bool   `json:"Main"`
		}
		if err := dec.Decode(&m); err != nil {
			return nil, fmt.Errorf("decode go list output: %w", err)
		}
		if m.Main || m.Path == "" {
			continue // the main module is the capability itself, not a dependency
		}
		doc.Components = append(doc.Components, Component{Type: "library", Name: m.Path, Version: m.Version})
	}
	if len(doc.Components) == 0 {
		return nil, fmt.Errorf("no Go module dependencies found for the SBOM")
	}
	return json.MarshalIndent(doc, "", "  ")
}

// ProvenanceStatement is a minimal build provenance (SLSA-style) binding the
// immutable package identity to the build.
type ProvenanceStatement struct {
	Type          string `json:"_type"`
	PredicateType string `json:"predicateType"`
	Subject       []struct {
		Name   string            `json:"name"`
		Digest map[string]string `json:"digest"`
	} `json:"subject"`
	Predicate struct {
		Builder struct {
			ID string `json:"id"`
		} `json:"builder"`
		BuildType  string `json:"buildType"`
		Invocation struct {
			ConfigSource struct {
				Digest map[string]string `json:"digest"`
			} `json:"configSource"`
		} `json:"invocation"`
	} `json:"predicate"`
}

// Provenance returns a provenance statement asserting that the given immutable
// package (manifest digest) was built by the named builder into the given
// artifact digest.
func Provenance(manifestDigest, artifactDigest, builder string) ([]byte, error) {
	var st ProvenanceStatement
	st.Type = "https://in-toto.io/Statement/v0.1"
	st.PredicateType = "https://slsa.dev/provenance/v0.2"
	st.Subject = append(st.Subject, struct {
		Name   string            `json:"name"`
		Digest map[string]string `json:"digest"`
	}{Name: "capability-implementation", Digest: map[string]string{"sha256": stripPrefix(artifactDigest)}})
	st.Predicate.Builder.ID = builder
	st.Predicate.BuildType = "https://forgeops.dev/forgeops-cap/build/v1"
	st.Predicate.Invocation.ConfigSource.Digest = map[string]string{"sha256": stripPrefix(manifestDigest)}
	return json.MarshalIndent(st, "", "  ")
}

func stripPrefix(d string) string {
	if len(d) > len("sha256:") && d[:len("sha256:")] == "sha256:" {
		return d[len("sha256:"):]
	}
	return d
}
