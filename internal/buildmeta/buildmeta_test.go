package buildmeta

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestProvenance(t *testing.T) {
	out, err := Provenance(
		"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		"https://forgeops.dev/forgeops-cap",
	)
	if err != nil {
		t.Fatal(err)
	}
	var st map[string]any
	if err := json.Unmarshal(out, &st); err != nil {
		t.Fatalf("provenance is not valid JSON: %v", err)
	}
	if !strings.Contains(string(out), "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb") {
		t.Fatal("provenance lacks the artifact subject digest")
	}
	if !strings.Contains(string(out), "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") {
		t.Fatal("provenance lacks the config source (manifest) digest")
	}
}

// TestGoModulesSBOM requires a go toolchain + a module; it uses this repo.
func TestGoModulesSBOM(t *testing.T) {
	// This test runs inside the forgeops-sdk module, so `go list -m`
	// has a real module graph.
	out, err := GoModulesSBOM("..")
	if err != nil {
		t.Fatalf("GoModulesSBOM: %v", err)
	}
	var doc SBOMDocument
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("sbom is not valid JSON: %v", err)
	}
	if doc.BOMFormat != "CycloneDX" || doc.SpecVersion != "1.5" {
		t.Fatalf("sbom header: %+v", doc)
	}
	if len(doc.Components) == 0 {
		t.Fatal("sbom has no components")
	}
}
