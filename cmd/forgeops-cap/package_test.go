package main

import (
	"strings"
	"testing"

	"github.com/ykdynamics/forgeops-sdk/buildrecipe"
)

func TestSetIdentity(t *testing.T) {
	raw := []byte(`{
  "schemaVersion": "capability.v1",
  "identity": {"key": "acme.demo.status", "version": "0.1.0", "artifactDigest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"},
  "contract": {
    "inputSchema": {"type":"object","properties":{"service":{"type":"string"}}},
    "outputSchema": {"type":"object","properties":{"healthy":{"type":"boolean"}}}
  },
  "executionBoundary": {"risk": "allow"},
  "runtime": {"interface": "mcp", "runtimeContract": "runtime.v1"}
}`)
	out, err := setIdentity(raw, "sha256:46209741ec1dabc50af4fbd1d0f23b13d531ef2157982b4ec9d015b7891500ba", "linux/arm64")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "46209741ec1dabc50af4fbd1d0f23b13d531ef2157982b4ec9d015b7891500ba") {
		t.Fatalf("pinned digest missing: %s", out)
	}
	if strings.Contains(string(out), "000000000000") {
		t.Fatal("placeholder digest still present")
	}
	// The platform is written beside the digest: a digest with no platform
	// beside it cannot say which bytes it describes.
	if !strings.Contains(string(out), `"implementationPlatform":"linux/arm64"`) {
		t.Fatalf("implementationPlatform was not recorded: %s", out)
	}
}

func TestResolvePlatform(t *testing.T) {
	tests := []struct {
		name        string
		declared    string
		flag        string
		allowHost   bool
		want        string
		wantHost    bool
		wantRefused bool
	}{
		{name: "declared platform is authoritative", declared: "linux/arm64", want: "linux/arm64"},
		{name: "flag may repeat the declaration", declared: "linux/arm64", flag: "linux/arm64", want: "linux/arm64"},
		{name: "flag may not contradict the declaration", declared: "linux/arm64", flag: "linux/amd64", wantRefused: true},
		{name: "flag supplies a missing declaration", flag: "linux/amd64", want: "linux/amd64"},
		{name: "neither is refused, not guessed", wantRefused: true},
		{name: "host bytes require an explicit opt-in", allowHost: true, wantHost: true},
		{name: "opt-in does not override a declaration", declared: "linux/arm64", allowHost: true, want: "linux/arm64"},
		{name: "malformed declaration is refused", declared: "linux/ARM64", wantRefused: true},
		{name: "malformed flag is refused", flag: "linux", wantRefused: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, hostFallback, err := resolvePlatform(tc.declared, tc.flag, tc.allowHost)
			if tc.wantRefused {
				if err == nil {
					t.Fatalf("resolvePlatform(%q, %q) was accepted (%s), want refusal", tc.declared, tc.flag, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolvePlatform(%q, %q): %v", tc.declared, tc.flag, err)
			}
			if hostFallback != tc.wantHost {
				t.Fatalf("hostFallback = %v, want %v", hostFallback, tc.wantHost)
			}
			if tc.wantHost {
				if got != buildrecipe.HostPlatform() {
					t.Fatalf("host fallback = %s, want %s", got, buildrecipe.HostPlatform())
				}
				return
			}
			if got.String() != tc.want {
				t.Fatalf("platform = %s, want %s", got, tc.want)
			}
		})
	}
}

// The end-to-end pin check -- packaging a maintained capability must reproduce
// the digest its manifest pins -- needs those capabilities and manifests, so it
// lives with them in the private capabilities repository (ADR-010 inventory,
// adaptation 4). Here the recipe's own reproducibility is tested in buildrecipe.
