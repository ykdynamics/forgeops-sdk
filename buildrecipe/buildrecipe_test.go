package buildrecipe

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// writeModule creates a throwaway module with one main package whose source is
// `body`, and returns its module root. Tests use their own module rather than
// this repo's capabilities: a recipe test that builds a real capability cannot
// vary its source, and varying the source is how "the digest follows the bytes"
// gets proven.
func writeModule(t *testing.T, body string) string {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	repoMod := string(readRepoGoMod(t))
	mod := "module buildrecipe.test/probe\n\ngo 1.23\n\n" + toolchainLine(t, repoMod)
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte(mod), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

func readRepoGoMod(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "go.mod"))
	if err != nil {
		t.Fatalf("read this repo's go.mod: %v", err)
	}
	return raw
}

// The constant a scaffolded project pins and the directive this module is built
// with must be one value: otherwise a developer's capability would pin a
// different compiler from the SDK it compiles.
func TestPinnedToolchainIsThisModulesToolchain(t *testing.T) {
	if got, want := strings.TrimSpace(strings.TrimPrefix(toolchainLine(t, string(readRepoGoMod(t))), "toolchain ")), PinnedToolchain; got != want {
		t.Fatalf("go.mod pins %s, PinnedToolchain says %s: change both together", got, want)
	}
}

// toolchainLine mirrors this repo's exact toolchain into the test module, so the
// tests never depend on the compiler the developer happens to have.
func toolchainLine(t *testing.T, repoMod string) string {
	t.Helper()
	m := toolchainDirective.FindSubmatch([]byte(repoMod))
	if m == nil {
		t.Fatal("this repo's go.mod declares no exact toolchain")
	}
	return "toolchain " + string(m[1]) + "\n"
}

const probeMain = `package main

import "fmt"

func main() { fmt.Println("implbuild-probe-A") }
`

// rawGoBuild runs a plain build with the caller's configuration left in place —
// GOENV, GOWORK and the codegen knobs are inherited exactly as an unfiltered
// toolchain would see them — with only the platform and compiler forced to the
// ones under test.
//
// It deliberately omits the recipe's -mod=mod, because Go REFUSES that flag in
// workspace mode ("-mod may only be set to readonly or vendor when in workspace
// mode"), so it cannot be used to observe what a workspace would do. Call it
// twice with the SAME flags and only the fixture differing: that is what makes
// "the fixture changed the bytes" a real observation instead of an artifact of
// the flag set.
//
// It exists only as a control. A hermeticity test that passes because the
// hostile fixture was never actually read proves nothing.
func rawGoBuild(dir string, p Platform) (string, error) {
	toolchain, err := ResolveToolchain(dir)
	if err != nil {
		return "", err
	}
	tmp, err := os.MkdirTemp("", "implbuild-control-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tmp)
	out := filepath.Join(tmp, "probe")

	env := make([]string, 0, len(os.Environ())+5)
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		switch name {
		case "GOOS", "GOARCH", "CGO_ENABLED", "GOTOOLCHAIN", "PWD":
			continue
		}
		env = append(env, kv)
	}
	// PWD is set for correctness of the logical cwd, not for hermeticity: the
	// control inherits GOENV/GOWORK/knobs on purpose, but a cwd the go command
	// disagrees with would break the fixture being measured.
	env = append(env, "CGO_ENABLED=0", "GOOS="+p.OS, "GOARCH="+p.Arch, "GOTOOLCHAIN="+toolchain, "PWD="+dir)

	cmd := exec.Command("go", "build", "-trimpath", "-buildvcs=false", "-ldflags", "-s -w", "-o", out, ".")
	cmd.Dir = dir
	cmd.Env = env
	if combined, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("%w\n%s", err, combined)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func buildProbe(t *testing.T, root string, p Platform, output string) Result {
	t.Helper()
	res, err := Build(Plan{Package: ".", Dir: root, Platform: p, Output: output})
	if err != nil {
		t.Fatalf("build %s for %s: %v", root, p, err)
	}
	return res
}

func linuxAMD64(t *testing.T) Platform {
	t.Helper()
	p, err := ParsePlatform("linux/amd64")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func linuxARM64(t *testing.T) Platform {
	t.Helper()
	p, err := ParsePlatform("linux/arm64")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// TestParsePlatform covers the malformed values that must never reach a
// manifest claiming to describe the bytes an edge will execute.
func TestParsePlatform(t *testing.T) {
	for _, ok := range []string{"linux/arm64", "linux/amd64", "darwin/arm64", "windows/amd64", "linux/riscv64"} {
		if _, err := ParsePlatform(ok); err != nil {
			t.Errorf("ParsePlatform(%q) refused a valid platform: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "linux", "arm64", "/arm64", "linux/", "linux/ARM64", "Linux/amd64", "linx/arm64", "linux/arm64/extra", "linux/amd65"} {
		if got, err := ParsePlatform(bad); err == nil {
			t.Errorf("ParsePlatform(%q) was accepted as %s, want refusal", bad, got)
		}
	}
}

// TestBuildEnvPinsEveryDecidedVariable proves the variables the recipe owns, and
// that nothing which can decide part of an identity survives from the caller.
func TestBuildEnvPinsEveryDecidedVariable(t *testing.T) {
	t.Setenv("GOFLAGS", "-ldflags=-X main.v=changed")
	t.Setenv("GOOS", "windows")
	t.Setenv("CGO_ENABLED", "1")
	t.Setenv("GOEXPERIMENT", "arenas")
	t.Setenv("GOFIPS140", "latest")
	t.Setenv("GOAMD64", "v3")
	t.Setenv("GOARM64", "v9.0")
	t.Setenv("GOWORK", "/somewhere/go.work")
	t.Setenv("GOENV", "/home/someone/.config/go/env")
	t.Setenv("PWD", "/somewhere/else")
	p := linuxARM64(t)
	env := BuildEnv(p, "go1.23.12", "/build/dir")

	got := map[string]string{}
	for _, kv := range env {
		name, value, _ := strings.Cut(kv, "=")
		got[name] = value
	}
	if got["GOOS"] != "linux" || got["GOARCH"] != "arm64" {
		t.Fatalf("GOOS/GOARCH = %s/%s, want linux/arm64", got["GOOS"], got["GOARCH"])
	}
	if got["CGO_ENABLED"] != "0" {
		t.Fatalf("CGO_ENABLED = %q, want 0 (the edge binary is static)", got["CGO_ENABLED"])
	}
	if got["GOTOOLCHAIN"] != "go1.23.12" {
		t.Fatalf("GOTOOLCHAIN = %q, want the exact pinned compiler", got["GOTOOLCHAIN"])
	}
	if _, present := got["GOFLAGS"]; present {
		t.Fatalf("GOFLAGS survived into the build environment (%q): a caller's GOFLAGS changes codegen without changing source", got["GOFLAGS"])
	}
	// Configuration read from OUTSIDE the source tree must be off, not merely
	// absent: an unset GOWORK means "go find a go.work yourself", and an unset
	// GOENV means "go read the per-user `go env -w` file".
	if got["GOWORK"] != "off" {
		t.Fatalf("GOWORK = %q, want off — a workspace's replace directives would override the module's dependency graph", got["GOWORK"])
	}
	if got["GOENV"] != "off" {
		t.Fatalf("GOENV = %q, want off — Go otherwise reads GOFLAGS and the codegen knobs from the user's env file", got["GOENV"])
	}
	// PWD is the go command's source for its logical cwd; inheriting the
	// caller's makes path-sensitive resolution disagree with cmd.Dir.
	if got["PWD"] != "/build/dir" {
		t.Fatalf("PWD = %q, want the build directory — a stale PWD breaks path-sensitive resolution", got["PWD"])
	}
	// The code-generation knobs are removed, so Go uses its per-architecture
	// baseline — which is what the committed pins were made with.
	for _, knob := range []string{"GOEXPERIMENT", "GOFIPS140", "GOAMD64", "GOARM", "GOARM64", "GO386", "GOMIPS", "GOMIPS64", "GOPPC64", "GORISCV64", "GOWASM"} {
		if value, present := got[knob]; present {
			t.Errorf("%s survived into the build environment (%q): it is a code-generation input", knob, value)
		}
	}
}

// TestFlagsAreTheRecipe pins the argument vector itself, so a flag cannot be
// dropped from the middle of the recipe without a test saying so.
func TestFlagsAreTheRecipe(t *testing.T) {
	got := strings.Join(Flags("./cmd/x", "/tmp/x"), " ")
	want := "build -mod=mod -trimpath -buildvcs=false -ldflags -s -w -o /tmp/x ./cmd/x"
	if got != want {
		t.Fatalf("Flags() = %q, want %q", got, want)
	}
}

// TestResolveToolchain reads the exact compiler, and fails closed without one.
func TestResolveToolchain(t *testing.T) {
	repo, err := ResolveToolchain(".")
	if err != nil {
		t.Fatalf("resolve this repo's toolchain: %v", err)
	}
	m := toolchainDirective.FindSubmatch(readRepoGoMod(t))
	if m == nil || repo != string(m[1]) {
		t.Fatalf("ResolveToolchain(.) = %q, want %q", repo, m[1])
	}

	// A `go` directive is a MINIMUM, not a pin: without `toolchain` a digest
	// would record whichever compiler is installed and would not reproduce.
	bare := t.TempDir()
	if err := os.WriteFile(filepath.Join(bare, "go.mod"), []byte("module probe\n\ngo 1.23\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveToolchain(bare); err == nil {
		t.Fatal("ResolveToolchain accepted a module with no exact toolchain, want failure")
	}
	if _, err := ResolveToolchain(t.TempDir()); err == nil {
		t.Fatal("ResolveToolchain accepted a directory with no go.mod, want failure")
	}
}
