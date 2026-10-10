package main

import (
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ykdynamics/forgeops-sdk/buildrecipe"
	"github.com/ykdynamics/forgeops-sdk/capability"
)

func TestSafeReadYAMLValidates(t *testing.T) {
	doc := safeReadYAML("acme.demo.status")
	pkg, errs, err := capability.ValidateDocument([]byte(doc))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(errs) != 0 {
		t.Fatalf("scaffolded capability.yaml should validate: %v", errs)
	}
	if pkg.Identity.Key != "acme.demo.status" {
		t.Fatalf("key = %q", pkg.Identity.Key)
	}
	if pkg.ExecutionBoundary.Risk != "allow" {
		t.Fatalf("risk = %q", pkg.ExecutionBoundary.Risk)
	}
}

func TestSafeReadMainGoParses(t *testing.T) {
	src := safeReadMainGo("acme.demo.status")
	if _, err := parser.ParseFile(token.NewFileSet(), "main.go", src, parser.AllErrors); err != nil {
		t.Fatalf("generated main.go does not parse: %v", err)
	}
	// The struct tags must survive the template intact (backtick quoting bug
	// would surface as a parse error or missing tags).
	if !strings.Contains(src, "`json:\"service\"`") {
		t.Fatal("generated main.go is missing the service JSON tag")
	}
	if !strings.Contains(src, "sdk.Serve(addr, status)") {
		t.Fatal("generated main.go is missing the sdk.Serve wiring")
	}
}

// A scaffolded project requires the released SDK: no replace, no checkout.
func TestRenderGoModRequiresTheRelease(t *testing.T) {
	mod := renderGoMod("github.com/dev/acme-demo-status", "v0.1.0", "", buildrecipe.PinnedToolchain)
	if !strings.Contains(mod, "\nrequire github.com/ykdynamics/forgeops-sdk v0.1.0\n") {
		t.Fatalf("go.mod does not require the SDK release:\n%s", mod)
	}
	if strings.Contains(mod, "replace") || strings.Contains(mod, "forgeops-capabilities") {
		t.Fatalf("a release project must not replace the SDK or name the private module:\n%s", mod)
	}
	// The scaffolded project must pin the compiler: `forgeops-cap package`
	// refuses to pin an implementation digest without an exact toolchain.
	if !strings.Contains(mod, "\ntoolchain "+buildrecipe.PinnedToolchain+"\n") {
		t.Fatalf("go.mod is missing the exact toolchain directive:\n%s", mod)
	}
}

// A local checkout is used only when asked for, as a replace.
func TestRenderGoModReplacesOnlyWhenAsked(t *testing.T) {
	mod := renderGoMod("github.com/dev/acme-demo-status", "", "/sdk/path", buildrecipe.PinnedToolchain)
	if !strings.Contains(mod, "replace github.com/ykdynamics/forgeops-sdk => /sdk/path") {
		t.Fatalf("go.mod is missing the requested replace:\n%s", mod)
	}
}

// The pinned compiler is the SDK's, never the one that built this CLI (a CLI
// built by a newer local Go used to scaffold that version into projects).
func TestScaffoldToolchainIsTheSDKs(t *testing.T) {
	if got := scaffoldToolchain(""); got != buildrecipe.PinnedToolchain {
		t.Fatalf("scaffoldToolchain() = %q, want the SDK's %q", got, buildrecipe.PinnedToolchain)
	}
	// A requested checkout that is not a readable module still gets the SDK's pin.
	if got := scaffoldToolchain(t.TempDir()); got != buildrecipe.PinnedToolchain {
		t.Fatalf("scaffoldToolchain(non-module) = %q, want %q", got, buildrecipe.PinnedToolchain)
	}
}

// TestResolveToolchainRequiresThreeComponents: a two-component directive is
// accepted by go.mod but does not name one toolchain, so it must not be
// treated as an exact pin.
func TestResolveToolchainRequiresThreeComponents(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module probe\n\ngo 1.23\n\ntoolchain go1.23\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := buildrecipe.ResolveToolchain(root); err == nil {
		t.Fatal("ResolveToolchain accepted `toolchain go1.23`, which names a language version rather than one compiler")
	}
}

// A CLI built from source carries no release, so init must not guess one: it
// asks for --sdk-version or --sdk-replace. (A scaffold that guessed used to
// write `replace … => ..`, a project that could not be built anywhere.)
func TestInitWithoutAReleaseAsksForOne(t *testing.T) {
	if sdkVersion() != "" {
		t.Skip("this test binary carries a release version")
	}
	inTempDir(t)
	err := cmdInit([]string{"acme.demo.status"})
	if err == nil || !strings.Contains(err.Error(), "--sdk-version") {
		t.Fatalf("init without a release = %v, want a request for --sdk-version or --sdk-replace", err)
	}
}

// The scaffolded project builds against this SDK tree, outside it: the
// developer's journey, with a replace standing in for the released module.
func TestScaffoldedProjectBuilds(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a project with the go toolchain")
	}
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	root, err := filepath.Abs(filepath.Join(wd, "..", "..")) // this module's root
	if err != nil {
		t.Fatal(err)
	}
	dir := inTempDir(t)
	if err := cmdInit([]string{"acme.demo.status", "--sdk-replace", root}); err != nil {
		t.Fatalf("init: %v", err)
	}
	build := exec.Command("go", "build", "-o", filepath.Join(dir, "capability-bin"), ".")
	build.Dir = filepath.Join(dir, "acme-demo-status")
	build.Env = append(os.Environ(), "GOFLAGS=-mod=mod", "GOWORK=off")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("the scaffolded project does not build: %v\n%s", err, out)
	}
}

// inTempDir runs the rest of the test in a fresh directory, outside any module.
func inTempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	prev, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(prev) })
	return dir
}

func TestSplitPositional(t *testing.T) {
	pos, flags := splitPositional([]string{"run", "--input", `{"x":1}`, "."})
	if pos != "run" {
		t.Fatalf("positional = %q", pos)
	}
	// Flags after the positional are extracted too (splitPositional is used on
	// the subcommand args, not the full argv).
	pos, flags = splitPositional([]string{"--input", `{"x":1}`, "."})
	if pos != "." {
		t.Fatalf("positional = %q", pos)
	}
	if len(flags) != 2 || flags[0] != "--input" {
		t.Fatalf("flags = %v", flags)
	}
}
