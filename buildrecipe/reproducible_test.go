package buildrecipe

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestBuildIsReproducible is the property the whole recipe exists for: the same
// source, platform and compiler produce the same bytes — twice in a row, and
// into two different output paths.
//
// The output path is checked deliberately. It is easy to assume a destination
// filename is part of executable identity, and that assumption is how someone
// "fixes" nondeterminism with a fixed temp name instead of finding the real
// input. With -trimpath the path is not an input, and this proves it.
func TestBuildIsReproducible(t *testing.T) {
	root := writeModule(t, probeMain)
	p := linuxAMD64(t)

	first := buildProbe(t, root, p, filepath.Join(t.TempDir(), "a", "probe"))
	again := buildProbe(t, root, p, filepath.Join(t.TempDir(), "probe"))

	if first.SHA256 != again.SHA256 {
		t.Fatalf("same source, same platform, same toolchain produced two identities:\n  %s\n  %s", first.SHA256, again.SHA256)
	}
	if first.Platform != "linux/amd64" || first.Toolchain == "" {
		t.Fatalf("result does not describe what it built: %+v", first)
	}
}

// TestDigestFollowsTheBytes proves the digest is a function of the source and
// the platform, and of nothing else: change either and it moves.
func TestDigestFollowsTheBytes(t *testing.T) {
	base := writeModule(t, probeMain)
	p := linuxAMD64(t)
	baseline := buildProbe(t, base, p, filepath.Join(t.TempDir(), "probe"))

	changed := writeModule(t, strings.Replace(probeMain, "probe-A", "probe-B", 1))
	if other := buildProbe(t, changed, p, filepath.Join(t.TempDir(), "probe")); other.SHA256 == baseline.SHA256 {
		t.Fatal("changing the source did not change the implementation digest")
	}

	if arm := buildProbe(t, base, linuxARM64(t), filepath.Join(t.TempDir(), "probe")); arm.SHA256 == baseline.SHA256 {
		t.Fatal("building for another platform did not change the implementation digest")
	}
}

// TestBuildHonorsPlatform reads the ELF header the recipe produced, so "built
// for linux/arm64" is proven by the bytes rather than by the metadata the
// builder reports about itself.
func TestBuildHonorsPlatform(t *testing.T) {
	root := writeModule(t, probeMain)
	for _, tc := range []struct {
		platform Platform
		machine  uint16
		what     string
	}{
		{linuxAMD64(t), 0x3E, "x86-64"},
		{linuxARM64(t), 0xB7, "AArch64"},
	} {
		res := buildProbe(t, root, tc.platform, filepath.Join(t.TempDir(), "probe"))
		raw, err := os.ReadFile(res.Path)
		if err != nil {
			t.Fatal(err)
		}
		if len(raw) < 20 || !bytes.Equal(raw[:4], []byte{0x7f, 'E', 'L', 'F'}) {
			t.Fatalf("%s: output is not an ELF binary", tc.platform)
		}
		got := uint16(raw[18]) | uint16(raw[19])<<8
		if got != tc.machine {
			t.Fatalf("%s: ELF e_machine = 0x%02X, want 0x%02X (%s)", tc.platform, got, tc.machine, tc.what)
		}
	}
}

// TestResultCarriesEvidence checks the fields callers write into manifests.
func TestResultCarriesEvidence(t *testing.T) {
	root := writeModule(t, probeMain)
	res := buildProbe(t, root, linuxARM64(t), filepath.Join(t.TempDir(), "probe"))
	if !strings.HasPrefix(res.SHA256, "sha256:") || len(res.SHA256) != len("sha256:")+64 {
		t.Fatalf("digest is not sha256:<64 hex>: %q", res.SHA256)
	}
	if res.Size == 0 {
		t.Fatal("Result.Size is zero")
	}
	if _, err := os.Stat(res.Path); err != nil {
		t.Fatalf("Result.Path does not exist: %v", err)
	}
}

// TestCallerEnvironmentCannotChangeTheDigest covers the environment variables
// that change codegen without touching a source file: GOFLAGS, the
// architecture tuning knobs, and the knobs that enable compiler experiments.
func TestCallerEnvironmentCannotChangeTheDigest(t *testing.T) {
	root := writeModule(t, probeMain)
	p := linuxAMD64(t)
	baseline := buildProbe(t, root, p, filepath.Join(t.TempDir(), "probe"))

	t.Setenv("GOFLAGS", "-ldflags=-X main.probe=injected")
	t.Setenv("GOOS", "windows")
	t.Setenv("GOARCH", "386")
	t.Setenv("CGO_ENABLED", "1")
	t.Setenv("GOAMD64", "v3")
	t.Setenv("GOEXPERIMENT", "arenas")
	if hostile := buildProbe(t, root, p, filepath.Join(t.TempDir(), "probe")); hostile.SHA256 != baseline.SHA256 {
		t.Fatalf("the caller's environment changed the implementation digest:\n  %s\n  %s", baseline.SHA256, hostile.SHA256)
	}
}

// TestUserGoEnvFileCannotChangeTheDigest covers the file behind `go env -w`.
// Go reads GOFLAGS and the codegen knobs from that file even when the
// environment variables themselves are absent, so filtering the environment is
// not enough: GOENV has to be turned off, or `go env -w GOFLAGS=-tags=hostile`
// on an operator's machine ends up deciding the bytes behind a pinned digest.
func TestUserGoEnvFileCannotChangeTheDigest(t *testing.T) {
	root := writeModule(t, probeMain)
	p := linuxAMD64(t)
	baseline := buildProbe(t, root, p, filepath.Join(t.TempDir(), "probe"))

	// Exactly what `go env -w GOFLAGS=…` writes and where Go looks for it.
	// -gcflags=-N is a certain codegen change, so if this file is honored at
	// all the bytes move.
	envFile := filepath.Join(t.TempDir(), "env")
	if err := os.WriteFile(envFile, []byte("GOFLAGS=-gcflags=-N\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOENV", envFile)
	t.Setenv("GOFLAGS", "")

	got := buildProbe(t, root, p, filepath.Join(t.TempDir(), "probe"))
	if got.SHA256 != baseline.SHA256 {
		t.Fatalf("the per-user go env file changed the implementation digest:\n  %s\n  %s", baseline.SHA256, got.SHA256)
	}

	// Prove the fixture is hostile rather than inert, and prove it with the
	// SAME build both times so the difference can only be the file: without
	// this, the test could pass because the file is never read at all.
	t.Setenv("GOENV", "")

	without, err := rawGoBuild(root, p)
	if err != nil {
		t.Fatalf("control build without the env file: %v", err)
	}
	t.Setenv("GOENV", envFile)
	with, err := rawGoBuild(root, p)
	if err != nil {
		t.Fatalf("control build with the env file: %v", err)
	}
	if with == without {
		t.Fatal("the fixture go env file does not actually change the build, so this test proves nothing")
	}
}

// TestWorkspaceCannotChangeTheDigest covers GOWORK. A workspace's replace
// directives override the module's own dependency graph, so the same module,
// platform and toolchain can compile genuinely different code — which is why a
// workspace must not be able to decide an implementation identity.
func TestWorkspaceCannotChangeTheDigest(t *testing.T) {
	root := t.TempDir()
	toolchain := toolchainLine(t, string(readRepoGoMod(t)))
	write := func(path, content string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	dep := func(dir, value string) {
		write(filepath.Join(dir, "go.mod"), "module probe/dep\n\ngo 1.23\n\n"+toolchain)
		write(filepath.Join(dir, "dep.go"), "package dep\n\nfunc Value() string { return \""+value+"\" }\n")
	}
	dep(filepath.Join(root, "dep-v1"), "v1")
	dep(filepath.Join(root, "dep-v2"), "v2")

	app := filepath.Join(root, "app")
	write(filepath.Join(app, "go.mod"),
		"module probe/app\n\ngo 1.23\n\n"+toolchain+"\nrequire probe/dep v0.0.0\n\nreplace probe/dep => ../dep-v1\n")
	write(filepath.Join(app, "main.go"),
		"package main\n\nimport (\n\t\"fmt\"\n\n\t\"probe/dep\"\n)\n\nfunc main() { fmt.Println(dep.Value()) }\n")

	p := linuxAMD64(t)
	baseline := buildProbe(t, app, p, filepath.Join(t.TempDir(), "probe"))
	// The control, measured BEFORE any workspace exists, with the same flags it
	// will use again below.
	without, err := rawGoBuild(app, p)
	if err != nil {
		t.Fatalf("control build without a workspace: %v", err)
	}

	// Let Go write the workspace rather than hand-writing go.work. A
	// hand-written one is not portable: `use ./app` and an absolute `use` both
	// resolve differently depending on whether the path is the logical one
	// (/var/folders/… on macOS) or the physical one (/private/var/…), and get
	// rejected as "not one of the workspace modules" for reasons that have
	// nothing to do with what this test is about.
	runGo(t, root, baseline.Toolchain, "work", "init", "./app")
	runGo(t, root, baseline.Toolchain, "work", "edit", "-replace=probe/dep=./dep-v2")
	work := filepath.Join(root, "go.work")
	if _, err := os.Stat(work); err != nil {
		t.Fatalf("workspace was not created: %v", err)
	}
	t.Setenv("GOWORK", work)

	// The recipe must ignore it.
	got := buildProbe(t, app, p, filepath.Join(t.TempDir(), "probe"))
	if got.SHA256 != baseline.SHA256 {
		t.Fatalf("a go.work changed the implementation digest: workspace resolution must be off\n  %s\n  %s", baseline.SHA256, got.SHA256)
	}

	// And the fixture must be a real override, or the assertion above passed
	// for the wrong reason.
	with, err := rawGoBuild(app, p)
	if err != nil {
		t.Fatalf("control build with the workspace: %v", err)
	}
	if with == without {
		t.Fatal("the fixture workspace does not actually override the module's replace, so this test proves nothing")
	}
}

// runGo runs a go subcommand for fixture setup (not for building anything whose
// digest is asserted) and fails the test on error. The toolchain is passed in
// because the fixture root is a workspace directory, which has no go.mod.
func runGo(t *testing.T, dir, toolchain string, args ...string) {
	t.Helper()
	cmd := exec.Command("go", args...)
	cmd.Dir = dir
	// No GOWORK here: creating the workspace is the point. PWD is set so the
	// go command's logical cwd matches cmd.Dir.
	cmd.Env = append(os.Environ(), "GOTOOLCHAIN="+toolchain, "GOENV=off", "PWD="+dir)
	if combined, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go %s: %v\n%s", strings.Join(args, " "), err, combined)
	}
}

// TestDirtyVCSDoesNotChangeTheDigest covers -buildvcs=false: a pin taken from a
// dirty tree must equal a clean rebuild of the same commit, otherwise the pin
// records the operator's working state instead of the reviewed source.
func TestDirtyVCSDoesNotChangeTheDigest(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not available")
	}
	root := writeModule(t, probeMain)
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = root
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=implbuild", "GIT_AUTHOR_EMAIL=implbuild@test",
			"GIT_COMMITTER_NAME=implbuild", "GIT_COMMITTER_EMAIL=implbuild@test",
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
		}
	}
	git("init", "-q")
	git("add", ".")
	git("commit", "-qm", "probe")

	p := linuxAMD64(t)
	clean := buildProbe(t, root, p, filepath.Join(t.TempDir(), "probe"))

	// An untracked file makes the working tree dirty; with -buildvcs=false that
	// state is not part of the build at all.
	if err := os.WriteFile(filepath.Join(root, "uncommitted.txt"), []byte("dirty\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	dirty := buildProbe(t, root, p, filepath.Join(t.TempDir(), "probe"))
	if clean.SHA256 != dirty.SHA256 {
		t.Fatalf("a dirty working tree changed the implementation digest:\n  clean %s\n  dirty %s", clean.SHA256, dirty.SHA256)
	}
}

// TestBuildFailsClosedWithoutExactToolchain: an identity pinned without an exact
// compiler is not reproducible, so the build refuses rather than guessing.
func TestBuildFailsClosedWithoutExactToolchain(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module probe\n\ngo 1.23\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte(probeMain), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Build(Plan{Package: ".", Dir: root, Platform: linuxAMD64(t), Output: filepath.Join(t.TempDir(), "probe")}); err == nil {
		t.Fatal("Build produced an implementation identity without an exact toolchain")
	}
}
