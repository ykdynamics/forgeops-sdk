// Package buildrecipe is the ONE implementation-build recipe that produces a
// capability's executable bytes — the bytes an identity digest describes
// (capability.yaml identity.artifactDigest: sha256 of the implementation
// binary). forgeops-cap packages with it, and so does any other tool that pins
// a capability's bytes: one recipe, so two tools can never pin two different
// digests for the same source.
//
// # Why the recipe is code and not a shell function
//
// A recipe assembled separately by each tool drifts. A bare compiler call —
// host platform, caller's compiler, caller's GOFLAGS, no -trimpath, no
// -buildvcs=false, unstripped — pins on a developer's Mac the digest of a
// darwin/arm64 Mach-O binary, while every edge runs a linux ELF. Adoption
// compares the digest an installer OBSERVED against the digest the package
// DECLARED, so such a package can either never be adopted (no edge can
// produce those bytes) or — worse — be adopted by passing the Mac's digest,
// authorizing bytes nothing reviewed.
//
// This API is experimental and versioned with the module (ADR-010).
//
// # What makes a digest mean anything
//
// A digest is only meaningful beside the platform and the compiler that made
// it, so both are explicit inputs and both come back in Result as evidence.
// There is deliberately no host default and no "whichever compiler is
// installed": Build refuses to run without an exact platform and an exact
// toolchain, and ResolveToolchain fails closed when go.mod carries no exact
// `toolchain` directive.
package buildrecipe

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

// PinnedToolchain is the exact compiler this SDK release is built and
// qualified with: the toolchain directive in this module's go.mod, which a test
// keeps equal to it. A project scaffolded by forgeops-cap pins it, so a
// capability's digest is reproducible under the same compiler as the SDK it
// imports, whichever compiler built the CLI.
const PinnedToolchain = "go1.23.12"

// Platform is the execution platform a digest was taken from: the GOOS/GOARCH
// the edge will actually run.
type Platform struct {
	OS   string
	Arch string
}

// String renders the platform the way manifests record it (linux/arm64).
func (p Platform) String() string { return p.OS + "/" + p.Arch }

// knownOS and knownArch are deliberately explicit lists rather than a shape
// check: "linux/ARM64" and "linx/arm64" are both well-shaped and both wrong,
// and a malformed platform is only caught here, before it reaches a manifest
// that claims to describe the bytes an edge will execute.
var (
	knownOS = map[string]bool{
		"aix": true, "darwin": true, "dragonfly": true, "freebsd": true,
		"illumos": true, "js": true, "linux": true, "netbsd": true,
		"openbsd": true, "plan9": true, "solaris": true, "wasip1": true,
		"windows": true,
	}
	knownArch = map[string]bool{
		"386": true, "amd64": true, "arm": true, "arm64": true, "loong64": true,
		"mips": true, "mips64": true, "mips64le": true, "mipsle": true,
		"ppc64": true, "ppc64le": true, "riscv64": true, "s390x": true,
		"wasm": true,
	}
)

// ParsePlatform parses "<os>/<arch>" and refuses anything malformed.
func ParsePlatform(s string) (Platform, error) {
	osName, arch, ok := strings.Cut(s, "/")
	if !ok || osName == "" || arch == "" || strings.Contains(arch, "/") {
		return Platform{}, fmt.Errorf("platform %q is not <os>/<arch> (e.g. linux/arm64)", s)
	}
	if !knownOS[osName] {
		return Platform{}, fmt.Errorf("platform %q: %q is not a known GOOS", s, osName)
	}
	if !knownArch[arch] {
		return Platform{}, fmt.Errorf("platform %q: %q is not a known GOARCH", s, arch)
	}
	return Platform{OS: osName, Arch: arch}, nil
}

// HostPlatform is the platform the current process runs on. It exists for the
// one caller that legitimately needs it — a local dev loop about to execute the
// binary it just built — and never as a silent default for an identity.
func HostPlatform() Platform { return Platform{OS: runtime.GOOS, Arch: runtime.GOARCH} }

// ModuleRoot walks up from dir to the module root (the directory holding
// go.mod). The recipe resolves its toolchain from that file, so it has to be
// found the same way for a capability inside this repo and for a scaffolded
// project somewhere else on disk.
func ModuleRoot(dir string) (string, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	for {
		if st, err := os.Stat(filepath.Join(abs, "go.mod")); err == nil && !st.IsDir() {
			return abs, nil
		}
		parent := filepath.Dir(abs)
		if parent == abs {
			return "", fmt.Errorf("no go.mod found at or above %s", dir)
		}
		abs = parent
	}
}

// toolchainDirective matches the exact-compiler directive in go.mod. All three
// components are required: `go1.23` is a language rather than a toolchain name,
// and a name that does not identify one exact release cannot decide which
// compiler makes — and checks — a digest.
var toolchainDirective = regexp.MustCompile(`(?m)^toolchain[ \t]+(go[0-9]+\.[0-9]+\.[0-9]+)[ \t]*$`)

// ResolveToolchain returns the exact compiler the module pins.
//
// The `go` directive is a MINIMUM: a newer installed compiler satisfies it and
// is silently used instead. That is fine for compiling and fatal for an
// identity, because the digest would then record whichever compiler the
// operator happened to have. Only the exact `toolchain` directive may decide
// which compiler makes — and therefore checks — a pin, so its absence is an
// error rather than a fallback. The returned value is passed as GOTOOLCHAIN,
// which makes the go command use exactly that compiler.
func ResolveToolchain(dir string) (string, error) {
	root, err := ModuleRoot(dir)
	if err != nil {
		return "", err
	}
	path := filepath.Join(root, "go.mod")
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	m := toolchainDirective.FindSubmatch(raw)
	if m == nil {
		return "", fmt.Errorf("%s declares no exact `toolchain goX.Y.Z` directive: a build here would be made by whichever compiler is installed, and the resulting digest would not reproduce. Pin the compiler in %s (see #524)", path, path)
	}
	return string(m[1]), nil
}

// PackagePattern expresses packageDir as a build pattern interpreted from
// moduleRoot ("./cmd/name"), which is how the pin and artifact scripts invoke
// the build: from the module root, by pattern. Building the same package by
// directory from inside it can embed a different path, so the whole repo
// converges on this one form.
func PackagePattern(moduleRoot, packageDir string) (string, error) {
	absRoot, err := filepath.Abs(moduleRoot)
	if err != nil {
		return "", err
	}
	absDir, err := filepath.Abs(packageDir)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(absRoot, absDir)
	if err != nil {
		return "", err
	}
	switch {
	case rel == ".":
		return ".", nil
	case rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)):
		return "", fmt.Errorf("%s is outside the module rooted at %s", packageDir, moduleRoot)
	}
	return "./" + filepath.ToSlash(rel), nil
}

// The recipe. Every flag here is part of the identity: changing one changes
// every digest in manifests/ without changing a byte of source. They are
// listed once, here, because they used to be maintained in three places and
// only two of them agreed.
const (
	// The module-cache build and a vendor-directory build embed different
	// go.sum h1: hashes in the build info.
	modFlag = "-mod=mod"
	// Without this the absolute source path is embedded, so the same source
	// in two checkouts produces two identities.
	trimpathFlag = "-trimpath"
	// Without this the commit hash and the dirty flag are embedded, so a pin
	// taken from a dirty tree differs from a clean rebuild of the same commit.
	buildVCSFlag = "-buildvcs=false"
	// This is what the OCI artifact ships; an unstripped pin can never match
	// the installed binary.
	ldFlags = "-s -w"
)

// Flags returns the exact argument vector the recipe runs, for a package
// pattern and an output path.
func Flags(pkg, output string) []string {
	return []string{
		"build", modFlag, trimpathFlag, buildVCSFlag,
		"-ldflags", ldFlags, "-o", output, pkg,
	}
}

// decidedEnv names every environment variable the recipe decides, and which is
// therefore removed from the caller's environment before the recipe's own values
// are set.
//
// Two kinds live here. The first is the recipe's own values (GOOS, GOARCH,
// CGO_ENABLED, GOTOOLCHAIN). The second is what would otherwise let the MACHINE
// decide part of an identity:
//
//   - GOFLAGS, GOEXPERIMENT, GOFIPS140 and the GOARCH tuning knobs (GOAMD64,
//     GOARM, GOARM64, GO386, GOMIPS, GOMIPS64, GOPPC64, GORISCV64, GOWASM) are
//     code-generation inputs: setting one changes the compiled bytes without
//     changing any source;
//   - GOWORK and GOENV are the two ways Go reads configuration from outside the
//     source tree. A workspace's replace directives override the module's own
//     dependency graph, so the same module and toolchain can compile different
//     code; and Go falls back to the per-user `go env -w` file for GOFLAGS and
//     the knobs above even when the environment variables are absent.
//
// Removing the first group restores Go's per-architecture baseline (which is
// what the committed pins were made with). The second group cannot be fixed by
// removal alone — an absent GOWORK means "go find a go.work yourself", and an
// absent GOENV means "go read the user's file" — so BuildEnv ALSO sets both to
// "off". Without that, `go env -w GOFLAGS=-tags=hostile` on an operator's
// machine, or a go.work two directories up, would quietly change the bytes
// behind a pinned digest.
var decidedEnv = map[string]bool{
	// The recipe's own values.
	"GOOS": true, "GOARCH": true, "CGO_ENABLED": true, "GOTOOLCHAIN": true,
	// Code-generation inputs.
	"GOFLAGS": true, "GOEXPERIMENT": true, "GOFIPS140": true,
	"GOAMD64": true, "GO386": true, "GOARM": true, "GOARM64": true,
	"GOMIPS": true, "GOMIPS64": true, "GOPPC64": true, "GORISCV64": true,
	"GOWASM": true,
	// Configuration from outside the source tree.
	"GOWORK": true, "GOENV": true,
	// The logical working directory. The go command derives its notion of "the
	// current directory" from PWD, and falls back to the physical path when PWD
	// is absent or does not describe the same directory. A build run with
	// cmd.Dir set to a module root would otherwise inherit the CALLER's PWD,
	// which describes a different directory — and on macOS, where a temp path
	// is reached through a symlink (/var -> /private/var), that mismatch is
	// enough to make workspace membership fail to resolve. BuildEnv sets it to
	// the directory the build actually runs in, which is what a `cd` would do.
	"PWD": true,
}

// BuildEnv is the environment the recipe runs in: the caller's environment with
// every variable the recipe decides removed, then set explicitly. dir is the
// directory the build runs in (the module root).
//
// GOFLAGS is a decided variable because `GOFLAGS=-ldflags=...` changes codegen
// without touching a source file, which would move an identity out from under
// the manifest that pins it. GOOS/GOARCH/CGO_ENABLED belong to the recipe too,
// not to whoever ran it; CGO_ENABLED=0 keeps the implementation static instead
// of depending on the host's C toolchain.
func BuildEnv(p Platform, toolchain, dir string) []string {
	env := make([]string, 0, len(os.Environ())+7)
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		if decidedEnv[name] {
			continue
		}
		env = append(env, kv)
	}
	return append(env,
		"CGO_ENABLED=0",
		"GOOS="+p.OS,
		"GOARCH="+p.Arch,
		"GOTOOLCHAIN="+toolchain,
		// Configuration-independence: no workspace's replace directives, and no
		// per-user go env file. Both are read from outside the source tree, so
		// neither belongs in a build that claims to be reproducible from the
		// source alone.
		"GOWORK=off",
		"GOENV=off",
		// A cwd the go command agrees with, rather than the caller's.
		"PWD="+dir,
	)
}

// Plan is one implementation build: a package pattern, the module root it is
// interpreted from, the platform the bytes are FOR, and where to write them.
type Plan struct {
	// Package is the build pattern ("./cmd/name"), interpreted from Dir.
	Package string
	// Dir is the module root the build runs in; the toolchain is resolved
	// from its go.mod.
	Dir string
	// Platform is the execution platform the bytes are for. Required.
	Platform Platform
	// Output is the path the implementation is written to.
	Output string
}

// Result is what the recipe produced, plus enough evidence to say what an
// identity digest describes: the path, the size, sha256 of the bytes, the
// platform they are for, and the exact compiler that made them.
type Result struct {
	Path      string
	Size      int64
	SHA256    string // sha256:<hex> of the implementation bytes
	Platform  string // <os>/<arch>
	Toolchain string // go1.23.12
}

// Build runs the recipe. It fails closed on anything that would make the
// result platform-ambiguous or compiler-ambiguous, because both are properties
// of the identity it is about to hand out.
func Build(plan Plan) (Result, error) {
	if strings.TrimSpace(plan.Package) == "" {
		return Result{}, fmt.Errorf("implbuild: no package to build")
	}
	if strings.TrimSpace(plan.Dir) == "" {
		return Result{}, fmt.Errorf("implbuild: no module root to build from")
	}
	if strings.TrimSpace(plan.Output) == "" {
		return Result{}, fmt.Errorf("implbuild: no output path")
	}
	platform, err := ParsePlatform(plan.Platform.String())
	if err != nil {
		return Result{}, err
	}
	dir, err := filepath.Abs(plan.Dir)
	if err != nil {
		return Result{}, err
	}
	toolchain, err := ResolveToolchain(dir)
	if err != nil {
		return Result{}, err
	}
	out, err := filepath.Abs(plan.Output)
	if err != nil {
		return Result{}, err
	}
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		return Result{}, fmt.Errorf("implbuild: create output directory: %w", err)
	}

	cmd := exec.Command("go", Flags(plan.Package, out)...)
	cmd.Dir = dir
	cmd.Env = BuildEnv(platform, toolchain, dir)
	if combined, err := cmd.CombinedOutput(); err != nil {
		return Result{}, fmt.Errorf("build %s for %s with %s failed: %w\n%s", plan.Package, platform, toolchain, err, combined)
	}

	f, err := os.Open(out)
	if err != nil {
		return Result{}, fmt.Errorf("implbuild: read built implementation: %w", err)
	}
	defer f.Close()
	h := sha256.New()
	size, err := io.Copy(h, f)
	if err != nil {
		return Result{}, fmt.Errorf("implbuild: hash built implementation: %w", err)
	}
	return Result{
		Path:      out,
		Size:      size,
		SHA256:    "sha256:" + hex.EncodeToString(h.Sum(nil)),
		Platform:  platform.String(),
		Toolchain: toolchain,
	}, nil
}
