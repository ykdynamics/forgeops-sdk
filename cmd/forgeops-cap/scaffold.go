package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"strings"

	"github.com/ykdynamics/forgeops-sdk/buildrecipe"
	"github.com/ykdynamics/forgeops-sdk/capability"
)

// placeholderDigest is a format-valid digest at scaffold time; the README tells
// the developer to set the real artifact digest at publish. The schema keeps
// the digest required so the registry refuses tampered packages at publish,
// while dev scaffolds still validate.
const placeholderDigest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

var keyRe = regexp.MustCompile(`^[a-z0-9]+([._-][a-z0-9]+)*$`)

// sdkModule is this SDK's module path: what a scaffolded project requires.
const sdkModule = "github.com/ykdynamics/forgeops-sdk"

// version is the forgeops-sdk release this CLI belongs to. Release binaries
// carry it (-ldflags "-X main.version=vX.Y.Z"); `go install
// github.com/ykdynamics/forgeops-sdk/cmd/forgeops-cap@vX.Y.Z` needs no stamp,
// since the module version is in the build info.
var version = ""

var moduleVersionRe = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$`)

// sdkVersion is the release a scaffolded project requires by default: the one
// this CLI comes from, so the project builds against exactly the SDK the CLI
// was released with. Empty for a CLI built from a source checkout, which
// carries no release: init then asks for --sdk-version or --sdk-replace rather
// than guessing.
func sdkVersion() string {
	if version != "" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Path == sdkModule && moduleVersionRe.MatchString(info.Main.Version) {
		return info.Main.Version
	}
	return ""
}

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	dir := fs.String("dir", "", "project directory (default: key with dots -> dashes)")
	sdkVer := fs.String("sdk-version", sdkVersion(), "the forgeops-sdk release the project requires (default: this CLI's own release)")
	sdkReplace := fs.String("sdk-replace", "", "build against a local forgeops-sdk checkout instead of a release (adds a go.mod replace)")
	key, flagArgs := splitPositional(args)
	_ = fs.Parse(flagArgs)
	if key == "" {
		return fmt.Errorf("init needs exactly one capability key (e.g. acme.service.status)")
	}
	if *sdkVer == "" && *sdkReplace == "" {
		return fmt.Errorf("this forgeops-cap carries no release version (built from source): pass --sdk-version vX.Y.Z, or --sdk-replace <path to a forgeops-sdk checkout>")
	}
	if *sdkVer != "" && !moduleVersionRe.MatchString(*sdkVer) {
		return fmt.Errorf("--sdk-version %q is not a module version (vX.Y.Z)", *sdkVer)
	}
	if !keyRe.MatchString(key) {
		return fmt.Errorf("%q is not a valid capability key (lowercase alphanumeric dotted segments)", key)
	}
	projectDir := *dir
	if projectDir == "" {
		projectDir = strings.ReplaceAll(key, ".", "-")
	}
	moduleName := "github.com/dev/" + projectDir

	if err := os.MkdirAll(projectDir, 0o755); err != nil {
		return fmt.Errorf("create project dir: %w", err)
	}

	pkgYAML := safeReadYAML(key)
	pkg, errs, err := capability.ValidateDocument([]byte(pkgYAML))
	if err != nil {
		return fmt.Errorf("generated capability.yaml failed to parse: %w", err)
	}
	if len(errs) != 0 {
		return fmt.Errorf("generated capability.yaml does not validate: %v", errs)
	}
	_ = pkg

	files := map[string]string{
		"capability.yaml": pkgYAML,
		"main.go":         safeReadMainGo(key),
		"go.mod":          renderGoMod(moduleName, *sdkVer, *sdkReplace, scaffoldToolchain(*sdkReplace)),
		"README.md":       renderReadme(key),
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(projectDir, name), []byte(content), 0o644); err != nil {
			return fmt.Errorf("write %s: %w", name, err)
		}
	}
	fmt.Printf("scaffolded %s in %s\n", key, projectDir)
	fmt.Println("  next: cd " + projectDir + " && forgeops-cap validate capability.yaml && forgeops-cap run .")
	return nil
}

func safeReadYAML(key string) string {
	return fmt.Sprintf(`schemaVersion: capability.v1
identity:
  key: %s
  version: 0.1.0
  artifactDigest: %s
contract:
  description: %s — safe-read capability scaffolded by forgeops-cap init
  inputSchema:
    type: object
    required: [service]
    additionalProperties: false
    properties:
      service:
        type: string
        minLength: 1
  outputSchema:
    type: object
    required: [healthy]
    additionalProperties: false
    properties:
      healthy:
        type: boolean
executionBoundary:
  risk: allow
  egress: []
runtime:
  interface: mcp
  runtimeContract: runtime.v1
`, key, placeholderDigest, key)
}

func safeReadMainGo(key string) string {
	// The backtick literals are built with %q-free concatenation so the raw
	// struct tags survive the template intact.
	return fmt.Sprintf(`// Command main is the %[1]s capability scaffolded by forgeops-cap init.
// Safe-read starter: bind the input, return the output; the SDK speaks the
// runtime contract (runtime.v1).
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/ykdynamics/forgeops-sdk/sdk"
)

type input struct {
	Service string %[2]sjson:"service"%[2]s
}

type output struct {
	Healthy bool %[2]sjson:"healthy"%[2]s
}

func main() {
	addr := envDefault("CAPABILITY_ADDR", ":8097")
	if len(os.Args) >= 2 && os.Args[1] == "healthcheck" {
		sdk.HealthcheckMain(addr)
	}
	if err := sdk.Serve(addr, status); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func status(ctx context.Context, rc *sdk.Context) (any, error) {
	var in input
	if err := rc.Bind(&in); err != nil {
		return nil, fmt.Errorf("invalid input: %%w", err)
	}
	if in.Service == "" {
		return nil, fmt.Errorf("service is required (the capability never chooses what to act on)")
	}
	_ = rc.Progress(ctx, 100, "status read complete")
	return output{Healthy: true}, nil
}

func envDefault(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
`, key, "`")
}

// renderGoMod writes the project's go.mod: it requires the forgeops-sdk
// release, and builds against a local checkout only when the developer asked
// for one (replace). The `toolchain` directive is not decoration:
// `forgeops-cap package` pins identity.artifactDigest by building the
// implementation with the exact compiler its module declares, and refuses to
// pin at all when the module declares none.
func renderGoMod(moduleName, sdkVersion, sdkReplace, toolchain string) string {
	mod := fmt.Sprintf("module %s\n\ngo 1.23\n\ntoolchain %s\n", moduleName, toolchain)
	if sdkVersion == "" {
		sdkVersion = "v0.0.0" // only with a replace: the version is then not resolved
	}
	mod += fmt.Sprintf("\nrequire %s %s\n", sdkModule, sdkVersion)
	if sdkReplace != "" {
		mod += fmt.Sprintf("\nreplace %s => %s\n", sdkModule, sdkReplace)
	}
	return mod
}

// scaffoldToolchain is the exact compiler a scaffolded project pins. Never the
// developer's installed compiler, nor the one that happened to build this CLI:
// the digest a project pins is only reproducible under the compiler that made
// it, and the project compiles this SDK, which is qualified with
// buildrecipe.PinnedToolchain. A local checkout given with --sdk-replace is
// asked first, since the project then compiles that tree.
func scaffoldToolchain(sdkReplace string) string {
	if sdkReplace != "" {
		if toolchain, err := buildrecipe.ResolveToolchain(sdkReplace); err == nil {
			return toolchain
		}
	}
	return buildrecipe.PinnedToolchain
}

func renderReadme(key string) string {
	return fmt.Sprintf(`# %s

Capability Package v1 project scaffolded by forgeops-cap init.

- capability.yaml — the canonical package identity (capability.v1 schema)
- main.go         — SDK-based safe-read implementation
- go.mod          — requires the ForgeOps SDK (github.com/ykdynamics/forgeops-sdk)
                    and pins the compiler its digests are reproducible with

Running locally proves the capability builds and answers. It grants nothing:
a customer's edge decides what may run there, and its owner approves.

## Develop

	forgeops-cap validate capability.yaml
	forgeops-cap run . --input '{"service":"acme"}'

## Publish

	forgeops-cap validate capability.yaml
	forgeops-cap package . --platform linux/arm64 --out packaged.yaml

--out writes the packaged capability.yaml. Add --key <pem> --publisher <name>
--register-out register.json to sign the canonical manifest and emit the
registry registration payload.

Packaging builds the implementation and pins its sha256 into
identity.artifactDigest. It builds for identity.implementationPlatform, or for
--platform when the document does not declare one, and it REFUSES when neither
is given: a digest is only meaningful beside the platform whose bytes it
describes, and a package built for whatever machine happened to run the command
cannot be verified on an edge. Declare identity.implementationPlatform in
capability.yaml once the execution platform is decided.

--allow-host-platform exists for a package that will only ever run where it was
built. It records the host platform in the document and is not a publishable
edge identity.
`, key)
}
