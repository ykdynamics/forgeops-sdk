package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ykdynamics/forgeops-sdk/artifact"
	"github.com/ykdynamics/forgeops-sdk/buildrecipe"
	"github.com/ykdynamics/forgeops-sdk/capability"
	"github.com/ykdynamics/forgeops-sdk/internal/buildmeta"
	"github.com/ykdynamics/forgeops-sdk/internal/capsign"
)

// cmdPackage turns a dev capability project into an
// immutable, publishable Capability Package v1: it builds the implementation
// with the repository's ONE implementation recipe (internal/implbuild), pins
// the resulting sha256 into capability.yaml's identity.artifactDigest, and
// (with --key) signs the canonical manifest with the publisher's P-256 key —
// emitting exactly the register payload the platform registry consumes.
//
// The build used to be a bare local compiler call, which made this tool able to
// pin the HOST platform with the caller's compiler into identity.artifactDigest
// while the edge ran the platform-pinned recipe's bytes. Adoption compares the
// digest an installer observed against the digest the package declared, so that
// package could not be adopted truthfully. It now goes through the same builder
// the pin and artifact scripts use, so one recipe produces every implementation
// identity in this repo.
func cmdPackage(args []string) error {
	fs := flag.NewFlagSet("package", flag.ExitOnError)
	key := fs.String("key", "", "PEM PKCS8 P-256 publisher private key — signs the canonical manifest")
	publisher := fs.String("publisher", "", "publisher name (required with --key)")
	out := fs.String("out", "", "write the packaged capability.yaml here (default: rewrite in place)")
	registerOut := fs.String("register-out", "", "write the platform register payload JSON here")
	sbomOut := fs.String("sbom-out", "", "write supply-chain metadata here (sbom.json CycloneDX + provenance.json)")
	platformFlag := fs.String("platform", "", "execution platform to build for (e.g. linux/arm64); must match identity.implementationPlatform when the manifest declares one")
	allowHostPlatform := fs.Bool("allow-host-platform", false, "package for the host platform when the manifest declares none — for a local package that will only ever run where it was built")
	artifactOut := fs.String("artifact-out", "", "also write the EXACT built executable as a single-platform OCI image layout here (for forgeops-cap push)")
	dir, flagArgs := splitPositional(args)
	_ = fs.Parse(flagArgs)
	if dir == "" {
		return fmt.Errorf("package needs a project directory containing capability.yaml")
	}

	manifestPath := filepath.Join(dir, "capability.yaml")
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", manifestPath, err)
	}
	pkg, findings, err := capability.ValidateDocument(raw)
	if err != nil {
		return fmt.Errorf("capability.yaml is not a valid Capability Package: %w", err)
	}
	if len(findings) != 0 {
		return fmt.Errorf("capability.yaml does not conform: %v", findings)
	}

	// 1. Build the implementation with the shared recipe (internal/implbuild),
	// for the platform the package declares — never silently for the host.
	moduleRoot, err := buildrecipe.ModuleRoot(dir)
	if err != nil {
		return err
	}
	pattern, err := buildrecipe.PackagePattern(moduleRoot, dir)
	if err != nil {
		return err
	}
	buildPlatform, hostFallback, err := resolvePlatform(pkg.Identity.ImplementationPlatform, *platformFlag, *allowHostPlatform)
	if err != nil {
		return err
	}
	binDir, err := os.MkdirTemp("", "forgeops-cap-package-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(binDir)
	built, err := buildrecipe.Build(buildrecipe.Plan{
		Package:  pattern,
		Dir:      moduleRoot,
		Platform: buildPlatform,
		// The output path is not part of the identity: internal/implbuild
		// builds -trimpath, so the same source at two destination paths
		// produces the same digest. See TestOutputPathDoesNotChangeDigest.
		Output: filepath.Join(binDir, filepath.Base(dir)+"-impl"),
	})
	if err != nil {
		return err
	}

	// 2. Pin the ACTUAL artifact digest into the manifest (replacing the
	// scaffold placeholder), and record the platform that digest describes.
	artifactDigest := built.SHA256

	// 2b. Keep the bytes that were hashed: the OCI image carries exactly them,
	// never a rebuild, so the implementation digest and the image stay bound.
	var image *artifact.Image
	if *artifactOut != "" {
		if hostFallback {
			return fmt.Errorf("--artifact-out packages bytes for an edge; a host-platform package (--allow-host-platform) is not deliverable")
		}
		data, err := os.ReadFile(built.Path)
		if err != nil {
			return fmt.Errorf("read the built implementation: %w", err)
		}
		if artifact.Digest(data) != artifactDigest {
			return fmt.Errorf("the built implementation changed after it was hashed")
		}
		if image, err = artifact.Build([]artifact.File{{Name: pkg.Identity.Key, Data: data}}, buildPlatform.OS, buildPlatform.Arch); err != nil {
			return err
		}
		if err := artifact.WriteLayout(*artifactOut, image); err != nil {
			return fmt.Errorf("write the OCI layout: %w", err)
		}
	}
	packaged, err := setIdentity(raw, artifactDigest, buildPlatform.String())
	if err != nil {
		return err
	}
	if _, findings, err := capability.ValidateDocument(packaged); err != nil || len(findings) != 0 {
		return fmt.Errorf("packaged capability.yaml does not conform: %v %v", err, findings)
	}

	// 3. Sign the canonical manifest with the publisher's key.
	canonical, err := capability.CanonicalJSON(packaged)
	if err != nil {
		return fmt.Errorf("canonicalize manifest: %w", err)
	}
	register := map[string]any{
		"capability_key": pkg.Identity.Key,
		"version":        pkg.Identity.Version,
		"publisher":      *publisher,
		"manifest":       json.RawMessage(packaged),
	}
	signed := false
	if *key != "" {
		if *publisher == "" {
			return fmt.Errorf("--publisher is required when signing with --key")
		}
		keyPEM, err := os.ReadFile(*key)
		if err != nil {
			return fmt.Errorf("read key: %w", err)
		}
		signature, err := capsign.Sign(keyPEM, canonical)
		if err != nil {
			return fmt.Errorf("sign: %w", err)
		}
		pubPEM, err := capsign.PublicKeyOf(keyPEM)
		if err != nil {
			return err
		}
		fingerprint, err := capsign.Fingerprint(pubPEM)
		if err != nil {
			return err
		}
		register["signature"] = signature
		register["key_fingerprint"] = fingerprint
		signed = true
	}

	// 4. Supply-chain metadata: a CycloneDX SBOM of the Go modules
	// the implementation is built from + a provenance statement binding the
	// immutable package to the build.
	if *sbomOut != "" {
		if err := writeBuildMetadata(*sbomOut, dir, canonical, artifactDigest, *publisher); err != nil {
			return err
		}
	}

	// 4. Emit the outputs.
	if *out == "" {
		*out = manifestPath
	}
	if err := os.WriteFile(*out, packaged, 0o644); err != nil {
		return fmt.Errorf("write packaged capability.yaml: %w", err)
	}
	fmt.Printf("packaged %s@%s\n", pkg.Identity.Key, pkg.Identity.Version)
	fmt.Printf("  artifact digest: %s\n", artifactDigest)
	fmt.Printf("  built for: %s with %s\n", buildPlatform, built.Toolchain)
	if image != nil {
		fmt.Printf("  OCI image: %s (manifest %s, carrying %s as %q)\n", *artifactOut, image.ManifestDigest, artifactDigest, pkg.Identity.Key)
		fmt.Println("  push it with: forgeops-cap push " + *artifactOut + " --repo <registry>/<path>")
	}
	if hostFallback {
		fmt.Printf("  host-platform identity: --allow-host-platform was given and capability.yaml declares no identity.implementationPlatform,\n")
		fmt.Printf("                          so this pin describes HOST bytes (%s) and must not be published as an edge package.\n", buildPlatform)
	}
	if signed {
		registerJSON, _ := json.MarshalIndent(register, "", "  ")
		if *registerOut != "" {
			if err := os.WriteFile(*registerOut, registerJSON, 0o600); err != nil {
				return fmt.Errorf("write register payload: %w", err)
			}
			fmt.Printf("  register payload: %s\n", *registerOut)
		} else {
			fmt.Printf("  register payload:\n%s\n", registerJSON)
		}
		fmt.Println("  register the publisher's PUBLIC key with the registry (fingerprint above), then POST the payload.")
	} else {
		fmt.Println("  unsigned (pass --key to sign for registry publication)")
	}
	return nil
}

// writeBuildMetadata generates + writes the CycloneDX SBOM and provenance
// statement for a packaged capability into dir.
func writeBuildMetadata(dir, projectDir string, canonicalManifest []byte, artifactDigest string, publisher string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create sbom dir: %w", err)
	}
	sbom, err := buildmeta.GoModulesSBOM(projectDir)
	if err != nil {
		return fmt.Errorf("generate sbom: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sbom.json"), sbom, 0o644); err != nil {
		return err
	}
	sum := sha256.Sum256(canonicalManifest)
	manifestDigest := "sha256:" + hex.EncodeToString(sum[:])
	builder := "https://forgeops.dev/forgeops-cap"
	if publisher != "" {
		builder += "?publisher=" + publisher
	}
	prov, err := buildmeta.Provenance(manifestDigest, artifactDigest, builder)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "provenance.json"), prov, 0o644); err != nil {
		return err
	}
	fmt.Printf("  sbom/provenance: %s (sbom.json, provenance.json)\n", dir)
	return nil
}

// resolvePlatform settles which platform the implementation is built for.
//
// identity.implementationPlatform is the package's DECLARED execution platform
// and is therefore authoritative: a package that says linux/arm64 is built for
// linux/arm64. A --platform flag may supply a MISSING declaration, and may
// repeat the declared one, but must never contradict it — silently overriding
// would point the digest at bytes for a platform the package does not claim,
// which is exactly the defect that made a Mac's darwin digest describable as a
// linux edge's implementation identity.
//
// With no declaration and no flag, packaging is REFUSED. This command's whole
// purpose is to produce a signed, publishable, immutable identity, and a
// warning printed next to it would still leave that identity dependent on where
// somebody happened to run the command. `forgeops-cap run` already owns the
// local host-development case; a package that will only ever run where it was
// built has to say so out loud, with --allow-host-platform, and the platform is
// recorded in the packaged document so the pin is never ambiguous.
func resolvePlatform(declared, flagValue string, allowHostPlatform bool) (buildrecipe.Platform, bool, error) {
	if declared != "" {
		p, err := buildrecipe.ParsePlatform(declared)
		if err != nil {
			return buildrecipe.Platform{}, false, fmt.Errorf("identity.implementationPlatform is not a usable platform: %w", err)
		}
		if flagValue != "" {
			flagPlatform, err := buildrecipe.ParsePlatform(flagValue)
			if err != nil {
				return buildrecipe.Platform{}, false, err
			}
			if flagPlatform != p {
				return buildrecipe.Platform{}, false, fmt.Errorf("--platform %s contradicts identity.implementationPlatform %s: the manifest declares the platform its digest describes", flagValue, declared)
			}
		}
		return p, false, nil
	}
	if flagValue != "" {
		p, err := buildrecipe.ParsePlatform(flagValue)
		if err != nil {
			return buildrecipe.Platform{}, false, err
		}
		return p, false, nil
	}
	if !allowHostPlatform {
		return buildrecipe.Platform{}, false, fmt.Errorf("no platform to build for: capability.yaml declares no identity.implementationPlatform and --platform was not given. An implementation digest is only meaningful beside the platform whose bytes it describes; declare identity.implementationPlatform, pass --platform <os>/<arch>, or pass --allow-host-platform for a package that will only ever run where it was built")
	}
	return buildrecipe.HostPlatform(), true, nil
}

// setIdentity rewrites identity.artifactDigest and identity.implementationPlatform
// in a capability.v1 document, preserving everything else.
//
// The platform is written beside the digest rather than left implicit: the
// digest is only meaningful side by side with the platform whose bytes it
// describes, and legacy registry manifests already record
// implementation_platform for exactly this reason.
func setIdentity(raw []byte, digest, platform string) ([]byte, error) {
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		// YAML-authored manifests: normalize via the shared canonicalizer.
		canonical, cerr := capability.CanonicalJSON(raw)
		if cerr != nil {
			return nil, fmt.Errorf("manifest is not valid YAML/JSON: %w", err)
		}
		if err := json.Unmarshal(canonical, &doc); err != nil {
			return nil, err
		}
	}
	id, ok := doc["identity"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("manifest has no identity object")
	}
	id["artifactDigest"] = digest
	id["implementationPlatform"] = platform
	out, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	return out, nil
}
