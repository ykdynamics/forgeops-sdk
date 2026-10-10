package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/ykdynamics/forgeops-sdk/artifact"
	"github.com/ykdynamics/forgeops-sdk/buildrecipe"
	"github.com/ykdynamics/forgeops-sdk/capability"
)

// registryFlags are the flags push and pull share. The password is read from
// an environment variable, never from the command line, where other users of
// the machine could see it.
type registryFlags struct {
	repo, user, passwordEnv *string
	plainHTTP               *bool
}

func addRegistryFlags(fs *flag.FlagSet) registryFlags {
	return registryFlags{
		repo:        fs.String("repo", "", "registry repository: host[:port]/path"),
		user:        fs.String("user", "", "registry user (anonymous when empty)"),
		passwordEnv: fs.String("password-env", "FORGEOPS_REGISTRY_PASSWORD", "environment variable holding the registry password or token"),
		plainHTTP:   fs.Bool("plain-http", false, "talk to the registry over plain HTTP (a local test registry only)"),
	}
}

func (f registryFlags) client() (*artifact.Client, error) {
	repo, err := artifact.ParseRepository(*f.repo)
	if err != nil {
		return nil, err
	}
	if *f.plainHTTP {
		repo.Scheme = "http"
	}
	return &artifact.Client{Repo: repo, Creds: artifact.Credentials{User: *f.user, Password: os.Getenv(*f.passwordEnv)}}, nil
}

// cmdPush pushes an OCI layout written by `package --artifact-out` and prints
// the manifest digest: the identity an install pulls by.
func cmdPush(args []string) error {
	fs := flag.NewFlagSet("push", flag.ExitOnError)
	reg := addRegistryFlags(fs)
	tag := fs.String("tag", "", "also tag the image (a convenience for people; installs pull by digest)")
	dir, flagArgs := splitPositional(args)
	_ = fs.Parse(flagArgs)
	if dir == "" {
		return fmt.Errorf("push needs the OCI layout directory written by package --artifact-out")
	}
	img, err := artifact.ReadLayout(dir)
	if err != nil {
		return err
	}
	client, err := reg.client()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	digest, err := client.Push(ctx, img, *tag)
	if err != nil {
		return err
	}
	fmt.Printf("pushed %s@%s\n", client.Repo, digest)
	fmt.Println("  an install pulls it by this digest, and checks every file against the package's identity.artifactDigest")
	return nil
}

// cmdPull fetches an image by digest, verifies it against a packaged
// capability.yaml (its key names the file, identity.artifactDigest pins it,
// identity.implementationPlatform names the platform), and installs it into
// --out only when everything checked. A refused pull leaves --out as it was.
func cmdPull(args []string) error {
	fs := flag.NewFlagSet("pull", flag.ExitOnError)
	reg := addRegistryFlags(fs)
	digest := fs.String("digest", "", "the image's manifest digest (sha256:…); tags are never used")
	packaged := fs.String("package", "", "the packaged capability.yaml whose implementation this image must carry")
	out := fs.String("out", "", "directory to install the verified implementation into")
	_ = fs.Parse(args)
	if *packaged == "" || *out == "" {
		return fmt.Errorf("pull needs --package <packaged capability.yaml> and --out <dir>")
	}
	raw, err := os.ReadFile(*packaged)
	if err != nil {
		return err
	}
	pkg, findings, err := capability.ValidateDocument(raw)
	if err != nil || len(findings) != 0 {
		return fmt.Errorf("%s is not a valid capability.v1 package: %v %v", *packaged, err, findings)
	}
	platform, err := buildrecipe.ParsePlatform(pkg.Identity.ImplementationPlatform)
	if err != nil {
		return fmt.Errorf("%s declares no usable identity.implementationPlatform: %w", *packaged, err)
	}
	client, err := reg.client()
	if err != nil {
		return err
	}
	expect := artifact.Expect{OS: platform.OS, Arch: platform.Arch, Pins: map[string]string{pkg.Identity.Key: pkg.Identity.ArtifactDigest}}

	// Stage beside --out, so the final step is a rename on one filesystem.
	parent := filepath.Dir(filepath.Clean(*out))
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return err
	}
	staging := filepath.Join(parent, fmt.Sprintf(".%s.staging-%d", filepath.Base(*out), os.Getpid()))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	if _, err := client.Pull(ctx, *digest, expect, staging); err != nil {
		return fmt.Errorf("refused, nothing installed: %w", err)
	}
	if err := promote(staging, *out); err != nil {
		os.RemoveAll(staging)
		return err
	}
	fmt.Printf("installed %s@%s into %s\n", pkg.Identity.Key, pkg.Identity.Version, *out)
	fmt.Printf("  from %s@%s, %s verified against identity.artifactDigest %s\n", client.Repo, *digest, platform, pkg.Identity.ArtifactDigest)
	return nil
}

// promote replaces dir with staging: the previous content is moved aside and
// removed only after the new one is in place.
func promote(staging, dir string) error {
	previous := ""
	if _, err := os.Stat(dir); err == nil {
		previous = fmt.Sprintf("%s.previous-%d", dir, os.Getpid())
		if err := os.Rename(dir, previous); err != nil {
			return err
		}
	}
	if err := os.Rename(staging, dir); err != nil {
		if previous != "" {
			_ = os.Rename(previous, dir)
		}
		return err
	}
	if previous != "" {
		return os.RemoveAll(previous)
	}
	return nil
}
