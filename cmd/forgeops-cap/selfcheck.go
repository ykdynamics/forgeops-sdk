package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

// cmdSelfcheck is the toolkit's self-check: it exercises the whole forgeops-cap
// journey on a throwaway sample in a temporary directory — scaffold → validate
// → package → run (+ sign when a key is given) — and reports each step, so a
// developer can see exactly where their installation breaks.
//
// It checks THIS TOOLKIT on THIS MACHINE, with its own sample. It does not
// check the developer's capability, and it says nothing about what a customer
// edge will allow: those are separate claims (ADR-010).
func cmdSelfcheck(args []string) error {
	fs := flag.NewFlagSet("selfcheck", flag.ExitOnError)
	key := fs.String("key", "", "optional P-256 publisher private key to also exercise signing")
	sdkVer := fs.String("sdk-version", sdkVersion(), "the forgeops-sdk release the sample requires (default: this CLI's own release)")
	sdkReplace := fs.String("sdk-replace", "", "build the sample against a local forgeops-sdk checkout instead of a release")
	_ = fs.Parse(args)

	work, err := os.MkdirTemp("", "forgeops-cap-selfcheck-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)
	dir := filepath.Join(work, "selfcheck-demo")

	initArgs := []string{"selfcheck.demo.status", "--dir", dir}
	if *sdkVer != "" {
		initArgs = append(initArgs, "--sdk-version", *sdkVer)
	}
	if *sdkReplace != "" {
		initArgs = append(initArgs, "--sdk-replace", *sdkReplace)
	}

	type step struct {
		name string
		fn   func() error
	}
	steps := []step{
		{"scaffold (init)", func() error { return cmdInit(initArgs) }},
		{"validate", func() error { return cmdValidate([]string{filepath.Join(dir, "capability.yaml")}) }},
		{"package (build + digest)", func() error {
			out := filepath.Join(work, "packaged.yaml")
			// --allow-host-platform: a local self-check runs its throwaway sample
			// on this machine, so host bytes are the honest answer here — which
			// is exactly why it has to be asked for, and why a production package
			// (signed, publishable, named in a manifest) cannot get them by accident.
			return cmdPackage([]string{dir, "--out", out, "--allow-host-platform"})
		}},
		{"run (local dev loop)", func() error {
			return cmdRun([]string{dir, "--input", `{"service":"acme"}`})
		}},
	}
	if *key != "" {
		registerOut := filepath.Join(work, "register.json")
		steps = append(steps, step{"sign (--key)", func() error {
			// The same explicit platform as the package step: signing packages
			// again, and packaging refuses an undeclared platform.
			return cmdPackage([]string{dir, "--allow-host-platform", "--key", *key, "--publisher", "selfcheck", "--register-out", registerOut})
		}}, step{"publish payload", func() error {
			if _, err := os.Stat(registerOut); err != nil {
				return fmt.Errorf("register payload missing after sign: %w", err)
			}
			fmt.Println("  register payload written with signature + fingerprint")
			return nil
		}})
	}

	failed := 0
	for _, s := range steps {
		fmt.Printf("[    ] %s\n", s.name)
		if err := s.fn(); err != nil {
			fmt.Printf("[FAIL] %s: %v\n", s.name, err)
			failed++
			continue
		}
		fmt.Printf("[PASS] %s\n", s.name)
	}
	if failed > 0 {
		return fmt.Errorf("selfcheck: %d/%d steps failed", failed, len(steps))
	}
	fmt.Printf("selfcheck: all %d steps passed — the forgeops-cap toolkit works on this machine (its own sample; your capability is not checked)\n", len(steps))
	return nil
}

// errNoProjectConformance answers `forgeops-cap conformance`. The name used to
// run the self-check, which reads as if it checked the developer's capability.
// Checking a project against the runtime contract is planned; until then the
// command says so instead of passing on a sample.
var errNoProjectConformance = fmt.Errorf("checking YOUR capability's conformance is not available yet; " +
	"`forgeops-cap selfcheck` checks this toolkit with its own sample, and `forgeops-cap run <dir>` runs your capability locally")
