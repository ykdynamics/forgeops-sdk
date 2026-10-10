package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/ykdynamics/forgeops-sdk/capability"
)

// cmdValidate validates a capability.yaml against the R5.1 canonical schema
// with deterministic, actionable errors.
func cmdValidate(args []string) error {
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	path, flagArgs := splitPositional(args)
	_ = fs.Parse(flagArgs)
	if path == "" {
		return fmt.Errorf("validate needs a capability.yaml path")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	pkg, errs, err := capability.ValidateDocument(data)
	if err != nil {
		return fmt.Errorf("%s is not a valid Capability Package: %w", path, err)
	}
	if len(errs) == 0 {
		fmt.Printf("OK: %s (%s) conforms to schemaVersion %s\n", pkg.Identity.Key, pkg.Identity.Version, capability.SchemaVersion)
		return nil
	}
	fmt.Printf("%s does not conform to %s (%d finding(s)):\n", path, capability.SchemaVersion, len(errs))
	for _, e := range errs {
		field := e.Field
		if field == "" {
			field = "(document)"
		}
		fmt.Printf("  - %s: %s\n", field, e.Message)
	}
	return fmt.Errorf("validation failed")
}
