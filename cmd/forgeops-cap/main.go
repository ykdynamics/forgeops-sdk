// Command forgeops-cap is the ForgeOps capability developer CLI: scaffold,
// validate, run locally and package a Capability Package v1 project.
//
//	forgeops-cap init acme.service.status [--dir ./acme-status]   scaffold a safe-read capability
//	forgeops-cap validate ./acme-status/capability.yaml           validate against the capability.v1 schema
//	forgeops-cap run ./acme-status --input '{"service":"acme"}'   local dev loop (build + run + sample input)
//
// The generated project validates against the canonical schema in capability/
// and serves the SDK's runtime contract (runtime.v1). Local success means the
// capability builds and answers; it grants nothing: a customer's edge decides
// what runs there.
package main

import (
	"fmt"
	"os"
)

func usage() {
	fmt.Fprintln(os.Stderr, `usage: forgeops-cap <command> [args]

commands:
  init <key>          scaffold a safe-read Capability Package v1 project
                      (--dir <dir>; --sdk-version vX.Y.Z, default this CLI's release;
                      --sdk-replace <path> builds against a local forgeops-sdk checkout)
  validate <file>     validate a capability.yaml against the capability.v1 schema
  run <dir>           build + run the capability and execute a sample input
                      (--input <json>, --addr <host:port>)
  package <dir>       build + pin the real artifact digest + (--key) sign
                      (--key <pem> --publisher <name> --register-out <file>)
                      builds for identity.implementationPlatform; --platform
                      <os>/<arch> supplies it when the manifest omits it, and
                      packaging is refused if neither is given
                      (--allow-host-platform opts into host bytes explicitly)
  publish-key         register the publisher P-256 public key with the registry
                      (<pub.pem> --registry <url> --token <jwt> --publisher <name>)
  publish             post a register payload to the registry
                      (<register.json> --registry <url> --token <jwt>)
  selfcheck           check this toolkit on this machine with its own sample
                      (scaffold -> validate -> package -> run; --key adds sign).
                      It does not check your capability.
  version             print the CLI's release`)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "init":
		if err := cmdInit(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "forgeops-cap init:", err)
			os.Exit(1)
		}
	case "validate":
		if err := cmdValidate(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "forgeops-cap validate:", err)
			os.Exit(1)
		}
	case "run":
		if err := cmdRun(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "forgeops-cap run:", err)
			os.Exit(1)
		}
	case "package":
		if err := cmdPackage(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "forgeops-cap package:", err)
			os.Exit(1)
		}
	case "publish":
		if err := cmdPublish(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "forgeops-cap publish:", err)
			os.Exit(1)
		}
	case "publish-key":
		if err := cmdPublishKey(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "forgeops-cap publish-key:", err)
			os.Exit(1)
		}
	case "selfcheck":
		if err := cmdSelfcheck(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "forgeops-cap selfcheck:", err)
			os.Exit(1)
		}
	case "conformance":
		fmt.Fprintln(os.Stderr, "forgeops-cap conformance:", errNoProjectConformance)
		os.Exit(2)
	case "version", "--version", "-v":
		if v := sdkVersion(); v != "" {
			fmt.Println("forgeops-cap", v)
		} else {
			fmt.Println("forgeops-cap (built from source, no release version)")
		}
	case "help", "--help", "-h":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "forgeops-cap: unknown command %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}
