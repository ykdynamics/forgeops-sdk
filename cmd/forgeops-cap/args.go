package main

import (
	"strings"
)

// splitPositional separates a command's single positional argument from its
// flags, so `forgeops-cap run . --input '{...}'` and
// `forgeops-cap run --input '{...}' .` both work (Go's flag package stops at
// the first non-flag token).
func splitPositional(args []string) (positional string, flagArgs []string) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "-") {
			flagArgs = append(flagArgs, a)
			// A flag value that is not `--flag=value` is the next token.
			if !strings.Contains(a, "=") && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				i++
				flagArgs = append(flagArgs, args[i])
			}
			continue
		}
		if positional == "" {
			positional = a
			continue
		}
		// More than one positional is an error; keep it in flagArgs so the
		// flag package reports it (NArg check catches the remainder).
		flagArgs = append(flagArgs, a)
	}
	return positional, flagArgs
}
