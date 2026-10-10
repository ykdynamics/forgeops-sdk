package sdk

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/ykdynamics/forgeops-sdk/runtimecontract"
)

// RuntimeContractVersion is the version of the http-runtime request, callback
// and result contract this SDK speaks. The normative,
// language-neutral contract lives in runtimecontract (docs/runtime-contract-v1.md);
// this SDK is its reference implementation, so the version string is the same
// single value.
const RuntimeContractVersion = runtimecontract.Version

// Contract is a capability's exact, schema-declared input/output contract. It
// mirrors the input/output schemas of its capability.yaml at runtime so
// the SDK can reject invalid input before the implementation runs and prevent
// invalid output from crossing the boundary as success.
type Contract struct {
	// Version is this capability's contract version (manifest `version`).
	Version string
	// Risk is the declared policy class: "allow" | "ask" | "deny".
	Risk string
	// InputSchema / OutputSchema are JSON Schema documents (the SDK's subset).
	InputSchema  json.RawMessage
	OutputSchema json.RawMessage
	// IdempotencyKey is the required input field (dotted path) that mutation
	// capabilities use as their stable idempotency key.
	IdempotencyKey string
}

// ErrorClass classifies a structured run error (safe, structured errors). The
// class is a machine-readable string; the message is human-safe.
type ErrorClass string

const (
	// ClassInvalidInput: the caller supplied input that does not match the
	// declared input schema. The implementation was NOT invoked.
	ClassInvalidInput ErrorClass = "invalid_input"
	// ClassInvalidOutput: the implementation produced output that does not
	// match the declared output schema. The run fails — the invalid output
	// never crosses the boundary as success.
	ClassInvalidOutput ErrorClass = "invalid_output"
	// ClassTimeout: the implementation exceeded the run deadline and was
	// terminated.
	ClassTimeout ErrorClass = "timeout"
	// ClassDenied: the capability refuses by declaration (e.g. a deny stub).
	ClassDenied ErrorClass = "denied"
	// ClassRefused: the capability declines on AUTHORITY grounds — it was asked
	// to act outside what this deployment gave it. It is not a fault.
	//
	// The distinction is operational, not cosmetic. Before this existed, a
	// capability correctly refusing a target it was never given returned
	// `500 internal`, so:
	//
	//   - an operator watching error rates saw a boundary being ENFORCED as a
	//     spike in internal errors;
	//   - alerting could not separate "someone tried to cross an estate
	//     boundary" from "the capability is broken";
	//   - a retry policy could treat it as transient, because internal errors
	//     usually are. This one never will be.
	//
	// The three cases it covers are all "this deployment did not give me that",
	// never "something went wrong":
	//
	//   the target is not in the declared set
	//   the URL is not in the declared egress allowlist
	//   a required secret is not provisioned on this edge
	ClassRefused ErrorClass = "refused"
	// ClassInternal: any other implementation failure.
	ClassInternal ErrorClass = "internal"
)

// StructuredError is a safe, classed run error.
type StructuredError struct {
	Class   ErrorClass
	Message string
}

func (e *StructuredError) Error() string { return e.Message }

// NewError builds a structured error.
func NewError(class ErrorClass, format string, args ...any) error {
	return &StructuredError{Class: class, Message: fmt.Sprintf(format, args...)}
}

// Deadline returns the run's deadline, if the worker delivered one.
func (c *Context) Deadline() (time.Time, bool) {
	return c.deadline, !c.deadline.IsZero()
}

// RefuseUndeclaredTarget is the refusal for a target this deployment did not
// give the capability. `kind` names what the capability calls its targets
// ("machine", "gateway", "service") so the message reads in the capability's
// own vocabulary.
//
// A capability never chooses what it acts on: it resolves a NAME against a
// declared set, and anything else is refused here rather than guessed at.
func RefuseUndeclaredTarget(kind, name string) error {
	if name == "" {
		return NewError(ClassRefused, "%s name is required (the capability never chooses what to act on)", kind)
	}
	return NewError(ClassRefused, "%s %q is not a declared target on this deployment", kind, name)
}

// RefuseUndeclaredEgress is the refusal for a URL outside the declared egress
// allowlist. Reaching it would be the capability choosing its own network
// scope.
func RefuseUndeclaredEgress(url string) error {
	return NewError(ClassRefused, "URL %q is not in the declared egress allowlist", url)
}

// RefuseMissingSecret is the refusal for a customer-local credential this edge
// does not hold. The capability cannot substitute one, and the cloud must not:
// the absence is the answer.
func RefuseMissingSecret(name string) error {
	return NewError(ClassRefused, "the customer-local credential (%s) is not provisioned on this edge", name)
}
