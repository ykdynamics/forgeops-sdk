package capability

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/ykdynamics/forgeops-sdk/internal/jsonschema"
)

// ErrNoRequesterOutput: the package proposes no requester-facing output
// (contract.requesterOutputSchema is absent), so a requester receives the
// status and no result.
var ErrNoRequesterOutput = errors.New("the package proposes no requester-facing output")

// ErrRequesterOutputInvalid: the result does not satisfy the declared
// requester-facing output, so nothing of it is disclosed.
var ErrRequesterOutputInvalid = errors.New("the result does not match the declared requester-facing output")

// ProjectRequesterOutput returns what of a capability's result may be
// disclosed to the requester under this package's declaration: exactly the
// properties contract.requesterOutputSchema names, taken from the result
// object, validated against that schema, as canonical JSON. Anything else in
// the result -- other properties, diagnostics -- is dropped, never passed on.
//
// It fails closed: no declaration, a result that is not a JSON object, or a
// projection that does not validate yields an error and no output. Whether
// the projection is disclosed at all is the customer's decision, made when
// binding this exact package; this function only says WHAT would be.
//
// It is the one implementation a platform and forgeops-cap conformance share,
// so an author's conformance run checks exactly what will be enforced.
func ProjectRequesterOutput(p *Package, result json.RawMessage) (json.RawMessage, error) {
	if p == nil || len(p.Contract.RequesterOutputSchema) == 0 {
		return nil, ErrNoRequesterOutput
	}
	var schema struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(p.Contract.RequesterOutputSchema, &schema); err != nil || len(schema.Properties) == 0 {
		return nil, fmt.Errorf("%w: the declaration names no properties", ErrRequesterOutputInvalid)
	}
	var full map[string]json.RawMessage
	if err := json.Unmarshal(result, &full); err != nil || full == nil {
		return nil, fmt.Errorf("%w: the result is not a JSON object", ErrRequesterOutputInvalid)
	}
	// The result must first honour the package's own output contract: a
	// result outside outputSchema is not this package's answer, and nothing of
	// it is disclosed.
	var whole any
	if err := json.Unmarshal(result, &whole); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRequesterOutputInvalid, err)
	}
	if err := jsonschema.Validate(p.Contract.OutputSchema, whole); err != nil {
		return nil, fmt.Errorf("%w: the result does not match outputSchema: %v", ErrRequesterOutputInvalid, err)
	}
	names := make([]string, 0, len(schema.Properties))
	for name := range schema.Properties {
		names = append(names, name)
	}
	sort.Strings(names)
	projected := make(map[string]json.RawMessage, len(names))
	for _, name := range names {
		v, ok := full[name]
		if !ok {
			continue
		}
		// One level deep, scalars only (the declaration is validated to say
		// so): an object here would carry fields nobody declared.
		if containsObject(v) {
			return nil, fmt.Errorf("%w: %q holds a nested object, which requester output does not carry", ErrRequesterOutputInvalid, name)
		}
		projected[name] = v
	}
	raw, err := json.Marshal(projected) // map keys marshal sorted: canonical
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRequesterOutputInvalid, err)
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRequesterOutputInvalid, err)
	}
	if err := jsonschema.Validate(p.Contract.RequesterOutputSchema, value); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRequesterOutputInvalid, err)
	}
	return raw, nil
}

// containsObject reports whether a JSON value is, or contains, an object.
func containsObject(raw json.RawMessage) bool {
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return true
	}
	switch t := v.(type) {
	case map[string]any:
		return true
	case []any:
		for _, e := range t {
			if _, ok := e.(map[string]any); ok {
				return true
			}
			if _, ok := e.([]any); ok {
				return true
			}
		}
	}
	return false
}
