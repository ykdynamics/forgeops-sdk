package sdk

import (
	"encoding/json"

	"github.com/ykdynamics/forgeops-sdk/internal/jsonschema"
)

// validateSchema validates value against a capability's declared JSON Schema,
// with the same checker forgeops-cap conformance uses.
func validateSchema(schema json.RawMessage, value any) error {
	return jsonschema.Validate(schema, value)
}
