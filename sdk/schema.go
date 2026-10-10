package sdk

import (
	"encoding/json"
	"fmt"
)

// validateSchema validates value against a JSON Schema. It implements the
// subset capability manifests use: type, required,
// properties, items, additionalProperties, enum and const. Everything else is
// ignored (validation is best-effort structural — it never rejects a value
// that the declared contract did not describe).
func validateSchema(schema json.RawMessage, value any) error {
	if len(schema) == 0 || string(schema) == "null" {
		return nil
	}
	var s map[string]any
	if err := json.Unmarshal(schema, &s); err != nil {
		return fmt.Errorf("invalid schema: %w", err)
	}
	return validateSchemaValue(s, value, "$")
}

func validateSchemaValue(s map[string]any, value any, path string) error {
	// Type.
	if t, ok := s["type"].(string); ok {
		if err := checkType(t, value, path); err != nil {
			return err
		}
	}
	// const — exact equality.
	if c, ok := s["const"]; ok {
		if !jsonEqual(c, value) {
			return fmt.Errorf("%s: value %v does not equal const %v", path, value, c)
		}
	}
	// enum.
	if e, ok := s["enum"].([]any); ok {
		matched := false
		for _, allowed := range e {
			if jsonEqual(allowed, value) {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("%s: value %v is not one of %v", path, value, e)
		}
	}
	// Object shape.
	if obj, ok := value.(map[string]any); ok {
		props, _ := s["properties"].(map[string]any)
		for _, name := range stringList(s["required"]) {
			if _, present := obj[name]; !present {
				return fmt.Errorf("%s: missing required property %q", path, name)
			}
		}
		for name, v := range obj {
			child, declared := props[name]
			if !declared {
				if add, ok := s["additionalProperties"].(bool); ok && !add {
					return fmt.Errorf("%s: undeclared property %q (additionalProperties=false)", path, name)
				}
				continue
			}
			if child == nil {
				continue
			}
			childSchema, ok := child.(map[string]any)
			if !ok {
				continue
			}
			if err := validateSchemaValue(childSchema, v, path+"."+name); err != nil {
				return err
			}
		}
	}
	// Array items.
	if arr, ok := value.([]any); ok {
		if items, ok := s["items"].(map[string]any); ok {
			for i, v := range arr {
				if err := validateSchemaValue(items, v, fmt.Sprintf("%s[%d]", path, i)); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func checkType(t string, value any, path string) error {
	ok := false
	switch t {
	case "string":
		_, ok = value.(string)
	case "number":
		_, ok = value.(float64)
	case "integer":
		f, isF := value.(float64)
		ok = isF && f == float64(int64(f))
	case "boolean":
		_, ok = value.(bool)
	case "object":
		_, ok = value.(map[string]any)
	case "array":
		_, ok = value.([]any)
	}
	if !ok {
		return fmt.Errorf("%s: expected type %q, got %T", path, t, value)
	}
	return nil
}

func stringList(v any) []string {
	raw, _ := v.([]any)
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// jsonEqual compares two JSON values structurally (numbers by numeric value).
func jsonEqual(a, b any) bool {
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	return string(ja) == string(jb)
}
