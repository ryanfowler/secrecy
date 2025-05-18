package secrecy

import "encoding/json"

const (
	redacted   = "[redacted]"
	redactedGo = `Secret{` + redacted + `}`
)

var (
	redactedBytes   = []byte(redacted)
	redactedGoBytes = []byte(redactedGo)
	redactedJSON    = []byte(`"` + redacted + `"`)
)

// Secret wraps a sensitive value to prevent it from being inadvertently leaked.
// To retrieve the underlying value, the Expose method must be called.
type Secret[T any] struct {
	value T
}

// New returns a new Secret that wraps the provided value.
func New[T any](value T) Secret[T] {
	return Secret[T]{value: value}
}

// Expose returns the underlying secret value.
func (s Secret[T]) Expose() T {
	return s.value
}

// String implements the Stinger interface.
func (s Secret[T]) String() string {
	return redacted
}

// GoString implements the GoStringer interface.
func (s Secret[T]) GoString() string {
	return redactedGo
}

// MarshalText implements the TextMarshaler interface.
func (s Secret[T]) MarshalText() ([]byte, error) {
	return redactedBytes, nil
}

// MarshalJSON implements the json.Marshaler interface.
func (s Secret[T]) MarshalJSON() ([]byte, error) {
	return redactedJSON, nil
}

// UnmarshalJSON implements the json.Unmarshaler interface.
func (s *Secret[T]) UnmarshalJSON(data []byte) error {
	return json.Unmarshal(data, &s.value)
}

// GobEncode implements the GobEncoder interface.
func (s Secret[T]) GobEncode() ([]byte, error) {
	return redactedBytes, nil
}

// MarshalYAML implements the yaml.Marshaler interface.
func (s Secret[T]) MarshalYAML() (any, error) {
	return redacted, nil
}

// MarshalTOML implements the toml.Marshaler interface.
func (s Secret[T]) MarshalTOML() ([]byte, error) {
	return redactedBytes, nil
}
