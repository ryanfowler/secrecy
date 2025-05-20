package secrecy

import (
	"encoding/json"
	"reflect"
	"runtime"
)

const (
	redacted   = "[redacted]"
	redactedGo = `Secret{` + redacted + `}`
)

var (
	redactedBytes = []byte(redacted)
	redactedJSON  = []byte(`"` + redacted + `"`)
)

// Secret wraps a sensitive value to prevent it from being inadvertently leaked
// through logging, formatting, or other encoding mechanisms.
// To retrieve the underlying value, the Expose method must be called.
type Secret[T any] struct {
	value T
}

// New returns a new Secret that wraps the provided value.
func New[T any](value T) Secret[T] {
	return Secret[T]{value: value}
}

// NewZeroizing returns a new Secret that wraps the provided value, and will
// "zero" the value when the Secret gets garbage collected. Please see the
// documentation for the Zeroize function for how values are zeroed. The
// provided value should not be accessed or modified outside of the scope of the
// returned Secret.
func NewZeroizing[T any](value T) *Secret[T] {
	s := &Secret[T]{value: value}
	runtime.AddCleanup(s, func(v T) { Zeroize(v) }, value)
	return s
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

// Zeroize deep "zeros" the provided value, if mutable. It traverses slices,
// maps, and struct fields as necessary to deep zero all child elements. Please
// note that although structs are fully zeroed, private struct fields cannot
// be deep zeroed.
func Zeroize(value any) {
	if value == nil {
		return
	}

	// Fast path for when value is a []byte.
	if b, ok := value.([]byte); ok {
		for i := range b {
			b[i] = 0
		}
		return
	}

	// Unwrap interfaces and pointers.
	v := reflect.ValueOf(value)
	if v.Kind() == reflect.Interface || v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	if v.IsZero() {
		return
	}

	switch v.Kind() {
	case reflect.Interface, reflect.Ptr:
		if !v.IsNil() {
			Zeroize(v.Interface())
		}
	case reflect.Array, reflect.Slice:
		for i := range v.Len() {
			index := v.Index(i)
			Zeroize(index.Interface())
			if index.CanSet() {
				index.Set(reflect.Zero(index.Type()))
			}
		}
	case reflect.Map:
		iter := v.MapRange()
		for iter.Next() {
			key := iter.Key()
			value := iter.Value()
			v.SetMapIndex(key, reflect.Value{})
			Zeroize(key.Interface())
			Zeroize(value.Interface())
		}
	case reflect.Struct:
		t := v.Type()
		for i := range t.NumField() {
			if t.Field(i).IsExported() {
				Zeroize(v.Field(i).Interface())
			}
		}
	}

	if v.CanSet() {
		v.SetZero()
	}
}
