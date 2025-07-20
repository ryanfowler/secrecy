// Package secrecy provides helpers for handling sensitive values. When wrapped
// in a Secret, the original value will never be printed or encoded unless it is
// explicitly exposed with the Expose method.
package secrecy

import (
	"encoding/json"
	"reflect"
	"runtime"
)

var (
	redacted      string
	redactedGo    string
	redactedBytes []byte
	redactedJSON  []byte
)

func init() {
	SetRedactedString("[REDACTED]")
}

// SetRedactedString sets the global value used when a secret is formatted or
// encoded. It should be called during program initialization, before any
// Secrets are created. By default the string is "[REDACTED]".
func SetRedactedString(s string) {
	redacted = s
	redactedGo = `Secret{` + redacted + `}`
	redactedBytes = []byte(redacted)
	redactedJSON, _ = json.Marshal(redacted)
}

// Secret wraps a sensitive value to prevent it from being inadvertently leaked
// through logging, formatting, or other encoding mechanisms.
// To retrieve the underlying value, the Expose method must be called.
type Secret[T any] struct {
	value T
}

// New returns a new Secret that wraps the provided value.
//
//	password := secrecy.New("p@ssword")
//	fmt.Println(password) // prints [REDACTED]
func New[T any](value T) Secret[T] {
	return Secret[T]{value: value}
}

// NewZeroizing returns a pointer to a Secret that wraps the provided value and
// automatically zeroes it when the Secret is garbage collected. The value
// should not be accessed or modified outside of the returned Secret.
//
//	token := secrecy.NewZeroizing([]byte("key"))
func NewZeroizing[T any](value T) *Secret[T] {
	s := &Secret[T]{value: value}
	runtime.AddCleanup(s, func(t *T) { Zeroize(t) }, &value)
	return s
}

// Expose returns the underlying secret value. This is the only way to
// retrieve the wrapped data.
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
	return redactedJSON, nil
}

// Zero runs the Zeroize function on the underlying secret value. After calling
// Zero, Expose will return the zero value for type T.
func (s *Secret[T]) Zero() {
	Zeroize(&s.value)
}

// Zeroize recursively zeroes the provided value in place when possible. It
// traverses slices, maps and structs, clearing every reachable element. Private
// struct fields are skipped as they cannot be modified via reflection.
func Zeroize(value any) {
	zeroize(reflect.ValueOf(value), 0)
}

func zeroize(v reflect.Value, n int) {
	// Stop recursion if invalid, nil, or too deep.
	if !v.IsValid() || v.IsZero() || n > 100 {
		return
	}
	n++

	// Unwrap interfaces and pointers.
	if v.Kind() == reflect.Interface || v.Kind() == reflect.Ptr {
		v = v.Elem()
		if !v.IsValid() || v.IsZero() {
			return
		}
	}

	switch v.Kind() {
	case reflect.Interface, reflect.Ptr:
		if !v.IsNil() {
			zeroize(v, n+1)
		}
	case reflect.Array, reflect.Slice:
		// Fast path for when value is a []byte.
		if v.Type().Elem().Kind() == reflect.Uint8 {
			b := v.Bytes()
			for i := range b {
				b[i] = 0
			}
		} else {
			for i := range v.Len() {
				zeroize(v.Index(i).Addr(), n+1)
			}
		}
	case reflect.Map:
		iter := v.MapRange()
		for iter.Next() {
			val := iter.Value()
			if val.Kind() == reflect.Ptr || val.Kind() == reflect.Interface {
				zeroize(val, n+1)
			}
		}
		v.Clear()
	case reflect.Struct:
		t := v.Type()
		for i := range t.NumField() {
			field := v.Field(i)
			if field.CanAddr() && v.Type().Field(i).IsExported() {
				zeroize(field.Addr(), n+1)
			}
		}
	}

	if v.CanSet() {
		v.SetZero()
	}
}
