package secrecy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"runtime"
	"testing"
)

func TestSecret_String(t *testing.T) {
	s := New("supersecret")
	if got := s.String(); got != redacted {
		t.Errorf("String() = %q, want %q", got, redacted)
	}
}

func TestSecret_GoString(t *testing.T) {
	s := New("supersecret")
	if got := s.GoString(); got != redactedGo {
		t.Errorf("GoString() = %q, want %q", got, redactedGo)
	}
}

func TestSecret_MarshalText(t *testing.T) {
	s := New("supersecret")
	b, err := s.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText() error = %v", err)
	}
	if !bytes.Equal(b, redactedBytes) {
		t.Errorf("MarshalText() = %q, want %q", b, redactedBytes)
	}
}

func TestSecret_MarshalJSON(t *testing.T) {
	s := New("supersecret")
	b, err := s.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON() error = %v", err)
	}
	if !bytes.Equal(b, redactedJSON) {
		t.Errorf("MarshalJSON() = %q, want %q", b, redactedJSON)
	}
}

func TestSecret_UnmarshalJSON(t *testing.T) {
	var s Secret[string]
	input := `"supersecret"`
	if err := json.Unmarshal([]byte(input), &s); err != nil {
		t.Fatalf("UnmarshalJSON() error = %v", err)
	}
	if got := s.Expose(); got != "supersecret" {
		t.Errorf("Expose() = %q, want %q", got, "supersecret")
	}
}

func TestSecret_Expose(t *testing.T) {
	val := "supersecret"
	s := New(val)
	if got := s.Expose(); got != val {
		t.Errorf("Expose() = %q, want %q", got, val)
	}
}

func TestSecret_Format(t *testing.T) {
	s := New("supersecret")
	if got := fmt.Sprintf("v = %s", s); got != "v = "+redacted {
		t.Errorf("Format %%s = %q, want %q", got, redacted)
	}
	if got := fmt.Sprintf("%q", s); got != fmt.Sprintf("%q", redacted) {
		t.Errorf("Format %%q = %q, want %q", got, redacted)
	}
	if got := fmt.Sprintf("%v", s); got != redacted {
		t.Errorf("Format %%v = %q, want %q", got, redacted)
	}
	if got := fmt.Sprintf("%#v", s); got != redactedGo {
		t.Errorf("Format %%#v = %q, want %q", got, redactedGo)
	}
	if got := fmt.Sprintf("%+v", s); got != redacted {
		t.Errorf("Format %%+v = %q, want %q", got, redacted)
	}
	if got := fmt.Sprintf("%x", s); got != "5b52454441435445445d" {
		t.Errorf("Format %%x = %q, want %q", got, "5b52454441435445445d")
	}
	if got := fmt.Sprintf("%T", s); got != "secrecy.Secret[string]" {
		t.Errorf("Format %%T = %q, want %q", got, "secrecy.Secret[string]")
	}
}

func TestSecret_GobEncode(t *testing.T) {
	s := New("supersecret")
	b, err := s.GobEncode()
	if err != nil {
		t.Fatalf("GobEncode() error = %v", err)
	}
	if !bytes.Equal(b, redactedBytes) {
		t.Errorf("GobEncode() = %q, want %q", b, redactedBytes)
	}
}

func TestSecret_MarshalYAML(t *testing.T) {
	s := New("supersecret")
	v, err := s.MarshalYAML()
	if err != nil {
		t.Fatalf("MarshalYAML() error = %v", err)
	}
	if v.(string) != redacted {
		t.Errorf("MarshalYAML() = %q, want %q", v, redactedBytes)
	}
}

func TestSecret_MarshalTOML(t *testing.T) {
	s := New("supersecret")
	b, err := s.MarshalTOML()
	if err != nil {
		t.Fatalf("MarshalTOML() error = %v", err)
	}
	if !bytes.Equal(b, redactedJSON) {
		t.Errorf("MarshalTOML() = %q, want %q", b, redactedBytes)
	}
}

func TestSecret_ZeroBytes(t *testing.T) {
	value := []byte("supersecret")
	s := New(value)
	if !bytes.Equal(s.Expose(), value) {
		t.Errorf("unexpected secret value: %v", s.Expose())
	}

	empty := make([]byte, len(value))
	s.Zero()
	if !bytes.Equal(value, empty) {
		t.Errorf("unexpected value after zeroing: %v", value)
	}
}

func TestSecret_ZeroString(t *testing.T) {
	value := "supersecret"
	s := New(value)
	if s.Expose() != value {
		t.Errorf("unexpected secret value: %s", s.Expose())
	}

	s.Zero()
	if s.Expose() != "" {
		t.Errorf("unexpected value after zeroing: %s", s.Expose())
	}
}

func TestZeroizingSecret(t *testing.T) {
	s := NewZeroizing("supersecret")
	if v := s.String(); v != redacted {
		t.Errorf("unexpected string for zeroizing secret: %s", v)
	}
	s = nil
	runtime.GC()
}

func TestZeroize(t *testing.T) {
	t.Run("nil", func(t *testing.T) {
		Zeroize(nil)
	})

	t.Run("zero value", func(t *testing.T) {
		var n int
		Zeroize(&n)
	})

	t.Run("string", func(t *testing.T) {
		value := "testval"
		Zeroize(&value)
		if value != "" {
			t.Errorf("unexpected value: %s", value)
		}
	})

	t.Run("*int", func(t *testing.T) {
		value := 42
		ptr := &value
		Zeroize(&ptr)
		if ptr != nil {
			t.Errorf("unexpected value for pointer: %v", ptr)
		}
		if value != 0 {
			t.Errorf("unexpected value for int: %d", value)
		}
	})

	t.Run("**int", func(t *testing.T) {
		value := 42
		ptr := &value
		ptr2 := &ptr
		Zeroize(&ptr2)
		if ptr2 != nil {
			t.Errorf("unexpected value for pointer: %v", ptr2)
		}
		if ptr != nil {
			t.Errorf("unexpected value for pointer: %v", ptr)
		}
		if value != 0 {
			t.Errorf("unexpected value for int: %d", value)
		}
	})

	t.Run("array", func(t *testing.T) {
		value := [3]int{1, 2, 3}
		Zeroize(&value)
		for _, v := range value {
			if v != 0 {
				t.Errorf("unexpected value: %d", v)
			}
		}
	})

	t.Run("slice", func(t *testing.T) {
		value := []int{1, 2, 3}
		Zeroize(value)
		for _, v := range value {
			if v != 0 {
				t.Errorf("unexpected value: %d", v)
			}
		}
	})

	t.Run("byte slice", func(t *testing.T) {
		value := []byte("hi")
		Zeroize(value)
		for _, v := range value {
			if v != 0 {
				t.Errorf("unexpected value: %d", v)
			}
		}
	})

	t.Run("byte array", func(t *testing.T) {
		value := [...]byte{'t', 'e', 's', 't'}
		Zeroize(&value)
		for _, v := range value {
			if v != 0 {
				t.Errorf("unexpected value: %d", v)
			}
		}
	})

	t.Run("map", func(t *testing.T) {
		value := map[int]int{1: 100, 2: 200, 3: 300}
		Zeroize(value)
		if len(value) != 0 {
			t.Errorf("unexpected value: %v", value)
		}
	})

	t.Run("nil map", func(t *testing.T) {
		var value map[int]int
		Zeroize(value)
	})

	t.Run("struct", func(t *testing.T) {
		value := struct {
			Name string
			Age  int
			id   int
		}{
			Name: "myname",
			Age:  100,
			id:   42,
		}
		Zeroize(&value)
		if value.Name != "" {
			t.Errorf("unexpected Name: %s", value.Name)
		}
		if value.Age != 0 {
			t.Errorf("unexpected Age: %d", value.Age)
		}
		if value.id != 0 {
			t.Errorf("unexpected id: %d", value.id)
		}
	})

	t.Run("nested struct", func(t *testing.T) {
		type Inner struct {
			Val int
		}
		type Outer struct {
			InnerField *Inner
			SliceField []int
			MapField   map[string]string
		}

		inner := &Inner{Val: 99}
		value := Outer{
			InnerField: inner,
			SliceField: []int{1, 2, 3},
			MapField:   map[string]string{"a": "b"},
		}

		Zeroize(&value)
		if value.InnerField != nil {
			t.Errorf("unexpected InnerField: %v", value.InnerField)
		}
		if len(value.SliceField) != 0 {
			t.Errorf("unexpected SliceField: %v", value.SliceField)
		}
		if len(value.MapField) != 0 {
			t.Errorf("unexpected MapField: %v", value.MapField)
		}
		if inner.Val != 0 {
			t.Errorf("unexpected Inner.Val: %d", inner.Val)
		}
	})

	t.Run("recursive", func(t *testing.T) {
		type Node struct {
			Next *Node
		}
		n := &Node{}
		n.Next = n

		Zeroize(n)
		if n.Next != nil {
			t.Errorf("unexpected value: %v", n)
		}
	})
}
