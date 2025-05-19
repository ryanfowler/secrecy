package secrecy

import (
	"bytes"
	"encoding/json"
	"fmt"
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
	if got := fmt.Sprintf("%x", s); got != "5b72656461637465645d" {
		t.Errorf("Format %%x = %q, want %q", got, "5b72656461637465645d")
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
	if !bytes.Equal(b, redactedBytes) {
		t.Errorf("MarshalTOML() = %q, want %q", b, redactedBytes)
	}
}
