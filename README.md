# secrecy

[![Go Reference](https://pkg.go.dev/badge/github.com/ryanfowler/secrecy.svg)](https://pkg.go.dev/github.com/ryanfowler/secrecy)

`secrecy` is a Go module that enables wrapping sensitive values so that they are
never shown when the value is printed, logged, or encoded. Any formatting
interface (`Stringer`, `json.Marshaler`, etc.) will return a constant
redacted string rather than the underlying value.

The project is inspired by the Rust
[`secrecy`](https://docs.rs/secrecy/latest/secrecy/) crate and exposes a
similar API in Go.

## Installation

```
go get github.com/ryanfowler/secrecy@latest
```

## Usage

Import the package and wrap sensitive values using `secrecy.New`. In order to
access the underlying secret, you must use the `Expose()` method.

```go
import "github.com/ryanfowler/secrecy"

type Login struct {
    Username string
    Password secrecy.Secret[string]
}

login := Login{
    Username: "ryanfowler",
    Password: secrecy.New("secretpassword"),
}

// Will output:
// Login = {Username:ryanfowler Password:[redacted]}
fmt.Printf("Login = %+v\n", login)

// Will output:
// Equal = true
fmt.Printf("Equal = %t\n", login.Password.Expose() == "secretpassword")
```

In order to have the underlying secret "zeroed" when the Secret gets garbage
collected, create the Secret with the `secrecy.NewZeroizing` method.

## Customising the redaction string

The string shown when a secret is formatted defaults to `"[REDACTED]"`. It can
be changed globally before any `Secret` values are created using
`secrecy.SetRedactedString`.

```go
func init() {
    secrecy.SetRedactedString("***")
}
```

All formatting and encoding operations will now emit the custom string.

## Zeroizing secrets

A secret can have it's contents zeroed by calling the `Zero()` method.

```go
s := secrecy.New([]byte("secretpassword"))
defer s.Zero()

useSecret(s.Expose())
```

Alternatively, the `secrecy.NewZeroizing` function returns a pointer to a
`Secret` that will automatically zero its value once the object becomes
unreachable and is garbage collected.

```go
s := secrecy.NewZeroizing([]byte("secretpassword"))

useToken(s.Expose())
```

After `Zero()` has been invoked, `Expose()` will return the zero value for the
wrapped type.

## License

This project is licensed under the [MIT License](LICENSE).
