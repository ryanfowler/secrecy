# secrecy

[![Go Reference](https://pkg.go.dev/badge/github.com/ryanfowler/secrecy.svg)](https://pkg.go.dev/github.com/ryanfowler/secrecy)

`secrecy` is a Go module that enables wrapping sensitive values to prevent
leaking them through logging, formatting, or other encoding mechanisms.

This module is inspired by the Rust [`secrecy`](https://docs.rs/secrecy/latest/secrecy/) crate.

## Installation

```
go get github.com/ryanfowler/secrecy@latest
```

## Usage

Import the package and wrap sensitive values. In order to access the underlying
secret, you must use the `Expose()` method.

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

## License

This project is licensed under the [MIT License](LICENSE).
