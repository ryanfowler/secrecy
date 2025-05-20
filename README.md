# secrecy

[![go.dev reference](https://img.shields.io/badge/go.dev-reference-007d9c?logo=go&logoColor=white&style=flat-square)](https://pkg.go.dev/github.com/ryanfowler/secrecy)

`secrecy` is a Go module that enables wrapping sensitive values to prevent
leaking them through logging, formatting, or other encoding mechanisms.

This module is inspired by the Rust [`secrecy`](https://docs.rs/secrecy/latest/secrecy/) crate.

## Installation

```
go get github.com/ryanfowler/secrecy@latest
```

## Usage

Import the package and wrap sensitive values:

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

// Login: {Username:ryanfowler Password:[redacted]}
fmt.Printf("Login: %+v\n", login)

// value == "secretpassword"
value := login.Password.Expose()
```

## License

This project is licensed under the [MIT License](LICENSE).
