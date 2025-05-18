# secrecy

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
```

## License

This project is licensed under the [MIT License](LICENSE).
