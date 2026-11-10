# shamir

[![Test](https://github.com/vjebramek/goshamir/actions/workflows/test.yml/badge.svg)](https://github.com/vjebramek/goshamir/actions/workflows/test.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/vjebramek/goshamir.svg)](https://pkg.go.dev/github.com/vjebramek/goshamir)
[![Go Report Card](https://goreportcard.com/badge/github.com/vjebramek/goshamir)](https://goreportcard.com/report/github.com/vjebramek/goshamir)
[![Go version](https://img.shields.io/github/go-mod/go-version/vjebramek/goshamir)](https://github.com/vjebramek/goshamir/blob/main/go.mod)
[![License](https://img.shields.io/github/license/vjebramek/goshamir)](LICENSE)

A byte-oriented Shamir secret-sharing library over GF(256).

> **Warning:** This project is for learning and experimentation, not production use.
> The author is not a cryptography expert, and the code has not received an independent
> cryptographic security review. Do not rely on it to protect valuable or sensitive
> secrets; use a well-reviewed, maintained cryptographic library instead.

## Usage

```go
package example

import "github.com/vjebramek/goshamir"

func example() error {
	s, err := shamir.NewShamirWithError(shamir.Option{}) // zero selects the default generator
	if err != nil {
		return err
	}

	shares, err := s.Split(shamir.Secret("secret"), 5, 3)
	if err != nil {
		return err
	}

	recovered, err := s.CombineWithThreshold([]shamir.Shard{
		shares[0], shares[2], shares[4],
	}, 3)
	if err != nil {
		return err
	}
	_ = recovered
	return nil
}
```

A shard is encoded as the evaluated secret bytes followed by a nonzero x-coordinate.
The threshold is not embedded in shards. Use `CombineWithThreshold` when the expected
threshold is known; `Combine` cannot determine whether enough shares were supplied.
Shards are represented as lowercase hexadecimal strings by `String` and JSON encoding.

## Security note

Polynomial coefficients are generated using `crypto/rand`. GF(256) operations use
lookup tables and are not constant-time, so this implementation does not protect
against local timing or cache side-channel observation.

A raw `Shard` provides neither confidentiality nor integrity. Altered shards or
shards from different split operations can be accepted by `Combine` and produce an
incorrect result without an error. The threshold is also not encoded in a shard:
`Combine` accepts two or more distinct shards, while `CombineWithThreshold` checks
only the threshold supplied by the caller. Keep the expected threshold and a unique
share-set identifier in trusted application metadata.

Before storing or transporting real shares, protect each share independently with
an authenticated encryption scheme and a distinct, securely managed key. Bind the
trusted share-set identifier, expected threshold, and recipient/share slot as
associated data; verify them against trusted metadata when opening the share. Keep
keys separate from the encrypted shares. See [`examples/secure`](examples/README.md)
for an illustrative AES-GCM integration pattern. It does not replace secure key
management or a cryptographic review, and it does not address malicious recipients
who possess their own symmetric keys.

## Examples

Runnable, commented programs covering splitting/reconstruction, JSON serialization,
and authenticated share envelopes are in [`examples/`](examples/README.md). Run them
from the module root with `go run ./examples/basic`, `go run ./examples/json`, or
`go run ./examples/secure`.
