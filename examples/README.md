# Runnable examples

These small programs demonstrate the public API without hiding the important
operational details. They are educational examples, not production-ready cryptographic
software. The author is not a cryptography expert, and the implementation has not had
an independent security review. Run them from the repository root:

```sh
go run ./examples/basic
go run ./examples/json
```

## `basic`

Creates five shares with a threshold of three, then reconstructs the secret from
three selected shares. It uses `NewShamirWithError` and `CombineWithThreshold` so
configuration and threshold mistakes are returned as errors. It also checks the
recovered bytes against the original input.

## `json`

Shows that a `Shard` is encoded as a JSON string containing lowercase hexadecimal
bytes and that the custom JSON unmarshaler restores those bytes. It then uses only
three of five decoded shares to reconstruct the secret.

The JSON example places all shares in one document strictly to demonstrate the
encoding. That defeats the distribution property if the document is used as actual
storage: a person who obtains it has every share. Keep real shares separately, and
protect the storage and transport channels. JSON and hexadecimal encoding provide
no confidentiality or integrity protection.

## `secure`

Demonstrates wrapping each shard in AES-GCM with an independent key before
serialization. The trusted share-set ID, expected threshold, and share number are
bound as associated data and checked when opening each envelope. The example verifies
authentication before passing shares to `CombineWithThreshold`; its tests cover
round-trip decoding, ciphertext tampering, and mismatched trusted metadata.

The program keeps all keys in memory and is only an integration example. A real
application must provision and store recipient keys independently (for example,
through a KMS), keep the expected set ID and threshold in trusted metadata, and
protect shares separately. AES-GCM here protects against parties without the
recipient key; it does not stop that key holder from forging their own envelope.

## Important constraints

- `Split(secret, parts, threshold)` requires `2 <= threshold <= parts <= 255`.
- The threshold is not embedded in shards. `Combine` accepts any two or more
  distinct shards; `CombineWithThreshold` checks only the threshold supplied by the
  caller. Keep the expected threshold in trusted metadata and pass it explicitly.
- Pass distinct shares from the same split operation. Mixed or modified raw shares
  are not detected by the Shamir library and can reconstruct to an incorrect value.
  Authenticate shares before combining them if storage or transport can be altered.
- The polynomial coefficients are generated with `crypto/rand`. The GF(256)
  operations are not constant-time, so this implementation does not protect against
  local timing or cache side-channel observation.
- Do not print real secrets or shares to logs. The programs print sample values
  only to make the demonstrations easy to follow.
