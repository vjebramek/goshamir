// Copyright 2019 Volker Jebramek
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Command basic demonstrates splitting a byte string into shares and reconstructing
// it from a threshold-sized subset. Run it from the module root with:
//
//	go run ./examples/basic
package main

import (
	"bytes"
	"fmt"
	"log/slog"
	"os"

	shamir "github.com/vjebramek/goshamir"
)

func main() {
	if err := run(); err != nil {
		slog.Error("example failed", "error", err)
		os.Exit(1)
	}
}

func run() error {
	// Use the checked constructor so an invalid custom field generator cannot
	// produce an instance with unusable GF(256) arithmetic. The zero-valued
	// option selects the library's default primitive generator.
	sharing, err := shamir.NewShamirWithError(shamir.Option{})
	if err != nil {
		return fmt.Errorf("create sharing instance: %w", err)
	}

	// Five shares are created, and any three distinct shares are sufficient to
	// recover the secret. The threshold is not stored inside the share data, so
	// remember it separately and pass it to CombineWithThreshold later.
	secret := shamir.Secret("A small secret for the example")
	const (
		shareCount = 5
		threshold  = 3
	)
	shares, err := sharing.Split(secret, shareCount, threshold)
	if err != nil {
		return fmt.Errorf("split secret: %w", err)
	}

	// String formats a share as lowercase hexadecimal for transport or display.
	// Real secrets and shares should not be printed to logs or terminals; this
	// output is only to make the example's data flow visible.
	fmt.Printf("Created %d shares for a threshold of %d:\n", shareCount, threshold)
	for index, share := range shares {
		fmt.Printf("  share %d: %s\n", index+1, share.String())
	}

	// Select three distinct shares. The sample deliberately does not use all
	// five: reconstruction should work with exactly the configured threshold.
	selected := []shamir.Shard{
		shares[0],
		shares[2],
		shares[4],
	}
	recovered, err := sharing.CombineWithThreshold(selected, threshold)
	if err != nil {
		return fmt.Errorf("combine shares: %w", err)
	}

	// Verify the result rather than assuming a successful call implies that the
	// caller selected valid shares from the same split operation.
	if !bytes.Equal(recovered, secret) {
		return fmt.Errorf("reconstructed secret does not match the original")
	}
	fmt.Printf("Recovered secret: %q\n", string(recovered))
	return nil
}
