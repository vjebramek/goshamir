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

// Command json demonstrates the JSON representation of shards and a complete
// encode/decode/reconstruction cycle. Run it from the module root with:
//
//	go run ./examples/json
package main

import (
	"bytes"
	"encoding/json"
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
	sharing, err := shamir.NewShamirWithError(shamir.Option{})
	if err != nil {
		return fmt.Errorf("create sharing instance: %w", err)
	}

	// This example creates five shares with a threshold of three. A Shard's JSON
	// representation is a JSON string containing lowercase hexadecimal bytes;
	// UnmarshalJSON decodes that same format back into the original bytes.
	const threshold = 3
	original := shamir.Secret("JSON is an encoding, not encryption")
	shares, err := sharing.Split(original, 5, threshold)
	if err != nil {
		return fmt.Errorf("split secret: %w", err)
	}

	// Encoding all shares together is convenient for demonstrating serialization,
	// but it is not a safe storage arrangement: anyone who gets this one document
	// gets every share. In a real deployment, store shares separately and protect
	// each location or recipient appropriately.
	encoded, err := json.MarshalIndent(shares, "", "  ")
	if err != nil {
		return fmt.Errorf("encode shares as JSON: %w", err)
	}
	fmt.Printf("Serialized shares (hex strings):\n%s\n", encoded)

	// Decoding into []Shard invokes Shard.UnmarshalJSON for each item. Invalid
	// JSON types and invalid hexadecimal strings are reported as errors.
	var decoded []shamir.Shard
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		return fmt.Errorf("decode shares from JSON: %w", err)
	}

	// The threshold is metadata known to the application, not something inferred
	// from the serialized shares. Supply at least that many distinct shares.
	recovered, err := sharing.CombineWithThreshold(decoded[:threshold], threshold)
	if err != nil {
		return fmt.Errorf("combine decoded shares: %w", err)
	}
	if !bytes.Equal(recovered, original) {
		return fmt.Errorf("reconstructed secret does not match the original")
	}
	fmt.Printf("Recovered secret: %q\n", string(recovered))
	return nil
}
