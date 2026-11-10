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

// Command secure demonstrates protecting each shard with authenticated
// encryption before storage or transport. Run it from the module root with:
//
//	go run ./examples/secure
//
// This is an integration pattern, not a production key-management system. The
// example keeps recipient keys in memory; a real application must use a KMS or
// another secure, independently managed key-distribution mechanism.
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	cryptorand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"

	shamir "github.com/vjebramek/goshamir"
)

const envelopeVersion uint8 = 1
const envelopeDomain = "github.com/vjebramek/goshamir/examples/secure/v1"

type shareEnvelope struct {
	Version     uint8  `json:"version"`
	SetID       string `json:"set_id"`
	Threshold   uint8  `json:"threshold"`
	ShareNumber uint8  `json:"share_number"`
	Nonce       []byte `json:"nonce"`
	Ciphertext  []byte `json:"ciphertext"`
}

func main() {
	if err := run(); err != nil {
		slog.Error("secure example failed", "error", err)
		os.Exit(1)
	}
}

func run() error {
	sharing, err := shamir.NewShamirWithError(shamir.Option{})
	if err != nil {
		return fmt.Errorf("create sharing instance: %w", err)
	}

	const (
		partCount = 5
		threshold = 3
	)
	secret := shamir.Secret("example secret; do not use sample data in production")
	shards, err := sharing.Split(secret, partCount, threshold)
	if err != nil {
		return fmt.Errorf("split secret: %w", err)
	}

	// Keep the expected set ID and threshold in trusted application metadata.
	// They must not be accepted solely from the envelope being opened.
	var setID [16]byte
	if _, err := io.ReadFull(cryptorand.Reader, setID[:]); err != nil {
		return fmt.Errorf("generate share-set ID: %w", err)
	}

	// Each share gets an independent key. In a real deployment, keep each key
	// with its intended recipient or key-management service, not with the
	// corresponding envelope.
	keys := make([][]byte, len(shards))
	envelopes := make([]shareEnvelope, len(shards))
	for i, shard := range shards {
		key := make([]byte, 32)
		if _, err := io.ReadFull(cryptorand.Reader, key); err != nil {
			return fmt.Errorf("generate key for share %d: %w", i+1, err)
		}
		keys[i] = key

		envelopes[i], err = sealShare(key, setID, uint8(threshold), uint8(i+1), shard)
		if err != nil {
			return fmt.Errorf("protect share %d: %w", i+1, err)
		}
	}

	// The JSON operation represents storage/transport. Ciphertext is safe to
	// serialize, but the example keeps it in memory and does not print it.
	selectedNumbers := []int{0, 2, 4}
	selected := make([]shamir.Shard, 0, len(selectedNumbers))
	for _, i := range selectedNumbers {
		encoded, err := json.Marshal(envelopes[i])
		if err != nil {
			return fmt.Errorf("encode envelope %d: %w", i+1, err)
		}
		var received shareEnvelope
		if err := json.Unmarshal(encoded, &received); err != nil {
			return fmt.Errorf("decode envelope %d: %w", i+1, err)
		}

		shard, err := openShare(keys[i], setID, uint8(threshold), uint8(i+1), received)
		if err != nil {
			return fmt.Errorf("authenticate share %d: %w", i+1, err)
		}
		selected = append(selected, shard)
	}

	recovered, err := sharing.CombineWithThreshold(selected, threshold)
	if err != nil {
		return fmt.Errorf("combine authenticated shares: %w", err)
	}
	if !bytes.Equal(recovered, secret) {
		return errors.New("reconstructed secret does not match the original")
	}

	fmt.Printf("Authenticated %d shares and reconstructed the secret.\n", len(selected))
	return nil
}

func sealShare(key []byte, setID [16]byte, threshold, shareNumber uint8, shard shamir.Shard) (shareEnvelope, error) {
	if threshold < 2 || shareNumber == 0 {
		return shareEnvelope{}, errors.New("invalid threshold or share number")
	}
	if err := validateShard(shard); err != nil {
		return shareEnvelope{}, err
	}

	aead, err := newAEAD(key)
	if err != nil {
		return shareEnvelope{}, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(cryptorand.Reader, nonce); err != nil {
		return shareEnvelope{}, fmt.Errorf("generate nonce: %w", err)
	}

	return shareEnvelope{
		Version:     envelopeVersion,
		SetID:       hex.EncodeToString(setID[:]),
		Threshold:   threshold,
		ShareNumber: shareNumber,
		Nonce:       nonce,
		Ciphertext:  aead.Seal(nil, nonce, shard, associatedData(setID, threshold, shareNumber)),
	}, nil
}

func openShare(key []byte, expectedSetID [16]byte, expectedThreshold, expectedShareNumber uint8, envelope shareEnvelope) (shamir.Shard, error) {
	if expectedThreshold < 2 || expectedShareNumber == 0 {
		return nil, errors.New("invalid expected threshold or share number")
	}
	if envelope.Version != envelopeVersion ||
		envelope.SetID != hex.EncodeToString(expectedSetID[:]) ||
		envelope.Threshold != expectedThreshold ||
		envelope.ShareNumber != expectedShareNumber {
		return nil, errors.New("share envelope metadata does not match trusted context")
	}

	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	plaintext, err := aead.Open(nil, envelope.Nonce, envelope.Ciphertext,
		associatedData(expectedSetID, expectedThreshold, expectedShareNumber))
	if err != nil {
		return nil, fmt.Errorf("authenticate ciphertext: %w", err)
	}
	if err := validateShard(plaintext); err != nil {
		return nil, fmt.Errorf("invalid decrypted shard: %w", err)
	}
	return shamir.Shard(plaintext), nil
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create AES cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}
	return aead, nil
}

func associatedData(setID [16]byte, threshold, shareNumber uint8) []byte {
	data := make([]byte, 0, len(envelopeDomain)+1+len(setID)+2)
	data = append(data, envelopeDomain...)
	data = append(data, envelopeVersion)
	data = append(data, setID[:]...)
	data = append(data, threshold, shareNumber)
	return data
}

func validateShard(shard []byte) error {
	if len(shard) < 2 {
		return shamir.ErrMinShardLen
	}
	if shard[len(shard)-1] == 0 {
		return shamir.ErrInvalidShardIndex
	}
	return nil
}
