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

// Package shamir implements byte-oriented Shamir secret sharing over GF(256).
//
// Shares contain the secret's evaluated bytes followed by a nonzero x-coordinate.
// The field operations use lookup tables and are not constant-time.
package shamir

import (
	cryptorand "crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"

	"github.com/vjebramek/goshamir/gf256"
)

// Secret is the byte sequence to split or reconstruct.
type Secret []byte

// Shamir splits and combines secrets using a configured GF(256) table.
type Shamir struct {
	table *gf256.Table
}

// Option configures a Shamir instance. A zero Generator selects the default.
type Option struct {
	Generator gf256.Generator
}

// Coefficients contains the low-to-high coefficients of a GF(256) polynomial.
type Coefficients []byte

// Shard is one share, encoded as secret bytes followed by its x-coordinate.
type Shard []byte

var (
	// ErrThreshold indicates that the number of parts is below the threshold.
	ErrThreshold = errors.New("number of parts cannot be less than threshold")
	// ErrMinThreshold indicates that the threshold is less than two.
	ErrMinThreshold = errors.New("threshold must be at least 2")
	// ErrMaxThreshold indicates that the threshold exceeds 255.
	ErrMaxThreshold = errors.New("threshold cannot exceed 255")
	// ErrEmptySecret indicates that an empty secret was supplied.
	ErrEmptySecret = errors.New("cannot split an empty secret")
	// ErrMinShards indicates that fewer than two shards were supplied.
	ErrMinShards = errors.New("at least two shards are required")
	// ErrNotEnoughShards indicates that fewer shards than the requested threshold were supplied.
	ErrNotEnoughShards = errors.New("number of shards is less than threshold")
	// ErrMinShardLen indicates that a shard has no secret bytes and coordinate.
	ErrMinShardLen = errors.New("shard must contain at least two bytes")
	// ErrSameShardLen indicates that shards have differing encoded lengths.
	ErrSameShardLen = errors.New("all shards must be of the same length")
	// ErrDuplicatedShard indicates that multiple shards have the same coordinate.
	ErrDuplicatedShard = errors.New("duplicate shard coordinate")
	// ErrInvalidShardIndex indicates that a shard has the reserved zero coordinate.
	ErrInvalidShardIndex = errors.New("shard coordinate must be nonzero")
	// ErrMaxParts indicates that more than 255 shares were requested.
	ErrMaxParts = errors.New("parts cannot exceed 255")
	// ErrInvalidShamir indicates that the Shamir instance was not initialized.
	ErrInvalidShamir = errors.New("shamir instance is not initialized")

	// ErrTreshold is retained for compatibility; use ErrThreshold instead.
	//
	// Deprecated: use ErrThreshold.
	ErrTreshold = ErrThreshold
	// ErrMinTreshold is retained for compatibility; use ErrMinThreshold instead.
	//
	// Deprecated: use ErrMinThreshold.
	ErrMinTreshold = ErrMinThreshold
	// ErrMaxTreshold is retained for compatibility; use ErrMaxThreshold instead.
	//
	// Deprecated: use ErrMaxThreshold.
	ErrMaxTreshold = ErrMaxThreshold
)

// NewShamir creates a Shamir instance. A zero generator selects the default.
// It returns nil for an invalid nonzero generator; use NewShamirWithError when
// the construction error needs to be handled.
func NewShamir(opt Option) *Shamir {
	instance, err := NewShamirWithError(opt)
	if err != nil {
		return nil
	}
	return instance
}

// NewShamirWithError creates a Shamir instance and reports invalid generators.
func NewShamirWithError(opt Option) (*Shamir, error) {
	generator := opt.Generator
	if generator == 0 {
		generator = gf256.Generator229
	}

	table, err := gf256.NewTableWithError(generator)
	if err != nil {
		return nil, fmt.Errorf("create GF(256) table: %w", err)
	}

	return &Shamir{table: table}, nil
}

// NewDefault creates a Shamir instance using the default GF(256) generator.
func NewDefault() *Shamir {
	return NewShamir(Option{Generator: gf256.Generator229})
}

// Split divides secret into parts shares. Any threshold or more distinct shares
// can reconstruct the secret. Threshold must be between 2 and 255, and parts
// must be at least threshold.
func (s *Shamir) Split(secret Secret, parts, threshold uint) ([]Shard, error) {
	if s == nil || s.table == nil {
		return nil, ErrInvalidShamir
	}
	if threshold < 2 {
		return nil, ErrMinThreshold
	}
	if threshold > 255 {
		return nil, ErrMaxThreshold
	}
	if parts > 255 {
		return nil, ErrMaxParts
	}
	if parts < threshold {
		return nil, ErrThreshold
	}
	if len(secret) == 0 {
		return nil, ErrEmptySecret
	}

	seed, err := NewSeed()
	if err != nil {
		return nil, fmt.Errorf("generate share coordinates: %w", err)
	}

	rng := rand.New(rand.NewSource(seed))
	xCoords := rng.Perm(255)

	result := make([]Shard, int(parts))
	for index := range result {
		result[index] = make(Shard, len(secret)+1)
		result[index][len(secret)] = uint8(xCoords[index] + 1)
	}

	for index, value := range secret {
		coefficients, err := NewCoefficients(value, uint8(threshold-1))
		if err != nil {
			return nil, fmt.Errorf("generate coefficients for secret byte %d: %w", index, err)
		}

		for part := range result {
			x := uint8(xCoords[part] + 1)
			result[part][index] = coefficients.Eval(s.table, x)
		}
	}

	return result, nil
}

// Combine reconstructs a secret by interpolating the supplied shares. The
// threshold is not encoded in a shard, so callers must provide at least as many
// shares as were required by Split. Use CombineWithThreshold to check that count.
func (s *Shamir) Combine(shards []Shard) (Secret, error) {
	if s == nil || s.table == nil {
		return nil, ErrInvalidShamir
	}
	if len(shards) < 2 {
		return nil, ErrMinShards
	}

	shardLen := len(shards[0])
	if shardLen < 2 {
		return nil, ErrMinShardLen
	}

	for _, shard := range shards {
		if len(shard) != shardLen {
			return nil, ErrSameShardLen
		}
	}

	x := make([]uint8, len(shards))
	y := make([]uint8, len(shards))
	seen := make(map[uint8]struct{}, len(shards))
	for i, shard := range shards {
		coordinate := shard[shardLen-1]
		if coordinate == 0 {
			return nil, ErrInvalidShardIndex
		}
		if _, exists := seen[coordinate]; exists {
			return nil, ErrDuplicatedShard
		}
		seen[coordinate] = struct{}{}
		x[i] = coordinate
	}

	secret := make(Secret, shardLen-1)
	for index := range secret {
		for i, shard := range shards {
			y[i] = shard[index]
		}

		value, err := s.interpolate(x, y, 0)
		if err != nil {
			return nil, fmt.Errorf("interpolate secret byte %d: %w", index, err)
		}
		secret[index] = value
	}

	return secret, nil
}

// CombineWithThreshold reconstructs a secret only when at least threshold
// distinct shares are supplied. The threshold must be between 2 and 255.
func (s *Shamir) CombineWithThreshold(shards []Shard, threshold uint) (Secret, error) {
	if threshold < 2 {
		return nil, ErrMinThreshold
	}
	if threshold > 255 {
		return nil, ErrMaxThreshold
	}
	if uint(len(shards)) < threshold {
		return nil, ErrNotEnoughShards
	}
	return s.Combine(shards)
}

// interpolate evaluates the Lagrange polynomial defined by (x, y) at n.
func (s *Shamir) interpolate(x, y []uint8, n uint8) (uint8, error) {
	result := uint8(0)

	for i := range x {
		basis := uint8(1)
		for j := range x {
			if i == j {
				continue
			}

			numerator := gf256.Add(n, x[j])
			denominator := gf256.Add(x[i], x[j])
			term, err := s.table.Div(numerator, denominator)
			if err != nil {
				return 0, err
			}
			basis = s.table.Mul(basis, term)
		}
		result = gf256.Add(result, s.table.Mul(y[i], basis))
	}

	return result, nil
}

// NewCoefficients creates a polynomial with the given intercept and degree.
// The remaining coefficients are read from crypto/rand.
func NewCoefficients(intercept, degree uint8) (Coefficients, error) {
	coefficients := make([]byte, int(degree)+1)
	coefficients[0] = intercept
	if _, err := cryptorand.Read(coefficients[1:]); err != nil {
		return nil, err
	}
	return coefficients, nil
}

// Eval evaluates the polynomial at x using the supplied GF(256) table. For a
// nonempty polynomial and nonzero x, table must be a non-nil initialized table
// created by gf256.NewTable or gf256.NewTableWithError.
func (c Coefficients) Eval(table *gf256.Table, x uint8) uint8 {
	if len(c) == 0 {
		return 0
	}
	if x == 0 {
		return c[0]
	}

	result := c[len(c)-1]
	for i := len(c) - 2; i >= 0; i-- {
		result = gf256.Add(table.Mul(result, x), c[i])
	}
	return result
}

// NewShardFromString decodes the bytes of a hexadecimal shard string. It does
// not validate shard length or the coordinate; Combine performs those checks.
func NewShardFromString(encoded string) (Shard, error) {
	shard, err := hex.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode shard hex: %w", err)
	}
	return Shard(shard), nil
}

// Bytes returns the shard's underlying byte slice without copying it.
func (shard Shard) Bytes() []uint8 {
	return shard
}

// String returns the shard encoded as lowercase hexadecimal.
func (shard Shard) String() string {
	return hex.EncodeToString(shard)
}

// MarshalJSON encodes a shard as a JSON string containing lowercase hex.
func (shard Shard) MarshalJSON() ([]byte, error) {
	return json.Marshal(shard.String())
}

// UnmarshalJSON decodes a JSON string containing a hexadecimal shard. It does
// not validate shard length or the coordinate; Combine performs those checks.
func (shard *Shard) UnmarshalJSON(data []byte) error {
	var encoded *string
	if err := json.Unmarshal(data, &encoded); err != nil {
		return fmt.Errorf("decode shard JSON string: %w", err)
	}
	if encoded == nil {
		return errors.New("decode shard JSON string: expected a string")
	}

	decoded, err := hex.DecodeString(*encoded)
	if err != nil {
		return fmt.Errorf("decode shard hex: %w", err)
	}
	*shard = Shard(decoded)
	return nil
}

// NewSeed returns a uniformly sourced 64-bit seed from crypto/rand.
func NewSeed() (int64, error) {
	var source [8]byte
	if _, err := cryptorand.Read(source[:]); err != nil {
		return 0, fmt.Errorf("read random seed: %w", err)
	}

	return int64(binary.LittleEndian.Uint64(source[:])), nil
}
