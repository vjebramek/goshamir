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

package shamir

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/vjebramek/goshamir/gf256"
)

func TestSplitAndCombineWithThreshold(t *testing.T) {
	instance, err := NewShamirWithError(Option{Generator: gf256.Generator229})
	if err != nil {
		t.Fatal(err)
	}

	secret := Secret{0, 1, 2, 0x80, 0xff}
	shards, err := instance.Split(secret, 5, 3)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := instance.CombineWithThreshold(shards[:2], 3); !errors.Is(err, ErrNotEnoughShards) {
		t.Fatalf("CombineWithThreshold with two shares error = %v, want ErrNotEnoughShards", err)
	}

	got, err := instance.CombineWithThreshold([]Shard{shards[0], shards[2], shards[4]}, 3)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("CombineWithThreshold() = %v, want %v", got, secret)
	}
}

func TestNewShamirGeneratorValidation(t *testing.T) {
	if NewShamir(Option{}) == nil {
		t.Fatal("NewShamir with zero-value option returned nil")
	}

	if _, err := NewShamirWithError(Option{Generator: 2}); !errors.Is(err, gf256.ErrInvalidGenerator) {
		t.Fatalf("NewShamirWithError with invalid generator error = %v, want ErrInvalidGenerator", err)
	}
	if NewShamir(Option{Generator: 2}) != nil {
		t.Fatal("NewShamir with invalid generator returned a non-nil instance")
	}
}

func TestCombineRejectsZeroCoordinate(t *testing.T) {
	instance := NewDefault()
	_, err := instance.Combine([]Shard{{1, 0}, {2, 1}})
	if !errors.Is(err, ErrInvalidShardIndex) {
		t.Fatalf("Combine error = %v, want ErrInvalidShardIndex", err)
	}
}

func TestZeroValueShamirReturnsError(t *testing.T) {
	var instance Shamir
	if _, err := instance.Split([]byte("secret"), 3, 2); !errors.Is(err, ErrInvalidShamir) {
		t.Fatalf("Split error = %v, want ErrInvalidShamir", err)
	}
}

func TestNewCoefficientsMaximumDegree(t *testing.T) {
	coefficients, err := NewCoefficients(7, 255)
	if err != nil {
		t.Fatal(err)
	}
	if len(coefficients) != 256 {
		t.Fatalf("len(coefficients) = %d, want 256", len(coefficients))
	}
}

func TestEmptyCoefficientsEvaluateToZero(t *testing.T) {
	if got := Coefficients(nil).Eval(nil, 1); got != 0 {
		t.Fatalf("Eval() = %d, want 0", got)
	}
}

func TestShardJSONRoundTrip(t *testing.T) {
	want := Shard{0, 1, 0xfe, 0xff}
	encoded, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}

	var got Shard
	if err := json.Unmarshal(encoded, &got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("JSON round trip = %v, want %v", got, want)
	}
}

func TestShardJSONRejectsInvalidInput(t *testing.T) {
	for _, input := range []string{`null`, `"not-hex"`, `123`} {
		var shard Shard
		if err := json.Unmarshal([]byte(input), &shard); err == nil {
			t.Errorf("Unmarshal(%s) succeeded, want an error", input)
		}
	}
}
