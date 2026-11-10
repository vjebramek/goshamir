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

package gf256

import (
	"errors"
	"strings"
	"testing"
)

func TestNewTableWithErrorRejectsNonPrimitiveGenerators(t *testing.T) {
	for _, generator := range []Generator{0, 2} {
		if _, err := NewTableWithError(generator); !errors.Is(err, ErrInvalidGenerator) {
			t.Errorf("NewTableWithError(%d) error = %v, want ErrInvalidGenerator", generator, err)
		}
		if table := NewTable(generator); table != nil {
			t.Errorf("NewTable(%d) = %v, want nil", generator, table)
		}
	}
}

func TestTableArithmeticMatchesPolynomialArithmetic(t *testing.T) {
	table, err := NewTableWithError(Generator003)
	if err != nil {
		t.Fatal(err)
	}

	for a := 0; a < 256; a++ {
		for b := 0; b < 256; b++ {
			if got, want := table.Mul(uint8(a), uint8(b)), Mul(uint8(a), uint8(b)); got != want {
				t.Fatalf("Mul(%02x, %02x) = %02x, want %02x", a, b, got, want)
			}
			if b != 0 {
				got, err := table.Div(uint8(a), uint8(b))
				if err != nil {
					t.Fatalf("Div(%02x, %02x): %v", a, b, err)
				}
				if table.Mul(got, uint8(b)) != uint8(a) {
					t.Fatalf("Div(%02x, %02x) = %02x, multiplication did not recover numerator", a, b, got)
				}
			}
		}
	}
}

func TestTableStringLabels(t *testing.T) {
	table, err := NewTableWithError(Generator003)
	if err != nil {
		t.Fatal(err)
	}

	got := table.String()
	if !strings.HasPrefix(got, "EXP:\n") {
		t.Fatalf("String() starts with %q, want EXP label", got)
	}
	if !strings.Contains(got, "\nLOG:\n") {
		t.Fatal("String() does not contain LOG label")
	}
}
