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

// Package gf256 provides arithmetic in the AES polynomial representation of GF(256).
package gf256

import (
	"encoding/hex"
	"fmt"
)

// Table contains exponent and logarithm tables for a primitive GF(256) generator.
// Create tables with NewTable or NewTableWithError; the zero value and nil
// pointers are not usable. Its operations use data-dependent table lookups and
// are not constant-time.
type Table struct {
	exp []uint8
	log []uint8
}

// GenerateTable creates exponent and logarithm tables for n. It returns nil
// tables when n is not a primitive generator. Use GenerateTableWithError when
// the reason for failure is needed.
func GenerateTable(n Generator) ([]uint8, []uint8) {
	exp, log, err := GenerateTableWithError(n)
	if err != nil {
		return nil, nil
	}
	return exp, log
}

// GenerateTableWithError creates exponent and logarithm tables for a primitive
// generator of the field defined by the AES polynomial x^8+x^4+x^3+x+1.
func GenerateTableWithError(n Generator) ([]uint8, []uint8, error) {
	const order = 255

	exp := make([]uint8, order+1)
	log := make([]uint8, 256)
	seen := [256]bool{}

	value := uint8(1)
	for i := range order {
		if value == 0 || seen[value] {
			return nil, nil, fmt.Errorf("%w: 0x%02x", ErrInvalidGenerator, uint8(n))
		}
		exp[i] = value
		log[value] = uint8(i)
		seen[value] = true
		value = Mul(uint8(n), value)
	}
	if value != 1 {
		return nil, nil, fmt.Errorf("%w: 0x%02x", ErrInvalidGenerator, uint8(n))
	}
	exp[order] = 1

	return exp, log, nil
}

// NewTable creates a lookup table for n. It returns nil when n is not a
// primitive generator; use NewTableWithError to handle that case explicitly.
func NewTable(n Generator) *Table {
	table, err := NewTableWithError(n)
	if err != nil {
		return nil
	}
	return table
}

// NewTableWithError creates a lookup table for a primitive GF(256) generator.
func NewTableWithError(n Generator) (*Table, error) {
	exp, log, err := GenerateTableWithError(n)
	if err != nil {
		return nil, err
	}

	return &Table{exp: exp, log: log}, nil
}

// Mul multiplies a and b in GF(256).
func (table *Table) Mul(a, b uint8) uint8 {
	if a == 0 || b == 0 {
		return 0
	}

	sum := (int(table.log[a]) + int(table.log[b])) % 255
	return table.exp[sum]
}

// Div divides a by b in GF(256), returning ErrDivisionByZero when b is zero.
func (table *Table) Div(a, b uint8) (uint8, error) {
	if b == 0 {
		return 0, ErrDivisionByZero
	}
	if a == 0 {
		return 0, nil
	}

	difference := (int(table.log[a]) - int(table.log[b])) % 255
	if difference < 0 {
		difference += 255
	}
	return table.exp[difference], nil
}

// String returns a hexadecimal dump of the exponent and logarithm tables.
func (table *Table) String() string {
	return fmt.Sprintf("EXP:\n%s\nLOG:\n%s", hex.Dump(table.exp), hex.Dump(table.log))
}
