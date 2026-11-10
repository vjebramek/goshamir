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

import "errors"

var (
	// ErrDivisionByZero is returned when dividing by zero in GF(256).
	ErrDivisionByZero = errors.New("division by zero")
	// ErrInvalidGenerator indicates that a value is not primitive in GF(256).
	ErrInvalidGenerator = errors.New("invalid GF(256) generator")
)
