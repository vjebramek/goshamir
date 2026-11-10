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

// Generator is a primitive element used to build GF(256) lookup tables.
type Generator uint8

// Generator constants are primitive elements for the AES polynomial field.
const (
	Generator003 = 0x03
	Generator005 = 0x05
	Generator006 = 0x06
	Generator009 = 0x09
	Generator011 = 0x0b
	Generator014 = 0x0e
	Generator017 = 0x11
	Generator018 = 0x12
	Generator019 = 0x13
	Generator020 = 0x14
	Generator023 = 0x17
	Generator024 = 0x18
	Generator025 = 0x19
	Generator026 = 0x1a
	Generator028 = 0x1c
	Generator030 = 0x1e
	Generator031 = 0x1f
	Generator033 = 0x21
	Generator034 = 0x22
	Generator035 = 0x23
	Generator039 = 0x27
	Generator040 = 0x28
	Generator042 = 0x2a
	Generator044 = 0x2c
	Generator048 = 0x30
	Generator049 = 0x31
	Generator060 = 0x3c
	Generator062 = 0x3e
	Generator063 = 0x3f
	Generator065 = 0x41
	Generator069 = 0x45
	Generator070 = 0x46
	Generator071 = 0x47
	Generator072 = 0x48
	Generator073 = 0x49
	Generator075 = 0x4b
	Generator076 = 0x4c
	Generator078 = 0x4e
	Generator079 = 0x4f
	Generator082 = 0x52
	Generator084 = 0x54
	Generator086 = 0x56
	Generator087 = 0x57
	Generator088 = 0x58
	Generator089 = 0x59
	Generator090 = 0x5a
	Generator091 = 0x5b
	Generator095 = 0x5f
	Generator100 = 0x64
	Generator101 = 0x65
	Generator104 = 0x68
	Generator105 = 0x69
	Generator109 = 0x6d
	Generator110 = 0x6e
	Generator112 = 0x70
	Generator113 = 0x71
	Generator118 = 0x76
	Generator119 = 0x77
	Generator121 = 0x79
	Generator122 = 0x7a
	Generator123 = 0x7b
	Generator126 = 0x7e
	Generator129 = 0x81
	Generator132 = 0x84
	Generator134 = 0x86
	Generator135 = 0x87
	Generator136 = 0x88
	Generator138 = 0x8a
	Generator142 = 0x8e
	Generator143 = 0x8f
	Generator144 = 0x90
	Generator147 = 0x93
	Generator149 = 0x95
	Generator150 = 0x96
	Generator152 = 0x98
	Generator153 = 0x99
	Generator155 = 0x9b
	Generator157 = 0x9d
	Generator160 = 0xa0
	Generator164 = 0xa4
	Generator165 = 0xa5
	Generator166 = 0xa6
	Generator167 = 0xa7
	Generator169 = 0xa9
	Generator170 = 0xaa
	Generator172 = 0xac
	Generator173 = 0xad
	Generator178 = 0xb2
	Generator180 = 0xb4
	Generator183 = 0xb7
	Generator184 = 0xb8
	Generator185 = 0xb9
	Generator186 = 0xba
	Generator190 = 0xbe
	Generator191 = 0xbf
	Generator192 = 0xc0
	Generator193 = 0xc1
	Generator196 = 0xc4
	Generator200 = 0xc8
	Generator201 = 0xc9
	Generator206 = 0xce
	Generator207 = 0xcf
	Generator208 = 0xd0
	Generator214 = 0xd6
	Generator215 = 0xd7
	Generator218 = 0xda
	Generator220 = 0xdc
	Generator221 = 0xdd
	Generator222 = 0xde
	Generator226 = 0xe2
	Generator227 = 0xe3
	Generator229 = 0xe5
	Generator230 = 0xe6
	Generator231 = 0xe7
	Generator233 = 0xe9
	Generator234 = 0xea
	Generator235 = 0xeb
	Generator238 = 0xee
	Generator240 = 0xf0
	Generator241 = 0xf1
	Generator244 = 0xf4
	Generator245 = 0xf5
	Generator246 = 0xf6
	Generator248 = 0xf8
	Generator251 = 0xfb
	Generator253 = 0xfd
	Generator254 = 0xfe
	Generator255 = 0xff
)

// Generators contains the primitive generators listed above. The slice is provided
// for iteration; table constructors validate generators independently.
var Generators = []Generator{
	Generator003, Generator005, Generator006, Generator009,
	Generator011, Generator014, Generator017, Generator018,
	Generator019, Generator020, Generator023, Generator024,
	Generator025, Generator026, Generator028, Generator030,
	Generator031, Generator033, Generator034, Generator035,
	Generator039, Generator040, Generator042, Generator044,
	Generator048, Generator049, Generator060, Generator062,
	Generator063, Generator065, Generator069, Generator070,
	Generator071, Generator072, Generator073, Generator075,
	Generator076, Generator078, Generator079, Generator082,
	Generator084, Generator086, Generator087, Generator088,
	Generator089, Generator090, Generator091, Generator095,
	Generator100, Generator101, Generator104, Generator105,
	Generator109, Generator110, Generator112, Generator113,
	Generator118, Generator119, Generator121, Generator122,
	Generator123, Generator126, Generator129, Generator132,
	Generator134, Generator135, Generator136, Generator138,
	Generator142, Generator143, Generator144, Generator147,
	Generator149, Generator150, Generator152, Generator153,
	Generator155, Generator157, Generator160, Generator164,
	Generator165, Generator166, Generator167, Generator169,
	Generator170, Generator172, Generator173, Generator178,
	Generator180, Generator183, Generator184, Generator185,
	Generator186, Generator190, Generator191, Generator192,
	Generator193, Generator196, Generator200, Generator201,
	Generator206, Generator207, Generator208, Generator214,
	Generator215, Generator218, Generator220, Generator221,
	Generator222, Generator226, Generator227, Generator229,
	Generator230, Generator231, Generator233, Generator234,
	Generator235, Generator238, Generator240, Generator241,
	Generator244, Generator245, Generator246, Generator248,
	Generator251, Generator253, Generator254, Generator255,
}
