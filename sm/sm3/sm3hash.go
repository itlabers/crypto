/*
Copyright IBM Corp. 2017 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	SPDX-License-Identifier: Apache-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package sm3

func leftRotate(x uint32, r uint32) uint32 { return x<<(r%32) | x>>(32-r%32) }

func ff0(X uint32, Y uint32, Z uint32) uint32 { return X ^ Y ^ Z }
func ff1(X uint32, Y uint32, Z uint32) uint32 { return (X & Y) | (X & Z) | (Y & Z) }

func gg0(X uint32, Y uint32, Z uint32) uint32 { return X ^ Y ^ Z }
func gg1(X uint32, Y uint32, Z uint32) uint32 { return (X & Y) | ((^X) & Z) }

func p0(X uint32) uint32 { return X ^ leftRotate(X, 9) ^ leftRotate(X, 17) }

func p1(X uint32) uint32 { return X ^ leftRotate(X, 15) ^ leftRotate(X, 23) }

var T = [64]uint32{
	0x79CC4519, 0xF3988A32, 0xE7311465, 0xCE6228CB, 0x9CC45197, 0x3988A32F, 0x7311465E, 0xE6228CBC,
	0xCC451979, 0x988A32F3, 0x311465E7, 0x6228CBCE, 0xC451979C, 0x88A32F39, 0x11465E73, 0x228CBCE6,
	0x9D8A7A87, 0x3B14F50F, 0x7629EA1E, 0xEC53D43C, 0xD8A7A879, 0xB14F50F3, 0x629EA1E7, 0xC53D43CE,
	0x8A7A879D, 0x14F50F3B, 0x29EA1E76, 0x53D43CEC, 0xA7A879D8, 0x4F50F3B1, 0x9EA1E762, 0x3D43CEC5,
	0x7A879D8A, 0xF50F3B14, 0xEA1E7629, 0xD43CEC53, 0xA879D8A7, 0x50F3B14F, 0xA1E7629E, 0x43CEC53D,
	0x879D8A7A, 0x0F3B14F5, 0x1E7629EA, 0x3CEC53D4, 0x79D8A7A8, 0xF3B14F50, 0xE7629EA1, 0xCEC53D43,
	0x9D8A7A87, 0x3B14F50F, 0x7629EA1E, 0xEC53D43C, 0xD8A7A879, 0xB14F50F3, 0x629EA1E7, 0xC53D43CE,
	0x8A7A879D, 0x14F50F3B, 0x29EA1E76, 0x53D43CEC, 0xA7A879D8, 0x4F50F3B1, 0x9EA1E762, 0x3D43CEC5}

func msgPadding(message []byte) []byte {
	// Pre-processing:
	chunk := message

	// Pre-processing: adding a single 1 bit
	chunk = append(chunk, byte(0x80))

	// Pre-processing: padding with zeros
	padding := 56 - len(chunk)%64
	for i := 0; i < padding; i++ {
		chunk = append(chunk, 0x00)
	}
	var l uint64
	l = uint64(len(message) * 8)
	chunk = append(chunk, byte((l>>56)&0xff), byte((l>>48)&0xff), byte((l>>40)&0xff), byte((l>>32)&0xff), byte((l>>24)&0xff), byte((l>>16)&0xff), byte((l>>8)&0xff), byte(l&0xff))
	return chunk
}

func cF(V [8]uint32, Bmsg [16]uint32) [8]uint32 {
	var j int
	var A, B, C, D, E, F, G, H uint32
	A = V[0]
	B = V[1]
	C = V[2]
	D = V[3]
	E = V[4]
	F = V[5]
	G = V[6]
	H = V[7]

	var i int
	var w [68]uint32
	for i = 0; i < 16; i++ {
		w[i] = Bmsg[i]
	}
	for i = 16; i < 68; i++ {
		w[i] = p1(w[i-16]^w[i-9]^leftRotate(w[i-3], 15)) ^ leftRotate(w[i-13], 7) ^ w[i-6]
	}
	for j = 0; j < 16; j++ {
		SS2 := leftRotate(A, 12)
		SS1 := leftRotate(SS2+E+T[j], 7)
		SS2 = SS1 ^ SS2
		TT1 := ff0(A, B, C) + D + SS2 + (w[j] ^ w[j+4])
		TT2 := gg0(E, F, G) + H + SS1 + w[j]
		D = C
		C = leftRotate(B, 9)
		B = A
		A = TT1
		H = G
		G = leftRotate(F, 19)
		F = E
		E = p0(TT2)
	}
	for j = 16; j < 64; j++ {
		SS2 := leftRotate(A, 12)
		SS1 := leftRotate(SS2+E+T[j], 7)
		SS2 = SS1 ^ SS2
		TT1 := ff1(A, B, C) + D + SS2 + (w[j] ^ w[j+4])
		TT2 := gg1(E, F, G) + H + SS1 + w[j]
		D = C
		C = leftRotate(B, 9)
		B = A
		A = TT1
		H = G
		G = leftRotate(F, 19)
		F = E
		E = p0(TT2)
	}

	V[0] = A ^ V[0]
	V[1] = B ^ V[1]
	V[2] = C ^ V[2]
	V[3] = D ^ V[3]
	V[4] = E ^ V[4]
	V[5] = F ^ V[5]
	V[6] = G ^ V[6]
	V[7] = H ^ V[7]

	return V
}

func Block(dig *digest, p []byte) {
	var V [8]uint32
	for i := 0; i < 8; i++ {
		V[i] = dig.h[i]
	}
	for len(p) >= 64 {
		m := [16]uint32{}
		x := p[:64]
		xi := 0
		mi := 0
		for mi < 16 {
			m[mi] = (uint32(x[xi+3]) |
				(uint32(x[xi+2]) << 8) |
				(uint32(x[xi+1]) << 16) |
				(uint32(x[xi]) << 24))
			mi += 1
			xi += 4
		}
		V = cF(V, m)
		p = p[64:]
	}
	for i := 0; i < 8; i++ {
		dig.h[i] = V[i]
	}
}
