// Copyright (c) 2016 Thomas Pornin <pornin@bolet.org>
// Copyright (c) 2017 Yawning Angel <yawning at schwanenlied dot me>
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
// BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
// ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package ghash

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// The test vectors are shamelessly stolen from "The  Galois/Counter Mode of
// Operation (GCM)", which is what BearSSL does.
//
// http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-revised-spec.pdf

var ghashVectors = []struct {
	h string
	a string
	c string
	y string
}{
	{
		"66e94bd4ef8a2c3b884cfa59ca342b2e",
		"",
		"",
		"00000000000000000000000000000000",
	},
	{
		"66e94bd4ef8a2c3b884cfa59ca342b2e",
		"",
		"0388dace60b6a392f328c2b971b2fe78",
		"f38cbb1ad69223dcc3457ae5b6b0f885",
	},
	{
		"b83b533708bf535d0aa6e52980d53b78",
		"",
		"42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985",
		"7f1b32b81b820d02614f8895ac1d4eac",
	},
	{
		"b83b533708bf535d0aa6e52980d53b78",
		"feedfacedeadbeeffeedfacedeadbeefabaddad2",
		"42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
		"698e57f70e6ecc7fd9463b7260a9ae5f",
	},
	{
		"b83b533708bf535d0aa6e52980d53b78",
		"feedfacedeadbeeffeedfacedeadbeefabaddad2",
		"61353b4c2806934a777ff51fa22a4755699b2a714fcdc6f83766e5f97b6c742373806900e49f24b22b097544d4896b424989b5e1ebac0f07c23f4598",
		"df586bb4c249b92cb6922877e444d37b",
	},
	{
		"b83b533708bf535d0aa6e52980d53b78",
		"feedfacedeadbeeffeedfacedeadbeefabaddad2",
		"8ce24998625615b603a033aca13fb894be9112a5c3a211a8ba262a3cca7e2ca701e4a9a4fba43c90ccdcb281d48c7c6fd62875d2aca417034c34aee5",
		"1c5afe9760d3932f3c9a878aac3dc3de",
	},
}

func gcmGHASH(y, h *[blockSize]byte, a, c []byte) {
	var p [blockSize]byte
	Ghash(y, h, a)
	Ghash(y, h, c)
	binary.BigEndian.PutUint32(p[4:], uint32(len(a))<<3)
	binary.BigEndian.PutUint32(p[12:], uint32(len(c))<<3)
	Ghash(y, h, p[:])
}

func TestGHASH(t *testing.T) {
	for i, vec := range ghashVectors {
		hh, err := hex.DecodeString(vec.h[:])
		if err != nil {
			t.Fatal(err)
		}
		a, err := hex.DecodeString(vec.a[:])
		if err != nil {
			t.Fatal(err)
		}
		c, err := hex.DecodeString(vec.c[:])
		if err != nil {
			t.Fatal(err)
		}
		yy, err := hex.DecodeString(vec.y[:])
		if err != nil {
			t.Fatal(err)
		}

		var h, y [blockSize]byte
		copy(h[:], hh)

		gcmGHASH(&y, &h, a, c)
		assertEqual(t, i, yy[:], y[:])
	}
}

func assertEqual(t *testing.T, idx int, expected, actual []byte) {
	if !bytes.Equal(expected, actual) {
		for i, v := range actual {
			if expected[i] != v {
				t.Errorf("[%d] first mismatch at offset: %d (%02x != %02x)", idx, i, expected[i], v)
				break
			}
		}
		t.Errorf("expected: %s", hex.Dump(expected))
		t.Errorf("actual: %s", hex.Dump(actual))
		t.FailNow()
	}
}

var ghashBenchOutput [blockSize]byte

func BenchmarkGHASH(b *testing.B) {
	var y, h [blockSize]byte
	var buf [8192]byte

	if _, err := rand.Read(buf[:]); err != nil {
		b.Error(err)
		b.Fail()
	}
	if _, err := rand.Read(h[:]); err != nil {
		b.Error(err)
		b.Fail()
	}

	b.SetBytes(int64(len(buf)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Ghash(&y, &h, buf[:])
	}
	b.StopTimer()
	copy(ghashBenchOutput[:], y[:])
}
