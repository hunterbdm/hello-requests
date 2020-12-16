// Copyright (c) 2019 Yawning Angel <yawning at schwanenlied dot me>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package tls

import (
	"crypto/aes"
	"crypto/cipher"

	"gitlab.com/yawning/bsaes.git"
)

var aesNewCipher func([]byte) (cipher.Block, error)

// EnableVartimeAES allows utls connections to the faster but insecure
// AES and GHASH implementation on certain hardware configurations.  When
// running on devices where the runtime `crypto/aes` implementation is
// constant time, this option has no effect.
func EnableVartimeAES() {
	aesNewCipher = aes.NewCipher
}

func init() {
	// Platforms where the runtime has optimized GCM-AES are the only
	// platforms where it is actually safe to use `crypto/aes` if you
	// care about cache timing attacks.
	//
	// Note: `s390x` may also be safe from skimming the Go source, but
	// upstream utls apparently had trouble getting it to work correctly.
	if hasGCMAsm {
		aesNewCipher = aes.NewCipher
	} else {
		aesNewCipher = bsaes.NewCipher
	}
}
