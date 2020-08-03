// aes_test.go - AES tests.
//
// To the extent possible under law, Yawning Angel has waived all copyright
// and related or neighboring rights to aes_test.go, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package bsaes

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math"
	"testing"

	"github.com/hunterbdm/hello-requests/bsaes/ct32"
	"github.com/hunterbdm/hello-requests/bsaes/ct64"
)

type Impl struct {
	name string
	ctor func([]byte) cipher.Block
}

var (
	implCt32    = &Impl{"ct32", ct32.NewCipher}
	implCt64    = &Impl{"ct64", ct64.NewCipher}
	implRuntime = &Impl{"runtime", func(k []byte) cipher.Block {
		blk, err := NewCipher(k)
		if err != nil {
			panic("implRuntime: NewCipher failed: " + err.Error())
		}
		return blk
	}}

	impls      = []*Impl{implCt32, implCt64}
	nativeImpl = implCt64
)

// The test vectors are shamelessly stolen from NIST Special Pub. 800-38A,
// my tax dollars at work.
//
// http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf

var ecbVectors = []struct {
	key        string
	plaintext  string
	ciphertext string
}{
	// ECB-AES128
	{
		"2b7e151628aed2a6abf7158809cf4f3c",
		"6bc1bee22e409f96e93d7e117393172a",
		"3ad77bb40d7a3660a89ecaf32466ef97",
	},
	{
		"2b7e151628aed2a6abf7158809cf4f3c",
		"ae2d8a571e03ac9c9eb76fac45af8e51",
		"f5d3d58503b9699de785895a96fdbaaf",
	},
	{
		"2b7e151628aed2a6abf7158809cf4f3c",
		"30c81c46a35ce411e5fbc1191a0a52ef",
		"43b1cd7f598ece23881b00e3ed030688",
	},
	{
		"2b7e151628aed2a6abf7158809cf4f3c",
		"f69f2445df4f9b17ad2b417be66c3710",
		"7b0c785e27e8ad3f8223207104725dd4",
	},

	// ECB-AES192
	{
		"8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
		"6bc1bee22e409f96e93d7e117393172a",
		"bd334f1d6e45f25ff712a214571fa5cc",
	},
	{
		"8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
		"ae2d8a571e03ac9c9eb76fac45af8e51",
		"974104846d0ad3ad7734ecb3ecee4eef",
	},
	{
		"8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
		"30c81c46a35ce411e5fbc1191a0a52ef",
		"ef7afd2270e2e60adce0ba2face6444e",
	},
	{
		"8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
		"f69f2445df4f9b17ad2b417be66c3710",
		"9a4b41ba738d6c72fb16691603c18e0e",
	},

	// ECB-AES256
	{
		"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
		"6bc1bee22e409f96e93d7e117393172a",
		"f3eed1bdb5d2a03c064b5a7e3db181f8",
	},
	{
		"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
		"ae2d8a571e03ac9c9eb76fac45af8e51",
		"591ccb10d410ed26dc5ba74a31362870",
	},
	{
		"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
		"30c81c46a35ce411e5fbc1191a0a52ef",
		"b6ed21b99ca6f4f9f153e7b1beafed1d",
	},
	{
		"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
		"f69f2445df4f9b17ad2b417be66c3710",
		"23304b7a39f9f3ff067d8d8f9e24ecc7",
	},
}

func TestECB_SP800_38A(t *testing.T) {
	for _, impl := range impls {
		t.Logf("Testing implementation: %v\n", impl.name)
		for i, vec := range ecbVectors {
			key, err := hex.DecodeString(vec.key[:])
			if err != nil {
				t.Fatal(err)
			}
			pt, err := hex.DecodeString(vec.plaintext[:])
			if err != nil {
				t.Fatal(err)
			}
			ct, err := hex.DecodeString(vec.ciphertext[:])
			if err != nil {
				t.Fatal(err)
			}

			b := impl.ctor(key)

			var dst [16]byte
			b.Encrypt(dst[:], pt)
			assertEqual(t, i, ct, dst[:])

			b.Decrypt(dst[:], ct)
			assertEqual(t, i, pt, dst[:])
		}
	}
}

var ctrVectors = []struct {
	key        string
	iv         string
	plaintext  string
	ciphertext string
}{
	// CTR-AES128
	{
		"2b7e151628aed2a6abf7158809cf4f3c",
		"f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
		"6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
		"874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee",
	},
	// CTR-AES192
	{
		"8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
		"f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
		"6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
		"1abc932417521ca24f2b0459fe7e6e0b090339ec0aa6faefd5ccc2c6f4ce8e941e36b26bd1ebc670d1bd1d665620abf74f78a7f6d29809585a97daec58c6b050",
	},
	// CTR-AES256
	{
		"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
		"f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
		"6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
		"601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c52b0930daa23de94ce87017ba2d84988ddfc9c58db67aada613c2dd08457941a6",
	},
}

func TestCTR_SP800_38A(t *testing.T) {
	for _, impl := range impls {
		t.Logf("Testing implementation: %v\n", impl.name)
		for i, vec := range ctrVectors {
			key, err := hex.DecodeString(vec.key[:])
			if err != nil {
				t.Fatal(err)
			}
			iv, err := hex.DecodeString(vec.iv[:])
			if err != nil {
				t.Fatal(err)
			}
			ct, err := hex.DecodeString(vec.ciphertext[:])
			if err != nil {
				t.Fatal(err)
			}
			pt, err := hex.DecodeString(vec.plaintext[:])
			if err != nil {
				t.Fatal(err)
			}

			b := impl.ctor(key)
			dst := make([]byte, len(ct))

			ctr := cipher.NewCTR(b, iv)
			ctr.XORKeyStream(dst, pt)
			assertEqual(t, i, ct, dst)
		}
	}
}

func TestCTR_keystream(t *testing.T) {
	var iv [16]byte

	for _, impl := range impls {
		strideSz := 0
		switch impl.name {
		case "ct32":
			strideSz = 2 * 16
		case "ct64":
			strideSz = 4 * 16
		case "runtime":
			// The CTR tests are tailored towards the bsaes CTR
			// so there is not much sense in testing `crypto/aes`'s,
			// when it's using AES-NI and assembly.
			t.Logf("Skipping CTR tests: %v\n", impl.name)
			continue
		default:
			panic("unable to determine stride")
		}
		t.Logf("Testing implementation: %v\n", impl.name)

		key := make([]byte, 16)
		if _, err := rand.Read(key[:]); err != nil {
			t.Error(err)
			t.Fail()
		}

		for sz := 0; sz <= strideSz; sz++ {
			blk := impl.ctor(key[:])
			ctr := cipher.NewCTR(blk, iv[:])

			refBlk, _ := aes.NewCipher(key[:])
			refCtr := cipher.NewCTR(refBlk, iv[:])

			n := sz + strideSz + sz
			src := make([]byte, n)
			dst := make([]byte, n)
			check := make([]byte, n)

			if _, err := rand.Read(src[:]); err != nil {
				t.Error(err)
				t.Fail()
			}

			ctr.XORKeyStream(dst, src[:sz])
			ctr.XORKeyStream(dst[sz:], src[sz:sz+strideSz])
			ctr.XORKeyStream(dst[sz+strideSz:], src[sz+strideSz:])

			refCtr.XORKeyStream(check, src)
			assertEqual(t, sz, check, dst)
		}
	}
}

var cbcDecVectors = []struct {
	key        string
	iv         string
	ciphertext string
	plaintext  string
}{
	// CBC-AES128
	{
		"2b7e151628aed2a6abf7158809cf4f3c",
		"000102030405060708090a0b0c0d0e0f",
		"7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7",
		"6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
	},
	// CBC-AES192
	{
		"8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
		"000102030405060708090a0b0c0d0e0f",
		"4f021db243bc633d7178183a9fa071e8b4d9ada9ad7dedf4e5e738763f69145a571b242012fb7ae07fa9baac3df102e008b0e27988598881d920a9e64f5615cd",
		"6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
	},
	// CBC-AES256
	{

		"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
		"000102030405060708090a0b0c0d0e0f",
		"f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b",
		"6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
	},
}

func TestCBCDecrypt_SP800_38A(t *testing.T) {
	for _, impl := range impls {
		t.Logf("Testing implementation: %v\n", impl.name)
		for i, vec := range cbcDecVectors {
			key, err := hex.DecodeString(vec.key[:])
			if err != nil {
				t.Fatal(err)
			}
			iv, err := hex.DecodeString(vec.iv[:])
			if err != nil {
				t.Fatal(err)
			}
			ct, err := hex.DecodeString(vec.ciphertext[:])
			if err != nil {
				t.Fatal(err)
			}
			pt, err := hex.DecodeString(vec.plaintext[:])
			if err != nil {
				t.Fatal(err)
			}

			b := impl.ctor(key)
			dst := make([]byte, len(ct))

			cbc := cipher.NewCBCDecrypter(b, iv)
			cbc.CryptBlocks(dst, ct)
			assertEqual(t, i, pt, dst)
		}
	}
}

var gcmVectors = []struct {
	k  string
	iv string
	a  string
	p  string
	c  string
	t  string
}{
	// GCM-AES128
	{
		"00000000000000000000000000000000",
		"000000000000000000000000",
		"",
		"",
		"",
		"58e2fccefa7e3061367f1d57a4e7455a",
	},
	{
		"00000000000000000000000000000000",
		"000000000000000000000000",
		"",
		"00000000000000000000000000000000",
		"0388dace60b6a392f328c2b971b2fe78",
		"ab6e47d42cec13bdf53a67b21257bddf",
	},
	{
		"feffe9928665731c6d6a8f9467308308",
		"cafebabefacedbaddecaf888",
		"",
		"d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
		"42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985",
		"4d5c2af327cd64a62cf35abd2ba6fab4",
	},
	{
		"feffe9928665731c6d6a8f9467308308",
		"cafebabefacedbaddecaf888",
		"feedfacedeadbeeffeedfacedeadbeefabaddad2",
		"d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
		"42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
		"5bc94fbc3221a5db94fae95ae7121a47",
	},
	{
		"feffe9928665731c6d6a8f9467308308",
		"cafebabefacedbad",
		"feedfacedeadbeeffeedfacedeadbeefabaddad2",
		"d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
		"61353b4c2806934a777ff51fa22a4755699b2a714fcdc6f83766e5f97b6c742373806900e49f24b22b097544d4896b424989b5e1ebac0f07c23f4598",
		"3612d2e79e3b0785561be14aaca2fccb",
	},
	{
		"feffe9928665731c6d6a8f9467308308",
		"9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b",
		"feedfacedeadbeeffeedfacedeadbeefabaddad2",
		"d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
		"8ce24998625615b603a033aca13fb894be9112a5c3a211a8ba262a3cca7e2ca701e4a9a4fba43c90ccdcb281d48c7c6fd62875d2aca417034c34aee5",
		"619cc5aefffe0bfa462af43c1699d050",
	},
	// GCM-AES192
	{
		"000000000000000000000000000000000000000000000000",
		"000000000000000000000000",
		"",
		"",
		"",
		"cd33b28ac773f74ba00ed1f312572435",
	},
	{
		"000000000000000000000000000000000000000000000000",
		"000000000000000000000000",
		"",
		"00000000000000000000000000000000",
		"98e7247c07f0fe411c267e4384b0f600",
		"2ff58d80033927ab8ef4d4587514f0fb",
	},
	{
		"feffe9928665731c6d6a8f9467308308feffe9928665731c",
		"cafebabefacedbaddecaf888",
		"",
		"d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
		"3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c7d773d00c144c525ac619d18c84a3f4718e2448b2fe324d9ccda2710acade256",
		"9924a7c8587336bfb118024db8674a14",
	},
	{
		"feffe9928665731c6d6a8f9467308308feffe9928665731c",
		"cafebabefacedbaddecaf888",
		"feedfacedeadbeeffeedfacedeadbeefabaddad2",
		"d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
		"3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c7d773d00c144c525ac619d18c84a3f4718e2448b2fe324d9ccda2710",
		"2519498e80f1478f37ba55bd6d27618c",
	},
	{
		"feffe9928665731c6d6a8f9467308308feffe9928665731c",
		"cafebabefacedbad",
		"feedfacedeadbeeffeedfacedeadbeefabaddad2",
		"d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
		"0f10f599ae14a154ed24b36e25324db8c566632ef2bbb34f8347280fc4507057fddc29df9a471f75c66541d4d4dad1c9e93a19a58e8b473fa0f062f7",
		"65dcc57fcf623a24094fcca40d3533f8",
	},
	{
		"feffe9928665731c6d6a8f9467308308feffe9928665731c",
		"9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b",
		"feedfacedeadbeeffeedfacedeadbeefabaddad2",
		"d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
		"d27e88681ce3243c4830165a8fdcf9ff1de9a1d8e6b447ef6ef7b79828666e4581e79012af34ddd9e2f037589b292db3e67c036745fa22e7e9b7373b",
		"dcf566ff291c25bbb8568fc3d376a6d9",
	},
	// GCM-AES256
	{
		"0000000000000000000000000000000000000000000000000000000000000000",
		"000000000000000000000000",
		"",
		"",
		"",
		"530f8afbc74536b9a963b4f1c4cb738b",
	},
	{
		"0000000000000000000000000000000000000000000000000000000000000000",
		"000000000000000000000000",
		"",
		"00000000000000000000000000000000",
		"cea7403d4d606b6e074ec5d3baf39d18",
		"d0d1c8a799996bf0265b98b5d48ab919",
	},
	{
		"feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
		"cafebabefacedbaddecaf888",
		"",
		"d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
		"522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad",
		"b094dac5d93471bdec1a502270e3cc6c",
	},
	{
		"feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
		"cafebabefacedbaddecaf888",
		"feedfacedeadbeeffeedfacedeadbeefabaddad2",
		"d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
		"522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
		"76fc6ece0f4e1768cddf8853bb2d551b",
	},
	{
		"feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
		"cafebabefacedbad",
		"feedfacedeadbeeffeedfacedeadbeefabaddad2",
		"d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
		"c3762df1ca787d32ae47c13bf19844cbaf1ae14d0b976afac52ff7d79bba9de0feb582d33934a4f0954cc2363bc73f7862ac430e64abe499f47c9b1f",
		"3a337dbf46a792c45e454913fe2ea8f2",
	},
	{
		"feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
		"9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b",
		"feedfacedeadbeeffeedfacedeadbeefabaddad2",
		"d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
		"5a8def2f0c9e53f1f75d7853659e2a20eeb2b22aafde6419a058ab4f6f746bf40fc0c3b780f244452da3ebf1c5d82cdea2418997200ef82e44ae7e3f",
		"a44a8266ee1c8eb0c8b5d4cf5ae9f19a",
	},
}

func TestGCM(t *testing.T) {
	for _, impl := range impls {
		t.Logf("Testing implementation: %v\n", impl.name)
		for i, vec := range gcmVectors {
			key, err := hex.DecodeString(vec.k[:])
			if err != nil {
				t.Fatal(err)
			}
			iv, err := hex.DecodeString(vec.iv[:])
			if err != nil {
				t.Fatal(err)
			}
			a, err := hex.DecodeString(vec.a[:])
			if err != nil {
				t.Fatal(err)
			}
			p, err := hex.DecodeString(vec.p[:])
			if err != nil {
				t.Fatal(err)
			}
			c, err := hex.DecodeString(vec.c[:])
			if err != nil {
				t.Fatal(err)
			}
			tag, err := hex.DecodeString(vec.t[:])
			if err != nil {
				t.Fatal(err)
			}
			sealOut := make([]byte, 0, len(c)+len(tag))
			sealOut = append(sealOut, c...)
			sealOut = append(sealOut, tag...)

			b := impl.ctor(key[:])
			g, err := cipher.NewGCMWithNonceSize(b, len(iv))
			if err != nil {
				t.Fatal(err)
			}

			ct := g.Seal(nil, iv, p, a)
			assertEqual(t, i, sealOut, ct)

			pt, err := g.Open(nil, iv, ct, a)
			if err != nil {
				t.Fatal(err)
			}
			assertEqual(t, i, p, pt)
		}
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

var ecbBenchOutput [16]byte

func doBenchECB(b *testing.B, impl *Impl, ksz int) {
	var src, dst, check [16]byte

	key := make([]byte, ksz)
	if _, err := rand.Read(key[:]); err != nil {
		b.Error(err)
		b.Fail()
	}

	blk := impl.ctor(key[:])

	b.SetBytes(16)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StartTimer()
		blk.Encrypt(dst[:], src[:])
		b.StopTimer()

		// Check forward/back because, why not.
		blk.Decrypt(check[:], dst[:])
		if !bytes.Equal(check[:], src[:]) {
			b.Fatalf("decrypt produced invalid output")
		}
		copy(src[:], dst[:])
	}
	copy(ecbBenchOutput[:], dst[:])
}

var benchOutput []byte

func doBenchCTR(b *testing.B, impl *Impl, ksz, n int) {
	var iv [16]byte

	key := make([]byte, ksz)
	if _, err := rand.Read(key[:]); err != nil {
		b.Error(err)
		b.Fail()
	}

	blk := impl.ctor(key[:])
	ctr := cipher.NewCTR(blk, iv[:])

	src := make([]byte, n)
	dst := make([]byte, n)

	b.SetBytes(int64(n))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctr.XORKeyStream(dst, src)
	}
	benchOutput = dst
}

func doBenchCBC(b *testing.B, impl *Impl, ksz, n int) {
	var iv [16]byte
	key := make([]byte, ksz)

	if _, err := rand.Read(key[:]); err != nil {
		b.Error(err)
		b.Fail()
	}

	blk := impl.ctor(key[:])
	cbc := cipher.NewCBCDecrypter(blk, iv[:])

	src := make([]byte, n)
	dst := make([]byte, n)

	b.SetBytes(int64(n))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cbc.CryptBlocks(dst, src)
	}
	benchOutput = dst
}

func doBenchGCM(b *testing.B, impl *Impl, ksz, n int) {
	var iv [96 / 8]byte
	key := make([]byte, ksz)

	if _, err := rand.Read(key[:]); err != nil {
		b.Error(err)
		b.Fail()
	}

	blk := impl.ctor(key[:])
	gcm, err := cipher.NewGCM(blk)
	if err != nil {
		b.Error(err)
		b.Fail()
	}

	src := make([]byte, n)
	var dst []byte

	b.SetBytes(int64(n))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dst = gcm.Seal(nil, iv[:], src, nil)
	}
	benchOutput = dst
}

func implIsNative(impl *Impl) bool {
	return impl == nativeImpl || impl == implRuntime
}

func doBench(b *testing.B, impl *Impl) {
	if testing.Short() && !implIsNative(impl) {
		b.SkipNow()
	}

	b.SetParallelism(1) // We want per-core figures.

	b.Run("ECB-AES128", func(b *testing.B) { doBenchECB(b, implCt32, 16) })
	if !testing.Short() { // No one cares about this mode.
		b.Run("ECB-AES192", func(b *testing.B) { doBenchECB(b, implCt32, 24) })
	}
	b.Run("ECB-AES256", func(b *testing.B) { doBenchECB(b, implCt32, 32) })

	for _, sz := range []int{16, 64, 256, 1024, 8192, 16384} {
		n := fmt.Sprintf("CTR-AES128_%d", sz)
		b.Run(n, func(b *testing.B) { doBenchCTR(b, impl, 16, sz) })
	}
	for _, sz := range []int{16, 64, 256, 1024, 8192, 16384} {
		n := fmt.Sprintf("DecryptCBC-AES128_%d", sz)
		b.Run(n, func(b *testing.B) { doBenchCBC(b, impl, 16, sz) })
	}
	for _, sz := range []int{16, 64, 256, 1024, 8192, 16384} {
		n := fmt.Sprintf("GCM-AES128_%d", sz)
		b.Run(n, func(b *testing.B) { doBenchGCM(b, impl, 16, sz) })
	}
}

func Benchmark_ct32(b *testing.B) {
	doBench(b, implCt32)
}

func Benchmark_ct64(b *testing.B) {
	doBench(b, implCt64)
}

func Benchmark_runtime(b *testing.B) {
	if !useCryptoAES {
		b.SkipNow()
	}
	doBench(b, implRuntime)
}

func init() {
	maxUintptr := uint64(^uintptr(0))
	switch maxUintptr {
	case math.MaxUint32:
		nativeImpl = implCt32
	case math.MaxUint64:
		nativeImpl = implCt64
	default:
		panic("bsaes: unsupported architecture")
	}
	if useCryptoAES {
		impls = append(impls, implRuntime)
	}
}
