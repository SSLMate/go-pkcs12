// Copyright 2015, 2018, 2019 Opsmate, Inc. All rights reserved.
// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkcs12

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"
)

func TestVerifyMac(t *testing.T) {
	td := macData{
		Mac: digestInfo{
			Digest: []byte{0x18, 0x20, 0x3d, 0xff, 0x1e, 0x16, 0xf4, 0x92, 0xf2, 0xaf, 0xc8, 0x91, 0xa9, 0xba, 0xd6, 0xca, 0x9d, 0xee, 0x51, 0x93},
		},
		MacSalt:    []byte{1, 2, 3, 4, 5, 6, 7, 8},
		Iterations: 2048,
	}

	message := []byte{11, 12, 13, 14, 15}
	password, _ := bmpStringZeroTerminated("")

	td.Mac.Algorithm.Algorithm = asn1.ObjectIdentifier([]int{1, 2, 3})
	err := verifyMac(&td, message, password)
	if _, ok := err.(NotImplementedError); !ok {
		t.Errorf("err: %v", err)
	}

	td.Mac.Algorithm.Algorithm = asn1.ObjectIdentifier([]int{1, 3, 14, 3, 2, 26})
	err = verifyMac(&td, message, password)
	if err != ErrIncorrectPassword {
		t.Errorf("Expected incorrect password, got err: %v", err)
	}

	password, _ = bmpStringZeroTerminated("Sesame open")
	err = verifyMac(&td, message, password)
	if err != nil {
		t.Errorf("err: %v", err)
	}

}

func TestComputeMac(t *testing.T) {
	td := macData{
		MacSalt:    []byte{1, 2, 3, 4, 5, 6, 7, 8},
		Iterations: 2048,
	}

	message := []byte{11, 12, 13, 14, 15}
	password, _ := bmpStringZeroTerminated("Sesame open")

	td.Mac.Algorithm.Algorithm = asn1.ObjectIdentifier([]int{1, 2, 3})
	err := computeMac(&td, message, password)
	if _, ok := err.(NotImplementedError); !ok {
		t.Errorf("err: %v", err)
	}

	td.Mac.Algorithm.Algorithm = asn1.ObjectIdentifier([]int{1, 3, 14, 3, 2, 26})
	err = computeMac(&td, message, password)
	if err != nil {
		t.Errorf("err: %v", err)
	}

	expectedDigest := []byte{0x18, 0x20, 0x3d, 0xff, 0x1e, 0x16, 0xf4, 0x92, 0xf2, 0xaf, 0xc8, 0x91, 0xa9, 0xba, 0xd6, 0xca, 0x9d, 0xee, 0x51, 0x93}

	if bytes.Compare(td.Mac.Digest, expectedDigest) != 0 {
		t.Errorf("Computed incorrect MAC; expected MAC to be '%d' but got '%d'", expectedDigest, td.Mac.Digest)
	}

}

func TestPBMAC1(t *testing.T) {
	// Create PBKDF2 parameters for PBMAC1
	kdfParams := pbkdf2Params{
		Salt:       asn1.RawValue{Tag: asn1.TagOctetString, Bytes: []byte{1, 2, 3, 4, 5, 6, 7, 8}},
		Iterations: 1000,
		KeyLength:  32,
		Prf:        pkix.AlgorithmIdentifier{Algorithm: oidHmacWithSHA256},
	}
	kdfParamsBytes, err := asn1.Marshal(kdfParams)
	if err != nil {
		t.Fatalf("Failed to marshal KDF params: %v", err)
	}

	// Create PBMAC1 parameters
	pbmac1Params := pbmac1Params{
		Kdf:    pkix.AlgorithmIdentifier{Algorithm: oidPBKDF2, Parameters: asn1.RawValue{FullBytes: kdfParamsBytes}},
		MacAlg: pkix.AlgorithmIdentifier{Algorithm: oidHmacWithSHA256},
	}
	pbmac1ParamsBytes, err := asn1.Marshal(pbmac1Params)
	if err != nil {
		t.Fatalf("Failed to marshal PBMAC1 params: %v", err)
	}

	// Create macData with PBMAC1 algorithm
	td := macData{
		Mac: digestInfo{
			Algorithm: pkix.AlgorithmIdentifier{
				Algorithm:  oidPBMAC1,
				Parameters: asn1.RawValue{FullBytes: pbmac1ParamsBytes},
			},
		},
		// MacSalt and Iterations should be ignored for PBMAC1
		MacSalt:    []byte{9, 10, 11, 12},
		Iterations: 999,
	}

	message := []byte{11, 12, 13, 14, 15}
	password, err := bmpStringZeroTerminated("test-password")
	if err != nil {
		t.Fatalf("Failed to encode password to BMP string: %v", err)
	}

	// Test MAC computation
	err = computeMac(&td, message, password)
	if err != nil {
		t.Errorf("Failed to compute PBMAC1: %v", err)
	}

	// Verify that MAC was computed
	if len(td.Mac.Digest) == 0 {
		t.Error("No MAC digest was computed")
	}

	// Test MAC verification
	err = verifyMac(&td, message, password)
	if err != nil {
		t.Errorf("Failed to verify PBMAC1: %v", err)
	}

	// Test with wrong password
	wrongPassword, err := bmpStringZeroTerminated("wrong-password")
	if err != nil {
		t.Fatalf("Failed to encode wrong password to BMP string: %v", err)
	}
	err = verifyMac(&td, message, wrongPassword)
	if err != ErrIncorrectPassword {
		t.Errorf("Expected ErrIncorrectPassword, got: %v", err)
	}
}
