// Copyright 2015, 2018, 2019 Opsmate, Inc. All rights reserved.
// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package pkcs12 implements some of PKCS#12 (also known as P12 or PFX).
// It is intended for decoding DER-encoded P12/PFX files for use with the crypto/tls
// package, and for encoding P12/PFX files for use by legacy applications which
// do not support newer formats.  Since PKCS#12 uses weak encryption
// primitives, it SHOULD NOT be used for new applications.
//
// Note that only DER-encoded PKCS#12 files are supported, even though PKCS#12
// allows BER encoding.  This is because encoding/asn1 only supports DER.
//
// # Decoding
//
// Depending on your use case, you may choose from the different decoding functions:
//   - [Decode] reads exactly one private key and certificate
//   - [DecodeChain] reads exactly one private key, certificate and related root CA certificate chain
//   - [DecodeChains] reads multiple private keys, certificates and related root CA certificate chains
//   - [DecodeTrustStore] reads multiple certificates, as commonly used in Java trust stores
//
// # Encoding
//
// Before encoding you must choose a specialized Encoder version, one of:
//   - [Modern2023] encryption used is PBES2 with PBKDF2-HMAC-SHA-256 and AES-256-CBC; recommended for new applications
//   - [LegacyDES] weak encryption used is 3DES using keys derived of HMAC-SHA-1; only for backward compatibility
//   - [LegacyRC2] weak encryption used (RC2, and 3DES); only for older Java 8 trust stores
//
// These encoder types offer multiple options to encode PKCS#12 data exists, and you may choose from:
//   - [Encoder.Encode] writes a private key and its certificate and related root CA certificates (chain)
//   - [Encoder.EncodeTrustStore] writes just certificates, compatible to Java trust store format
//   - [Encoder.EncodeTrustStoreEntries] writes friendly names and certificates, compatible to Java trust store format
//
// This package is forked from golang.org/x/crypto/pkcs12, which is frozen.
// The implementation is distilled from https://tools.ietf.org/html/rfc7292
// and referenced documents.
package pkcs12 // import "software.sslmate.com/src/go-pkcs12"

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
)

// DefaultPassword is the string "changeit", a commonly-used password for
// PKCS#12 files.
const DefaultPassword = "changeit"

var (
	oidDataContentType          = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 7, 1})
	oidEncryptedDataContentType = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 7, 6})

	oidFriendlyName     = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 9, 20})
	oidLocalKeyID       = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 9, 21})
	oidMicrosoftCSPName = asn1.ObjectIdentifier([]int{1, 3, 6, 1, 4, 1, 311, 17, 1})

	oidJavaTrustStore      = asn1.ObjectIdentifier([]int{2, 16, 840, 1, 113894, 746875, 1, 1})
	oidAnyExtendedKeyUsage = asn1.ObjectIdentifier([]int{2, 5, 29, 37, 0})
)

type pfxPdu struct {
	Version  int
	AuthSafe contentInfo
	MacData  macData `asn1:"optional"`
}

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"tag:0,explicit,optional"`
}

type encryptedData struct {
	Version              int
	EncryptedContentInfo encryptedContentInfo
}

type encryptedContentInfo struct {
	ContentType                asn1.ObjectIdentifier
	ContentEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedContent           []byte `asn1:"tag:0,optional"`
}

func (i encryptedContentInfo) Algorithm() pkix.AlgorithmIdentifier {
	return i.ContentEncryptionAlgorithm
}

func (i encryptedContentInfo) Data() []byte { return i.EncryptedContent }

func (i *encryptedContentInfo) SetData(data []byte) { i.EncryptedContent = data }

type pkcs12Attribute struct {
	Id    asn1.ObjectIdentifier
	Value asn1.RawValue `asn1:"set"`
}

type encryptedPrivateKeyInfo struct {
	AlgorithmIdentifier pkix.AlgorithmIdentifier
	EncryptedData       []byte
}

func (i encryptedPrivateKeyInfo) Algorithm() pkix.AlgorithmIdentifier {
	return i.AlgorithmIdentifier
}

func (i encryptedPrivateKeyInfo) Data() []byte {
	return i.EncryptedData
}

func (i *encryptedPrivateKeyInfo) SetData(data []byte) {
	i.EncryptedData = data
}

// unmarshal calls asn1.Unmarshal, but also returns an error if there is any
// trailing data after unmarshalling.
func unmarshal(in []byte, out interface{}) error {
	trailing, err := asn1.Unmarshal(in, out)
	if err != nil {
		return err
	}
	if len(trailing) != 0 {
		return errors.New("pkcs12: trailing data found")
	}
	return nil
}
