// Copyright 2015, 2018, 2019 Opsmate, Inc. All rights reserved.
// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkcs12

import (
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"io"
)

// An Encoder contains methods for encoding PKCS#12 files.  This package
// defines several different Encoders with different parameters.
// An Encoder is safe for concurrent use by multiple goroutines.
type Encoder struct {
	macAlgorithm         asn1.ObjectIdentifier
	certAlgorithm        asn1.ObjectIdentifier
	keyAlgorithm         asn1.ObjectIdentifier
	macIterations        int
	encryptionIterations int
	saltLen              int
	rand                 io.Reader
}

// LegacyRC2 encodes PKCS#12 files using weak algorithms that were
// traditionally used in PKCS#12 files, including those produced
// by OpenSSL before 3.0.0, go-pkcs12 before 0.3.0, and Java when
// keystore.pkcs12.legacy is defined.  Specifically, certificates
// are encrypted using PBE with RC2, and keys are encrypted using PBE
// with 3DES, using keys derived with 2048 iterations of HMAC-SHA-1.
// MACs use HMAC-SHA-1 with keys derived with 1 iteration of HMAC-SHA-1.
//
// Due to the weak encryption, it is STRONGLY RECOMMENDED that you use [DefaultPassword]
// when encoding PKCS#12 files using this encoder, and protect the PKCS#12 files
// using other means.
//
// By default, OpenSSL 3 can't decode PKCS#12 files created using this encoder.
// For better compatibility, use [LegacyDES].  For better security, use
// [Modern2023].
var LegacyRC2 = &Encoder{
	macAlgorithm:         oidSHA1,
	certAlgorithm:        oidPBEWithSHAAnd40BitRC2CBC,
	keyAlgorithm:         oidPBEWithSHAAnd3KeyTripleDESCBC,
	macIterations:        1,
	encryptionIterations: 2048,
	saltLen:              8,
	rand:                 rand.Reader,
}

// LegacyDES encodes PKCS#12 files using weak algorithms that are
// supported by a wide variety of software.  Certificates and keys
// are encrypted using PBE with 3DES using keys derived with 2048
// iterations of HMAC-SHA-1.  MACs use HMAC-SHA-1 with keys derived
// with 1 iteration of HMAC-SHA-1.  These are the same parameters
// used by OpenSSL's -descert option.  As of 2023, this encoder is
// likely to produce files that can be read by the most software.
//
// Due to the weak encryption, it is STRONGLY RECOMMENDED that you use [DefaultPassword]
// when encoding PKCS#12 files using this encoder, and protect the PKCS#12 files
// using other means.  To create more secure PKCS#12 files, use [Modern2023].
var LegacyDES = &Encoder{
	macAlgorithm:         oidSHA1,
	certAlgorithm:        oidPBEWithSHAAnd3KeyTripleDESCBC,
	keyAlgorithm:         oidPBEWithSHAAnd3KeyTripleDESCBC,
	macIterations:        1,
	encryptionIterations: 2048,
	saltLen:              8,
	rand:                 rand.Reader,
}

// Passwordless encodes PKCS#12 files without any encryption or MACs.
// A lot of software has trouble reading such files, so it's probably only
// useful for creating Java trust stores using [Encoder.EncodeTrustStore]
// or [Encoder.EncodeTrustStoreEntries].
//
// When using this encoder, you MUST specify an empty password.
var Passwordless = &Encoder{
	macAlgorithm:  nil,
	certAlgorithm: nil,
	keyAlgorithm:  nil,
	rand:          rand.Reader,
}

// Modern2023 encodes PKCS#12 files using algorithms that are considered modern
// as of 2023.  Private keys and certificates are encrypted using PBES2 with
// PBKDF2-HMAC-SHA-256 and AES-256-CBC.  The MAC algorithm is HMAC-SHA-2.  These
// are the same algorithms used by OpenSSL 3 (by default), Java 20 (by default),
// and Windows Server 2019 (when "stronger" is used).
//
// Files produced with this encoder can be read by OpenSSL 1.1.1 and higher,
// Java 12 and higher, and Windows Server 2019 and higher.
//
// For passwords, it is RECOMMENDED that you do one of the following:
// 1) Use [DefaultPassword] and protect the file using other means, or
// 2) Use a high-entropy password, such as one generated with `openssl rand -hex 16`.
//
// You SHOULD NOT use a lower-entropy password with this encoder because the number of KDF
// iterations is only 2048 and doesn't provide meaningful protection against
// brute-forcing.  You can increase the number of iterations using [Encoder.WithIterations],
// but as https://neilmadden.blog/2023/01/09/on-pbkdf2-iterations/ explains, this doesn't
// help as much as you think.
var Modern2023 = &Encoder{
	macAlgorithm:         oidSHA256,
	certAlgorithm:        oidPBES2,
	keyAlgorithm:         oidPBES2,
	macIterations:        2048,
	encryptionIterations: 2048,
	saltLen:              16,
	rand:                 rand.Reader,
}

// Legacy encodes PKCS#12 files using weak, legacy parameters that work in
// a wide variety of software.
//
// Currently, this encoder is the same as [LegacyDES], but this
// may change in the future if another encoder is found to provide better
// compatibility.
//
// Due to the weak encryption, it is STRONGLY RECOMMENDED that you use [DefaultPassword]
// when encoding PKCS#12 files using this encoder, and protect the PKCS#12 files
// using other means.
var Legacy = LegacyDES

// Modern encodes PKCS#12 files using modern, robust parameters.
//
// Currently, this encoder is the same as [Modern2023], but this
// may change in the future to keep up with modern practices.
var Modern = Modern2023

// TrustStoreEntry represents an entry in a Java TrustStore.
type TrustStoreEntry struct {
	Cert         *x509.Certificate
	FriendlyName string
}

// WithIterations creates a new Encoder identical to enc except that
// it will use the given number of KDF iterations for deriving the MAC
// and encryption keys.
//
// Note that even with a large number of iterations, a weak
// password can still be brute-forced in much less time than it would
// take to brute-force a high-entropy encryption key.  For the best
// security, don't worry about the number of iterations and just
// use a high-entropy password (e.g. one generated with `openssl rand -hex 16`).
// See https://neilmadden.blog/2023/01/09/on-pbkdf2-iterations/ for more detail.
//
// Panics if iterations is less than 1.
func (enc Encoder) WithIterations(iterations int) *Encoder {
	if iterations < 1 {
		panic("pkcs12: number of iterations is less than 1")
	}
	enc.macIterations = iterations
	enc.encryptionIterations = iterations
	return &enc
}

// WithRand creates a new Encoder identical to enc except that
// it will use the given io.Reader for its random number generator
// instead of [crypto/rand.Reader].
func (enc Encoder) WithRand(rand io.Reader) *Encoder {
	enc.rand = rand
	return &enc
}

// Encode is equivalent to LegacyRC2.WithRand(rand).Encode.
// See [Encoder.Encode] and [LegacyRC2] for details.
//
// Deprecated: for the same behavior, use LegacyRC2.Encode;
// for better compatibility, use Legacy.Encode;
// for better security, use Modern.Encode.
func Encode(rand io.Reader, privateKey interface{}, certificate *x509.Certificate, caCerts []*x509.Certificate, password string) (pfxData []byte, err error) {
	return LegacyRC2.WithRand(rand).Encode(privateKey, certificate, caCerts, password)
}

// EncodeTrustStore is equivalent to LegacyRC2.WithRand(rand).EncodeTrustStore.
// See [Encoder.EncodeTrustStore] and [LegacyRC2] for details.
//
// Deprecated: for the same behavior, use LegacyRC2.EncodeTrustStore;
// to generate passwordless trust stores, use Passwordless.EncodeTrustStore.
func EncodeTrustStore(rand io.Reader, certs []*x509.Certificate, password string) (pfxData []byte, err error) {
	return LegacyRC2.WithRand(rand).EncodeTrustStore(certs, password)
}

// Encode produces pfxData containing one private key (privateKey), an
// end-entity certificate (certificate), and any number of CA certificates
// (caCerts).
//
// The pfxData is encrypted and authenticated with keys derived from
// the provided password.
//
// Encode emulates the behavior of OpenSSL's PKCS12_create: it creates two
// SafeContents: one that's encrypted with the certificate encryption algorithm
// and contains the certificates, and another that is unencrypted and contains the
// private key shrouded with the key encryption algorithm.  The private key bag and
// the end-entity certificate bag have the LocalKeyId attribute set to the SHA-1
// fingerprint of the end-entity certificate.
func (enc *Encoder) Encode(privateKey interface{}, certificate *x509.Certificate, caCerts []*x509.Certificate, password string) (pfxData []byte, err error) {
	if enc.macAlgorithm == nil && enc.certAlgorithm == nil && enc.keyAlgorithm == nil && password != "" {
		return nil, errors.New("pkcs12: password must be empty")
	}

	encodedPassword, err := bmpStringZeroTerminated(password)
	if err != nil {
		return nil, err
	}

	var pfx pfxPdu
	pfx.Version = 3

	var certFingerprint = sha1.Sum(certificate.Raw)
	var localKeyIdAttr pkcs12Attribute
	localKeyIdAttr.Id = oidLocalKeyID
	localKeyIdAttr.Value.Class = 0
	localKeyIdAttr.Value.Tag = 17
	localKeyIdAttr.Value.IsCompound = true
	if localKeyIdAttr.Value.Bytes, err = asn1.Marshal(certFingerprint[:]); err != nil {
		return nil, err
	}

	var certBags []safeBag
	if certBag, err := makeCertBag(certificate.Raw, []pkcs12Attribute{localKeyIdAttr}); err != nil {
		return nil, err
	} else {
		certBags = append(certBags, *certBag)
	}

	for _, cert := range caCerts {
		if certBag, err := makeCertBag(cert.Raw, []pkcs12Attribute{}); err != nil {
			return nil, err
		} else {
			certBags = append(certBags, *certBag)
		}
	}

	var keyBag safeBag
	if enc.keyAlgorithm == nil {
		keyBag.Id = oidKeyBag
		keyBag.Value.Class = 2
		keyBag.Value.Tag = 0
		keyBag.Value.IsCompound = true
		if keyBag.Value.Bytes, err = x509.MarshalPKCS8PrivateKey(privateKey); err != nil {
			return nil, err
		}
	} else {
		keyBag.Id = oidPKCS8ShroundedKeyBag
		keyBag.Value.Class = 2
		keyBag.Value.Tag = 0
		keyBag.Value.IsCompound = true
		if keyBag.Value.Bytes, err = encodePkcs8ShroudedKeyBag(enc.rand, privateKey, enc.keyAlgorithm, encodedPassword, enc.encryptionIterations, enc.saltLen); err != nil {
			return nil, err
		}
	}
	keyBag.Attributes = append(keyBag.Attributes, localKeyIdAttr)

	// Construct an authenticated safe with two SafeContents.
	// The first SafeContents is encrypted and contains the cert bags.
	// The second SafeContents is unencrypted and contains the shrouded key bag.
	var authenticatedSafe [2]contentInfo
	if authenticatedSafe[0], err = makeSafeContents(enc.rand, certBags, enc.certAlgorithm, encodedPassword, enc.encryptionIterations, enc.saltLen); err != nil {
		return nil, err
	}
	if authenticatedSafe[1], err = makeSafeContents(enc.rand, []safeBag{keyBag}, nil, nil, 0, 0); err != nil {
		return nil, err
	}

	var authenticatedSafeBytes []byte
	if authenticatedSafeBytes, err = asn1.Marshal(authenticatedSafe[:]); err != nil {
		return nil, err
	}

	if enc.macAlgorithm != nil {
		// compute the MAC
		pfx.MacData.Mac.Algorithm.Algorithm = enc.macAlgorithm
		pfx.MacData.MacSalt = make([]byte, enc.saltLen)
		if _, err = enc.rand.Read(pfx.MacData.MacSalt); err != nil {
			return nil, err
		}
		pfx.MacData.Iterations = enc.macIterations
		if err = computeMac(&pfx.MacData, authenticatedSafeBytes, encodedPassword); err != nil {
			return nil, err
		}
	}

	pfx.AuthSafe.ContentType = oidDataContentType
	pfx.AuthSafe.Content.Class = 2
	pfx.AuthSafe.Content.Tag = 0
	pfx.AuthSafe.Content.IsCompound = true
	if pfx.AuthSafe.Content.Bytes, err = asn1.Marshal(authenticatedSafeBytes); err != nil {
		return nil, err
	}

	if pfxData, err = asn1.Marshal(pfx); err != nil {
		return nil, errors.New("pkcs12: error writing P12 data: " + err.Error())
	}
	return
}

// EncodeTrustStore produces pfxData containing any number of CA certificates
// (certs) to be trusted. The certificates will be marked with a special OID that
// allow it to be used as a Java TrustStore in Java 1.8 and newer.
//
// EncodeTrustStore creates a single SafeContents that's optionally encrypted
// and contains the certificates.
//
// The Subject of the certificates are used as the Friendly Names (Aliases)
// within the resulting pfxData. If certificates share a Subject, then the
// resulting Friendly Names (Aliases) will be identical, which Java may treat as
// the same entry when used as a Java TrustStore, e.g. with `keytool`.  To
// customize the Friendly Names, use [EncodeTrustStoreEntries].
func (enc *Encoder) EncodeTrustStore(certs []*x509.Certificate, password string) (pfxData []byte, err error) {
	var certsWithFriendlyNames []TrustStoreEntry
	for _, cert := range certs {
		certsWithFriendlyNames = append(certsWithFriendlyNames, TrustStoreEntry{
			Cert:         cert,
			FriendlyName: cert.Subject.String(),
		})
	}
	return enc.EncodeTrustStoreEntries(certsWithFriendlyNames, password)
}

// EncodeTrustStoreEntries is equivalent to LegacyRC2.WithRand(rand).EncodeTrustStoreEntries.
// See [Encoder.EncodeTrustStoreEntries] and [LegacyRC2] for details.
//
// Deprecated: for the same behavior, use LegacyRC2.EncodeTrustStoreEntries; to generate passwordless trust stores,
// use Passwordless.EncodeTrustStoreEntries.
func EncodeTrustStoreEntries(rand io.Reader, entries []TrustStoreEntry, password string) (pfxData []byte, err error) {
	return LegacyRC2.WithRand(rand).EncodeTrustStoreEntries(entries, password)
}

// EncodeTrustStoreEntries produces pfxData containing any number of CA
// certificates (entries) to be trusted. The certificates will be marked with a
// special OID that allow it to be used as a Java TrustStore in Java 1.8 and newer.
//
// This is identical to [Encoder.EncodeTrustStore], but also allows for setting specific
// Friendly Names (Aliases) to be used per certificate, by specifying a slice
// of TrustStoreEntry.
//
// If the same Friendly Name is used for more than one certificate, then the
// resulting Friendly Names (Aliases) in the pfxData will be identical, which Java
// may treat as the same entry when used as a Java TrustStore, e.g. with `keytool`.
//
// EncodeTrustStoreEntries creates a single SafeContents that's optionally
// encrypted and contains the certificates.
func (enc *Encoder) EncodeTrustStoreEntries(entries []TrustStoreEntry, password string) (pfxData []byte, err error) {
	if enc.macAlgorithm == nil && enc.certAlgorithm == nil && password != "" {
		return nil, errors.New("pkcs12: password must be empty")
	}

	encodedPassword, err := bmpStringZeroTerminated(password)
	if err != nil {
		return nil, err
	}

	var pfx pfxPdu
	pfx.Version = 3

	var certAttributes []pkcs12Attribute

	extKeyUsageOidBytes, err := asn1.Marshal(oidAnyExtendedKeyUsage)
	if err != nil {
		return nil, err
	}

	// the oidJavaTrustStore attribute contains the EKUs for which
	// this trust anchor will be valid
	certAttributes = append(certAttributes, pkcs12Attribute{
		Id: oidJavaTrustStore,
		Value: asn1.RawValue{
			Class:      0,
			Tag:        17,
			IsCompound: true,
			Bytes:      extKeyUsageOidBytes,
		},
	})

	var certBags []safeBag
	for _, entry := range entries {

		bmpFriendlyName, err := bmpString(entry.FriendlyName)
		if err != nil {
			return nil, err
		}

		encodedFriendlyName, err := asn1.Marshal(asn1.RawValue{
			Class:      0,
			Tag:        30,
			IsCompound: false,
			Bytes:      bmpFriendlyName,
		})
		if err != nil {
			return nil, err
		}

		friendlyName := pkcs12Attribute{
			Id: oidFriendlyName,
			Value: asn1.RawValue{
				Class:      0,
				Tag:        17,
				IsCompound: true,
				Bytes:      encodedFriendlyName,
			},
		}

		certBag, err := makeCertBag(entry.Cert.Raw, append(certAttributes, friendlyName))
		if err != nil {
			return nil, err
		}
		certBags = append(certBags, *certBag)
	}

	// Construct an authenticated safe with one SafeContent.
	// The SafeContents it contains the cert bags.
	var authenticatedSafe [1]contentInfo
	if authenticatedSafe[0], err = makeSafeContents(enc.rand, certBags, enc.certAlgorithm, encodedPassword, enc.encryptionIterations, enc.saltLen); err != nil {
		return nil, err
	}

	var authenticatedSafeBytes []byte
	if authenticatedSafeBytes, err = asn1.Marshal(authenticatedSafe[:]); err != nil {
		return nil, err
	}

	if enc.macAlgorithm != nil {
		// compute the MAC
		pfx.MacData.Mac.Algorithm.Algorithm = enc.macAlgorithm
		pfx.MacData.MacSalt = make([]byte, enc.saltLen)
		if _, err = enc.rand.Read(pfx.MacData.MacSalt); err != nil {
			return nil, err
		}
		pfx.MacData.Iterations = enc.macIterations
		if err = computeMac(&pfx.MacData, authenticatedSafeBytes, encodedPassword); err != nil {
			return nil, err
		}
	}

	pfx.AuthSafe.ContentType = oidDataContentType
	pfx.AuthSafe.Content.Class = 2
	pfx.AuthSafe.Content.Tag = 0
	pfx.AuthSafe.Content.IsCompound = true
	if pfx.AuthSafe.Content.Bytes, err = asn1.Marshal(authenticatedSafeBytes); err != nil {
		return nil, err
	}

	if pfxData, err = asn1.Marshal(pfx); err != nil {
		return nil, errors.New("pkcs12: error writing P12 data: " + err.Error())
	}
	return
}

func makeCertBag(certBytes []byte, attributes []pkcs12Attribute) (certBag *safeBag, err error) {
	certBag = new(safeBag)
	certBag.Id = oidCertBag
	certBag.Value.Class = 2
	certBag.Value.Tag = 0
	certBag.Value.IsCompound = true
	if certBag.Value.Bytes, err = encodeCertBag(certBytes); err != nil {
		return nil, err
	}
	certBag.Attributes = attributes
	return
}

func makeSafeContents(rand io.Reader, bags []safeBag, algoID asn1.ObjectIdentifier, password []byte, iterations int, saltLen int) (ci contentInfo, err error) {
	var data []byte
	if data, err = asn1.Marshal(bags); err != nil {
		return
	}

	if algoID == nil {
		ci.ContentType = oidDataContentType
		ci.Content.Class = 2
		ci.Content.Tag = 0
		ci.Content.IsCompound = true
		if ci.Content.Bytes, err = asn1.Marshal(data); err != nil {
			return
		}
	} else {
		randomSalt := make([]byte, saltLen)
		if _, err = rand.Read(randomSalt); err != nil {
			return
		}

		var algo pkix.AlgorithmIdentifier
		algo.Algorithm = algoID
		if algoID.Equal(oidPBES2) {
			if algo.Parameters.FullBytes, err = makePBES2Parameters(rand, randomSalt, iterations); err != nil {
				return
			}
		} else {
			if algo.Parameters.FullBytes, err = asn1.Marshal(pbeParams{Salt: randomSalt, Iterations: iterations}); err != nil {
				return
			}
		}

		var encryptedData encryptedData
		encryptedData.Version = 0
		encryptedData.EncryptedContentInfo.ContentType = oidDataContentType
		encryptedData.EncryptedContentInfo.ContentEncryptionAlgorithm = algo
		if err = pbEncrypt(&encryptedData.EncryptedContentInfo, data, password); err != nil {
			return
		}

		ci.ContentType = oidEncryptedDataContentType
		ci.Content.Class = 2
		ci.Content.Tag = 0
		ci.Content.IsCompound = true
		if ci.Content.Bytes, err = asn1.Marshal(encryptedData); err != nil {
			return
		}
	}
	return
}
