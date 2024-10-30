// Copyright 2015, 2018, 2019 Opsmate, Inc. All rights reserved.
// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkcs12

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
)

// A CertificateChain represents a private key, a leaf certificate matching it, and the CA certificate chain.
// It also stores the friendlyName of the private key.
type CertificateChain struct {
	FriendlyName    string
	PrivateKey      crypto.PrivateKey
	LeafCertificate *x509.Certificate
	CACertificates  []*x509.Certificate
}

// Decode extracts a certificate and private key from pfxData, which must be a DER-encoded PKCS#12 file.
// This function assumes that there is only one certificate and only one private key in the pfxData.
// Since PKCS#12 files often contain more than one certificate, you probably want to use [DecodeChain] instead.
// It will return an error, if there is more than one private key in the data.
func Decode(pfxData []byte, password string) (privateKey interface{}, certificate *x509.Certificate, err error) {
	var caCerts []*x509.Certificate
	privateKey, certificate, caCerts, err = DecodeChain(pfxData, password)
	if len(caCerts) != 0 {
		err = errors.New("pkcs12: expected exactly two safe bags in the PFX PDU")
	}
	return
}

// DecodeChain extracts a certificate, a CA certificate chain, and private key
// from pfxData, which must be a DER-encoded PKCS#12 file. This function assumes that there is at least one certificate
// and only one private key in the pfxData.  The first certificate is assumed to
// be the leaf certificate, and subsequent certificates, if any, are assumed to
// comprise the CA certificate chain.
func DecodeChain(pfxData []byte, password string) (privateKey interface{}, certificate *x509.Certificate, caCerts []*x509.Certificate, err error) {
	encodedPassword, err := bmpStringZeroTerminated(password)
	if err != nil {
		return nil, nil, nil, err
	}

	bags, encodedPassword, err := getSafeContents(pfxData, encodedPassword, 1, 2)
	if err != nil {
		return nil, nil, nil, err
	}

	for _, bag := range bags {
		switch {
		case bag.Id.Equal(oidCertBag):
			certsData, err := decodeCertBag(bag.Value.Bytes)
			if err != nil {
				return nil, nil, nil, err
			}
			certs, err := x509.ParseCertificates(certsData)
			if err != nil {
				return nil, nil, nil, err
			}
			if len(certs) != 1 {
				err = errors.New("pkcs12: expected exactly one certificate in the certBag")
				return nil, nil, nil, err
			}
			if certificate == nil {
				certificate = certs[0]
			} else {
				caCerts = append(caCerts, certs[0])
			}

		case bag.Id.Equal(oidKeyBag):
			if privateKey != nil {
				err = errors.New("pkcs12: expected exactly one key bag")
				return nil, nil, nil, err
			}

			if privateKey, err = x509.ParsePKCS8PrivateKey(bag.Value.Bytes); err != nil {
				return nil, nil, nil, err
			}
		case bag.Id.Equal(oidPKCS8ShroundedKeyBag):
			if privateKey != nil {
				err = errors.New("pkcs12: expected exactly one key bag")
				return nil, nil, nil, err
			}

			if privateKey, err = decodePkcs8ShroudedKeyBag(bag.Value.Bytes, encodedPassword); err != nil {
				return nil, nil, nil, err
			}
		}
	}

	if certificate == nil {
		return nil, nil, nil, errors.New("pkcs12: certificate missing")
	}
	if privateKey == nil {
		return nil, nil, nil, errors.New("pkcs12: private key missing")
	}

	return
}

// DecodeChains extracts Chains from pfxData, which must be a DER-encoded PKCS#12 file. The function
// assumes there is at least one private key with a friendlyName attribute and at least one matching certificate.
// The function ignores certificates that do not match any private keys, or are not part of any CA certificates chain.
func DecodeChains(pfxData []byte, password string) (chains []CertificateChain, err error) {
	encodedPassword, err := bmpStringZeroTerminated(password)
	if err != nil {
		return nil, err
	}

	bags, encodedPassword, err := getSafeContents(pfxData, encodedPassword, 1, 2)
	if err != nil {
		return nil, err
	}

	// extract all bags
	privateKeysAll := make(map[string]crypto.PrivateKey)
	var certsAll []*x509.Certificate // do not store cert alias
	for _, bag := range bags {
		friendlyName, err := extractFriendlyname(bag)
		if err != nil {
			friendlyName = ""
		}
		switch {
		case bag.Id.Equal(oidCertBag):
			certsData, err := decodeCertBag(bag.Value.Bytes)
			if err != nil {
				return nil, err
			}
			certs, err := x509.ParseCertificates(certsData)
			if err != nil {
				return nil, err
			}
			if len(certs) != 1 {
				err = errors.New("pkcs12: expected exactly one certificate in the certBag")
				return nil, err
			}
			certsAll = append(certsAll, certs[0])
		case bag.Id.Equal(oidKeyBag):
			privateKey, err := x509.ParsePKCS8PrivateKey(bag.Value.Bytes)
			if err != nil {
				return nil, err
			}
			pk, ok := privateKey.(crypto.PrivateKey)
			if !ok {
				return nil, fmt.Errorf("pkcs12: failed to get private key")
			}
			privateKeysAll[friendlyName] = pk
		case bag.Id.Equal(oidPKCS8ShroundedKeyBag):
			privateKey, err := decodePkcs8ShroudedKeyBag(bag.Value.Bytes, encodedPassword)
			if err != nil {
				return nil, err
			}
			pk, ok := privateKey.(crypto.PrivateKey)
			if !ok {
				return nil, fmt.Errorf("pkcs12: failed to get private key")
			}
			privateKeysAll[friendlyName] = pk
		default:
			// TODO: bag types: crlBag, secretBag, safeContentsBag aren't supported yet, should signal a warning
		}
	}
	for pkAlias, pk := range privateKeysAll {
		chain := CertificateChain{
			FriendlyName: pkAlias,
			PrivateKey:   pk,
		}
		// find matching private keys to leaf certificates
		var leafCertificate *x509.Certificate
		for i, cert := range certsAll {
			if certificateMatchesToKey(pk, cert) {
				chain.LeafCertificate = cert
				leafCertificate = cert
				certsAll = removeCert(certsAll, i)
				break
			}
		}
		// build the chain, from remaining, un-ordered certificates
		for leafCertificate != nil && hasIssuer(leafCertificate) && !selfSigned(leafCertificate) {
			foundIssuer := false
			for i, issuerCert := range certsAll {
				if issuedBy(leafCertificate, issuerCert) {
					chain.CACertificates = append(chain.CACertificates, issuerCert)
					leafCertificate = issuerCert
					certsAll = removeCert(certsAll, i)
					foundIssuer = true
					break
				}
			}
			if !foundIssuer {
				break // incomplete chain, no reason to error
			}
		}
		chains = append(chains, chain)
	}
	// verify chains
	for _, chain := range chains {
		if chain.LeafCertificate == nil {
			return nil, errors.New("pkcs12: leaf certificate missing")
		}
	}

	return
}

func removeCert(slice []*x509.Certificate, s int) []*x509.Certificate {
	return append(slice[:s], slice[s+1:]...)
}

func selfSigned(cert *x509.Certificate) bool {
	return issuedBy(cert, cert)
}

func issuedBy(subject, issuer *x509.Certificate) bool {
	return bytes.Equal(subject.RawIssuer, issuer.RawSubject) &&
		issuer.CheckSignature(subject.SignatureAlgorithm, subject.RawTBSCertificate, subject.Signature) == nil
}

func hasIssuer(cert *x509.Certificate) bool {
	return len(cert.RawIssuer) > 0
}

// DecodeTrustStore extracts the certificates from pfxData, which must be a DER-encoded
// PKCS#12 file containing exclusively certificates with attribute 2.16.840.1.113894.746875.1.1,
// which is used by Java to designate a trust anchor.
//
// If the password argument is empty, DecodeTrustStore will decode either password-less
// PKCS#12 files (i.e. those without encryption) or files with a literal empty password.
func DecodeTrustStore(pfxData []byte, password string) (certs []*x509.Certificate, err error) {
	encodedPassword, err := bmpStringZeroTerminated(password)
	if err != nil {
		return nil, err
	}

	bags, encodedPassword, err := getSafeContents(pfxData, encodedPassword, 1, 1)
	if err != nil {
		return nil, err
	}

	for _, bag := range bags {
		switch {
		case bag.Id.Equal(oidCertBag):
			if !bag.hasAttribute(oidJavaTrustStore) {
				return nil, errors.New("pkcs12: trust store contains a certificate that is not marked as trusted")
			}
			certsData, err := decodeCertBag(bag.Value.Bytes)
			if err != nil {
				return nil, err
			}
			parsedCerts, err := x509.ParseCertificates(certsData)
			if err != nil {
				return nil, err
			}

			if len(parsedCerts) != 1 {
				err = errors.New("pkcs12: expected exactly one certificate in the certBag")
				return nil, err
			}

			certs = append(certs, parsedCerts[0])

		default:
			return nil, errors.New("pkcs12: expected only certificate bags")
		}
	}
	return
}

type safeBag struct {
	Id         asn1.ObjectIdentifier
	Value      asn1.RawValue     `asn1:"tag:0,explicit"`
	Attributes []pkcs12Attribute `asn1:"set,optional"`
}

func (bag *safeBag) hasAttribute(id asn1.ObjectIdentifier) bool {
	for _, attr := range bag.Attributes {
		if attr.Id.Equal(id) {
			return true
		}
	}
	return false
}

func extractFriendlyname(bag safeBag) (string, error) {
	for _, attribute := range bag.Attributes {
		if attribute.Id.Equal(oidFriendlyName) {
			if err := unmarshal(attribute.Value.Bytes, &attribute.Value); err != nil {
				return "", err
			}
			value, err := decodeBMPString(attribute.Value.Bytes)
			if err != nil {
				return "", err
			}
			return value, nil
		}
	}
	return "", errors.New("pkcs12: friendlyName attribute not found")
}

func certificateMatchesToKey(privateKey crypto.PrivateKey, certificate *x509.Certificate) bool {
	pk, ok := privateKey.(interface {
		Public() crypto.PublicKey
	})
	if !ok {
		return false
	}
	publicKey, ok := pk.Public().(interface {
		Equal(crypto.PublicKey) bool
	})
	if !ok {
		return false
	}
	if publicKey.Equal(certificate.PublicKey) {
		return true
	}
	return false
}

func getSafeContents(p12Data, password []byte, expectedItemsMin int, expectedItemsMax int) (bags []safeBag, updatedPassword []byte, err error) {
	pfx := new(pfxPdu)
	if err := unmarshal(p12Data, pfx); err != nil {
		return nil, nil, errors.New("pkcs12: error reading P12 data: " + err.Error())
	}

	if pfx.Version != 3 {
		return nil, nil, NotImplementedError("can only decode v3 PFX PDU's")
	}

	if !pfx.AuthSafe.ContentType.Equal(oidDataContentType) {
		return nil, nil, NotImplementedError("only password-protected PFX is implemented")
	}

	// unmarshal the explicit bytes in the content for type 'data'
	if err := unmarshal(pfx.AuthSafe.Content.Bytes, &pfx.AuthSafe.Content); err != nil {
		return nil, nil, err
	}

	if len(pfx.MacData.Mac.Algorithm.Algorithm) == 0 {
		if !(len(password) == 2 && password[0] == 0 && password[1] == 0) {
			return nil, nil, errors.New("pkcs12: no MAC in data")
		}
	} else if err := verifyMac(&pfx.MacData, pfx.AuthSafe.Content.Bytes, password); err != nil {
		if err == ErrIncorrectPassword && len(password) == 2 && password[0] == 0 && password[1] == 0 {
			// some implementations use an empty byte array
			// for the empty string password try one more
			// time with empty-empty password
			password = nil
			err = verifyMac(&pfx.MacData, pfx.AuthSafe.Content.Bytes, password)
		}
		if err != nil {
			return nil, nil, err
		}
	}

	var authenticatedSafe []contentInfo
	if err := unmarshal(pfx.AuthSafe.Content.Bytes, &authenticatedSafe); err != nil {
		return nil, nil, err
	}

	if len(authenticatedSafe) < expectedItemsMin || len(authenticatedSafe) > expectedItemsMax {
		if expectedItemsMin == expectedItemsMax {
			return nil, nil, NotImplementedError(fmt.Sprintf("expected exactly %d items in the authenticated safe, but this file has %d", expectedItemsMin, len(authenticatedSafe)))
		}
		return nil, nil, NotImplementedError(fmt.Sprintf("expected between %d and %d items in the authenticated safe, but this file has %d", expectedItemsMin, expectedItemsMax, len(authenticatedSafe)))
	}

	for _, ci := range authenticatedSafe {
		var data []byte

		switch {
		case ci.ContentType.Equal(oidDataContentType):
			if err := unmarshal(ci.Content.Bytes, &data); err != nil {
				return nil, nil, err
			}
		case ci.ContentType.Equal(oidEncryptedDataContentType):
			var encryptedData encryptedData
			if err := unmarshal(ci.Content.Bytes, &encryptedData); err != nil {
				return nil, nil, err
			}
			if encryptedData.Version != 0 {
				return nil, nil, NotImplementedError("only version 0 of EncryptedData is supported")
			}
			if data, err = pbDecrypt(encryptedData.EncryptedContentInfo, password); err != nil {
				return nil, nil, err
			}
		default:
			return nil, nil, NotImplementedError("only data and encryptedData content types are supported in authenticated safe")
		}

		var safeContents []safeBag
		if err := unmarshal(data, &safeContents); err != nil {
			return nil, nil, err
		}
		bags = append(bags, safeContents...)
	}

	return bags, password, nil
}
