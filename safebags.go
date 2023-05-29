// Copyright 2015, 2018, 2019 Opsmate, Inc. All rights reserved.
// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkcs12

import (
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"crypto/x509/pkix"
)

var (
	// see https://tools.ietf.org/html/rfc7292#appendix-D
	oidCertTypeX509Certificate = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 9, 22, 1})
	oidPKCS8ShroundedKeyBag    = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 12, 10, 1, 2})
	oidCertBag                 = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 12, 10, 1, 3})
)

type certBag struct {
	Id   asn1.ObjectIdentifier
	Data []byte `asn1:"tag:0,explicit"`
}

// Function which decodes a keybag, for use in a Custom Key Decoder with a string input (password)
func DecodePkcs8ShroudedKeyBagWithPassword(asn1Data []byte, password interface{}) (privateKey interface{}, algorithm asn1.ObjectIdentifier, err error) {
	var encodedPassword []byte
	switch val := password.(type) {
	case string:
		encodedPassword, err = bmpStringZeroTerminated(val)
		if err != nil {
			return
		}
	case []byte:
		encodedPassword = val
	default:
		err = fmt.Errorf("pkcs12: unknown password type: %t", val)
		return
	}
	return decodePkcs8ShroudedKeyBag(asn1Data, encodedPassword)
}

// Function which decodes a keybag, for use in a Custom Key Decoder
func decodePkcs8ShroudedKeyBag(asn1Data, password []byte) (privateKey interface{}, algorithm asn1.ObjectIdentifier, err error) {
	pkinfo := new(encryptedPrivateKeyInfo)
	if err = unmarshal(asn1Data, pkinfo); err != nil {
		err = errors.New("pkcs12: error decoding PKCS#8 shrouded key bag: " + err.Error())
		return
	}

	var pkData []byte
	pkData, err = pbDecrypt(pkinfo, password)
	if err != nil {
		err = errors.New("pkcs12: error decrypting PKCS#8 shrouded key bag: " + err.Error())
		return
	}

	ret := new(asn1.RawValue)
	if err = unmarshal(pkData, ret); err != nil {
		err = errors.New("pkcs12: error unmarshaling decrypted private key: " + err.Error())
		return
	}

	if privateKey, err = x509.ParsePKCS8PrivateKey(pkData); err != nil {
		err = errors.New("pkcs12: error parsing PKCS#8 private key: " + err.Error())
		return
	}

	algorithm = pkinfo.AlgorithmIdentifier.Algorithm
	return
}

func EncodePkcs8ShroudedKeyBagWithPassword(rand io.Reader, privateKey, password interface{}, algorithm asn1.ObjectIdentifier) (asn1Data []byte, err error) {
	var encodedPassword []byte
	switch val := password.(type) {
	case string:
		encodedPassword, err = bmpStringZeroTerminated(val)
		if err != nil {
			return
		}
	case []byte:
		encodedPassword = val
	default:
		err = fmt.Errorf("pkcs12: unknown password type: %t", val)
		return
	}
	return encodePkcs8ShroudedKeyBag(rand, privateKey, encodedPassword, algorithm)
}
func encodePkcs8ShroudedKeyBag(rand io.Reader, privateKey interface{}, password []byte, algorithm asn1.ObjectIdentifier) (asn1Data []byte, err error) {
	var pkData []byte
	if pkData, err = x509.MarshalPKCS8PrivateKey(privateKey); err != nil {
		return nil, errors.New("pkcs12: error encoding PKCS#8 private key: " + err.Error())
	}

	randomSalt := make([]byte, 8)
	if _, err = rand.Read(randomSalt); err != nil {
		return nil, errors.New("pkcs12: error reading random salt: " + err.Error())
	}

	var paramBytes []byte
	if algorithm.Equal(OidPBES2) {
		paramBytes, err = encodePBES2Params(randomSalt, rand)
		if err != nil {
			return nil, errors.New("pkcs12: error encoding PBES2 params: " + err.Error())
		}
	} else if paramBytes, err = asn1.Marshal(pbeParams{Salt: randomSalt, Iterations: 2048}); err != nil {
		return nil, errors.New("pkcs12: error encoding params: " + err.Error())
	}

	var pkinfo encryptedPrivateKeyInfo
	pkinfo.AlgorithmIdentifier.Algorithm = algorithm
	pkinfo.AlgorithmIdentifier.Parameters.FullBytes = paramBytes

	if err = pbEncrypt(&pkinfo, pkData, password); err != nil {
		return nil, errors.New("pkcs12: error encrypting PKCS#8 shrouded key bag: " + err.Error())
	}

	if asn1Data, err = asn1.Marshal(pkinfo); err != nil {
		return nil, errors.New("pkcs12: error encoding PKCS#8 shrouded key bag: " + err.Error())
	}

	return asn1Data, nil
}

func encodePBES2Params(salt []byte, rand io.Reader) (paramBytes []byte, err error) {
	iv := make([]byte, 16)
	if _, err = rand.Read(iv); err != nil {
		return
	}
	var algo, kdf, encScheme pkix.AlgorithmIdentifier
	var kdfParams pbkdf2Params

	algo.Algorithm = OidPBES2

	kdf.Algorithm = oidPBKDF2
	kdfParams.Salt.Tag = asn1.TagOctetString
	kdfParams.Salt.Bytes = salt
	kdfParams.Iterations = 2048
	kdfParams.Prf.Algorithm = OidHmacWithSHA256
	if kdf.Parameters.FullBytes, err = asn1.Marshal(kdfParams); err != nil {
		return
	}

	encScheme.Algorithm = OidAES256CBC
	encScheme.Parameters.Bytes = iv

	if paramBytes, err = asn1.Marshal(pbes2Params{Kdf: kdf, EncryptionScheme: encScheme}); err != nil {
		return
	}
	return
}


func decodeCertBag(asn1Data []byte) (x509Certificates []byte, err error) {
	bag := new(certBag)
	if err := unmarshal(asn1Data, bag); err != nil {
		return nil, errors.New("pkcs12: error decoding cert bag: " + err.Error())
	}
	if !bag.Id.Equal(oidCertTypeX509Certificate) {
		return nil, NotImplementedError("only X509 certificates are supported")
	}
	return bag.Data, nil
}

func encodeCertBag(x509Certificates []byte) (asn1Data []byte, err error) {
	var bag certBag
	bag.Id = oidCertTypeX509Certificate
	bag.Data = x509Certificates
	if asn1Data, err = asn1.Marshal(bag); err != nil {
		return nil, errors.New("pkcs12: error encoding cert bag: " + err.Error())
	}
	return asn1Data, nil
}
