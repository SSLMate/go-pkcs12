// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkcs12

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"strings"
	"testing"
)

func TestPfx(t *testing.T) {
	for commonName, base64P12 := range testdata {
		p12, err := base64decode(base64P12)
		if err != nil {
			t.Fatal(err)
		}

		priv, cert, err := Decode(p12, "")
		if err != nil {
			t.Fatal(err)
		}

		if err := priv.(*rsa.PrivateKey).Validate(); err != nil {
			t.Errorf("error while validating private key: %v", err)
		}

		if cert.Subject.CommonName != commonName {
			t.Errorf("expected common name to be %q, but found %q", commonName, cert.Subject.CommonName)
		}
	}
}

func TestPEM(t *testing.T) {
	for commonName, base64P12 := range testdata {
		p12, err := base64decode(base64P12)
		if err != nil {
			t.Fatal(err)
		}

		blocks, err := ToPEM(p12, "")
		if err != nil {
			t.Fatalf("error while converting to PEM: %s", err)
		}

		var pemData []byte
		for _, b := range blocks {
			pemData = append(pemData, pem.EncodeToMemory(b)...)
		}

		cert, err := tls.X509KeyPair(pemData, pemData)
		if err != nil {
			t.Errorf("err while converting to key pair: %v", err)
		}
		config := tls.Config{
			Certificates: []tls.Certificate{cert},
		}
		config.BuildNameToCertificate()

		if _, exists := config.NameToCertificate[commonName]; !exists {
			t.Errorf("did not find our cert in PEM?: %v", config.NameToCertificate)
		}
	}
}

func TestTrustStore(t *testing.T) {
	for commonName, base64P12 := range testdata {
		p12, err := base64decode(base64P12)
		if err != nil {
			t.Fatal(err)
		}

		_, cert, err := Decode(p12, "")
		if err != nil {
			t.Fatal(err)
		}

		pfxData, err := EncodeTrustStore(rand.Reader, []*x509.Certificate{cert}, "password")
		if err != nil {
			t.Fatal(err)
		}

		decodedCerts, err := DecodeTrustStore(pfxData, "password")
		if err != nil {
			t.Fatal(err)
		}

		if len(decodedCerts) != 1 {
			t.Fatal("Unexpected number of certs")
		}

		if decodedCerts[0].Subject.CommonName != commonName {
			t.Errorf("expected common name to be %q, but found %q", commonName, decodedCerts[0].Subject.CommonName)
		}
	}
}

func TestPBES2(t *testing.T) {
	// This P12 PDU is a self-signed certificate exported via Windows certmgr.
	// It is encrypted with the following options (verified via openssl): PBES2, PBKDF2, AES-256-CBC, Iteration 2000, PRF hmacWithSHA256
	commonName := "*.ad.standalone.com"
	base64P12 := `
		MIIK1wIBAzCCCoMGCSqGSIb3DQEHAaCCCnQEggpwMIIKbDCCBkIGCSqGSIb3DQEHAaCCBjMEggYv
		MIIGKzCCBicGCyqGSIb3DQEMCgECoIIFMTCCBS0wVwYJKoZIhvcNAQUNMEowKQYJKoZIhvcNAQUM
		MBwECKESv9Fb9n1qAgIH0DAMBggqhkiG9w0CCQUAMB0GCWCGSAFlAwQBKgQQVfcQGG6G712YmXBY
		ug/7aASCBNARs5FW8sl11oZG+ynkQCQKByX0ykA8sPGqz4QJ9zZVda570ZbTP0hxvWbh7eXErZ4e
		T0Pg68Lcp2gKMQqGLhasCTEFBk41lpAO/Xpy1ODQ/4C6PrQIF5nPBcqz+fEJ0FxxZYpvR5biy7h8
		CGt6QRc44i2Iu4il2YotRcX5r4tkKSyzcTCHaMq9QjpR9NmpXtTfaz+quB0EqlTfEe9cmMU1JRUX
		2S5orVyDE6Y+HGfg/PuRapEk45diwhTpfh+xzL3FDFCOzu17eluVaWNE2Jxrg3QvnoOQT5vRHopz
		OWDacHlqE2nUXGdUmuzzx2KLtjyJ/g8ofHCzzfLd32DmfRUQAhsPLVMCygv/lQukVRRnL2WJuwpP
		/58I1XLcsb6J48ZNCVsx/BMLNQ8GBHOuhPmmZ/ca4qNWcKALmUhh1BOE451n5eORTbJC5PwNl0r9
		xBa0f26ikDtWsGKNXSSntVGMgxAeNjEP2cfGNzcB23NwXvxGONL8BSHf8wShGJ09t7A3rXhr2k31
		3KedQsKvDowj13LSYlUGogoF+5RGPdLtpLxk6GntlucvhO+OPd+Ccyvzd/ESaVQeqep2tr9kET80
		jOtxjdr7Gbz4Hn2bDDM+l+qpswVKw6NgTWFJrLt1CH2VHqoaTsQoQjMuoqH6ZRb3TsrzXwJXNxWE
		9Nov8jf0qUFXRqXaghqhYBHFNaHrwMwOneQ+h+via8cVcDsmmrdHEsZijWmp9cfb+lcDIl5ZEg05
		EGGULnyHxeB8dp3LBYAVCLj6KthYGh4n8dHwd6HvfCDYYJQbwvV+I79TDUNc6PP32sbfLomLahCJ
		btRV+L+VKjp9wNbupF2rYVpijiz1cyATn43DPDkDnTS2eQbA+u0hUC32YqK3OmPiJk7pWp8uqGt1
		5P0Rfyyb4ZJO7YhA+oghyRXB0IlQZ9DMlqbDF3g2mgghvSGw0HXoVcGElGLtaXIHh4Bbch3NxD/e
		uc41YA4CwvpeTkoUg37dFI3Msl+4smeKiVIVtnL7ptOxmiJYhrZZSEDbjVLqvbuUaqn+sHMnn2Tk
		sNs6mbwgTTEpEBtf4FJ4kij1cg/UkPPLmyM9O5iDrCdNxYmhUM47wC1trFGeG4eKhYFKpIclBfZA
		+w2PEw7kZS8rr8jbBgzLiqVhRvUa0dHq4zgmnjR7baa0ED69kXXwx3O8I9JMECECjma7o75987fJ
		FvhRaRhJpBl9Qlrb/8HRK97vwuMZEDU+uT5Rg7rfG1qiyUxxcMplvaAs5NxZy14BpD6oCeE912Iw
		+kflckGHRKvHpKJij9eRdhfesXSA3fwCILVqQAi0H0xclLdA2ieH2NyrYXsJPJvrh2NYSv+wzRSn
		FVjGGqhePwSniSUVoJRrkb9YVAKGmA7/2Vs4H8HGTgw3tM5RM50L0ObRYmH6epPFNfr9qipjxet1
		1mn25Sa3dIbVkaF6Tl5bU6C0Ys3WXYIzVOa7PQAyLhjU7M7OeLY5kZK1DVLjApvUtb1PuQ83Acxh
		RctVCM1S6EwH6DWMC8hh5m2ysiqiBpmLUaPxUcMPPlK8/DP4X+ElaALnjUHXYx8l/LYvo8nbiwXB
		26Pt+h21CmSMpjeC2Dxk67HkCnLwm3WGztcnTyWjkz6zkf9YrxSG7Ql/wzGB4jANBgkrBgEEAYI3
		EQIxADATBgkqhkiG9w0BCRUxBgQEAQAAADBdBgkqhkiG9w0BCRQxUB5OAHQAZQAtAGMANgBiAGQA
		YQA2ADIAMgAtADMAMABhADQALQA0AGUAYwBiAC0AYQA4ADQANAAtADEAOQBjAGMAYgBmADEAMgBh
		ADUAMQAxMF0GCSsGAQQBgjcRATFQHk4ATQBpAGMAcgBvAHMAbwBmAHQAIABTAG8AZgB0AHcAYQBy
		AGUAIABLAGUAeQAgAFMAdABvAHIAYQBnAGUAIABQAHIAbwB2AGkAZABlAHIwggQiBgkqhkiG9w0B
		BwagggQTMIIEDwIBADCCBAgGCSqGSIb3DQEHATBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQww
		HAQINoqHIcmRiwUCAgfQMAwGCCqGSIb3DQIJBQAwHQYJYIZIAWUDBAEqBBBswaO5+BydNdATUst6
		dpBMgIIDoDTTSNRlGrm+8N5VeKuaySe7dWmjL3W9baJNErXB7audUdapdWXsBYVgrHNMfYCOArbD
		esWQLE3JQILaQ7iQYYWqFk4qApKCjHyISJ6Ks9t46EcRRBx2RhE0eAVyoEBdsncYSSUeBmC6qvJf
		yXk6zL8F6XQ9Q6Gq/P9o9L+Bb2Z6IZurIFPolntimemAdD2XhPAYtk6MP2CeOTsBJHNAJ5Z2Je2F
		4nEknE+i48mmr/PPCA6k24vXNwXSyF7CKyQCa9dBnNjEo6M8p39UIlBvBWmleKq+GmkaZpEtG16a
		MFDaWSNgcifHk0xaT8aV4VToGl4fvXn1ZEPeGerN+4SbdDipMXZCmw5YpCBZYWi9qXuof8Ue6hnH
		48fQKHAVslNtSbS3FcnQavv7YTeR2Npf9lBZHhhnvoAVFCYOQH5CMBqqKiBVWJzBxF2evB1gKvzJ
		nqqb6gJp62eH4NisThu06Gxd9LssVbri1z1600XequI2gcYpPPDY3IuUY8xGjfHvhFCcIegkp3oQ
		fUg+G7GHjQgiwZqnV1tmk76wamreYh/3zX4lZlpQbpFpUz+MB4WPFoTeHm2/IRhs2Dur6nMQEidd
		/UstLH83pJNcQO0e/DHUGt8FIyeMcfox6V/ml3mqx50StY9b68+TIFk6htZkHXAzer8c0HF00R6L
		/XdUfd9BkffngNX4Ca+cmrAQN44j7/lGJSrEbTYbxxLTiwOTm7fMddBdI9Y49O3wy5lvrH+TMdMI
		JCRG2oOCILGQZkRzzgznixo12tjgjW5CSmjRKdnLlZl47cGEJDmB7gFS7WB7i/qot23sFSvunniv
		vx7mVYrsItAIdPFXzzV/WS2Go+1eJMW0GOhA7EN4R0TnFp0WjPZjR4QNU0q034C2v9wldGlK+EVJ
		aRnAZqlpJ0khfOz12LSDm90JgHIUi3eQxL6dOuwLwbiz5/aBhCGitZVGq4gRcaIPTfWniqv3QoyA
		+i3k/Nn2IEAi8a7R9DPlmkvQaAvKAkaO53c7XzOj0hTnkjO7PfhiwGgpCFdHlKg5jk/SB6qxkSwt
		XZwKaUIynnlu52PykemOh/+OZ+e6p8CiBv9my650avE0teCE9csOjOAQL7BCKHIC6XpsSLUuHhz7
		cTf8MehzJRSgkl5lmdW8+wJmOPmoRznUe5lvKT6x7op6OqiBjVKcl0QLMhvkJBY4TczbrRRA97G9
		6BHN4DBJpg4kCM/votw4eHQPrhPVce0wSzAvMAsGCWCGSAFlAwQCAQQgj1Iu53yHiWVEMsvWiRSz
		VpPEeNzjeXXdrfuUMhBDWAQEFLYa3qh/1OH1CugDTUZD8yt4lOIFAgIH0A==`
	p12, err := base64decode(base64P12)
	if err != nil {
		t.Fatal(err)
	}
	pk, cert, caCerts, err := DecodeChain(p12, "password")
	if err != nil {
		t.Fatal(err)
	}

	rsaPk, ok := pk.(*rsa.PrivateKey)
	if !ok {
		t.Error("could not cast to rsa private key")
	}
	if !rsaPk.PublicKey.Equal(cert.PublicKey) {
		t.Error("public key embedded in private key not equal to public key of certificate")
	}
	if cert.Subject.CommonName != commonName {
		t.Errorf("unexpected leaf cert common name, got %s, want %s", cert.Subject.CommonName, commonName)
	}
	if len(caCerts) != 0 {
		t.Errorf("unexpected # of caCerts: got %d, want 0", len(caCerts))
	}
}

var testdata = map[string]string{
	// 'null' password test case
	"Windows Azure Tools": `
		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
		RD/fsd1x6dda+wQ=`,

	// empty string password test case
	"testing@example.com": `
		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
		HQ8CAggA`,
}

func TestDecodeAES256(t *testing.T) {
	commonname := "paulschou.com"
	for _, b := range base64P12AES256andDES3 {
		p12, err := base64decode(b)
		if err != nil {
			t.Fatal(err)
		}

		priv, cert, err := Decode(p12, "testme")
		if err != nil {
			t.Fatal(err)
		}

		if err := priv.(*rsa.PrivateKey).Validate(); err != nil {
			t.Errorf("error while validating private key: %v", err)
		}

		if cert.Subject.CommonName != commonname {
			t.Errorf("expected common name to be %q, but found %q", commonname, cert.Subject.CommonName)
		}
	}
}

// test decode of AES256 and DES3 with password "testme"
var base64P12AES256andDES3 = []string{`
	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
	CpQzlrM7aQICCAA=`,
	`
	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
	`,
}

func base64decode(b64 string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(
		strings.TrimSpace(strings.ReplaceAll(b64, "\t", "")))
}
