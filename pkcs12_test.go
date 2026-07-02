// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkcs12

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"testing"
)

//go:embed test-data/testing_at_example_com.p12
var fileTestingAtExampleCom []byte

//go:embed test-data/windows_azure_tools.p12
var fileWindowsAzureTools []byte

var testdata = map[string][]byte{
	// 'null' password test case
	"Windows Azure Tools": fileWindowsAzureTools,
	// empty string password test case
	"testing@example.com": fileTestingAtExampleCom,
}

func TestPfx(t *testing.T) {
	for commonName, p12 := range testdata {
		t.Run(commonName, func(t *testing.T) {
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
		})
	}
}

func TestPEM(t *testing.T) {
	for commonName, p12 := range testdata {
		t.Run(commonName, func(t *testing.T) {
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
		})
	}
}

func TestTrustStore(t *testing.T) {
	for commonName, p12 := range testdata {
		t.Run(commonName, func(t *testing.T) {
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
		})
	}
}

//go:embed test-data/example_com_aescbc128.p12
var fileExampleComAesCbc128 []byte

//go:embed test-data/example_com_aescbc192.p12
var fileExampleComAesCbc192 []byte

//go:embed test-data/ad_standalone_com_aescbc256.p12
var fileAdStandaloneComAesCbc256 []byte

func Test_DecodeChain_PBES2(t *testing.T) {
	tests := []struct {
		testName        string
		storeData       []byte
		password        string
		commonName      string
		testDescription string
	}{
		{
			testName:        "AES128CBC",
			storeData:       fileExampleComAesCbc128,
			password:        "rHyQTJsubhfxcpH5JttyilHE6BBsNoZp",
			commonName:      "example-com",
			testDescription: "PKCS7 Encrypted data: PBES2, PBKDF2, AES-128-CBC, Iteration 2048, PRF hmacWithSHA256",
		},
		{
			testName:        "AES192CBC",
			storeData:       fileExampleComAesCbc192,
			password:        "password",
			commonName:      "example-com",
			testDescription: "PKCS7 Encrypted data: PBES2, PBKDF2, AES-192-CBC, Iteration 2048, PRF hmacWithSHA256",
		},
		{
			testName:        "AES256CBC",
			storeData:       fileAdStandaloneComAesCbc256,
			password:        "password",
			commonName:      "*.ad.standalone.com",
			testDescription: "This P12 PDU is a self-signed certificate exported via Windows certmgr. It is encrypted with the following options (verified via openssl): PBES2, PBKDF2, AES-256-CBC, Iteration 2000, PRF hmacWithSHA256",
		},
	}
	for _, tt := range tests {
		t.Run(tt.testName, func(t *testing.T) {
			pk, cert, caCerts, err := DecodeChain(tt.storeData, tt.password)
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
			if cert.Subject.CommonName != tt.commonName {
				t.Errorf("unexpected leaf cert common name, got %s, want %s", cert.Subject.CommonName, tt.commonName)
			}
			if len(caCerts) != 0 {
				t.Errorf("unexpected # of caCerts: got %d, want 0", len(caCerts))
			}
		})
	}
}
