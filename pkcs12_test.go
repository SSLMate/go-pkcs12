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
