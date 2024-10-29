package pkcs12

import (
	"crypto/rsa"
	_ "embed"
	"testing"
)

//go:embed test-data/example_com_aescbc128.p12
var fileExampleComAesCbc128 []byte

//go:embed test-data/example_com_aescbc192.p12
var fileExampleComAesCbc192 []byte

//go:embed test-data/ad_standalone_com_aescbc256.p12
var fileAdStandaloneComAesCbc256 []byte

var decodeChainTests = []struct {
	testName        string
	pfxData         []byte
	password        string
	commonName      string
	testDescription string
}{
	{
		testName:        "AES128CBC",
		pfxData:         fileExampleComAesCbc128,
		password:        "rHyQTJsubhfxcpH5JttyilHE6BBsNoZp",
		commonName:      "example-com",
		testDescription: "PKCS7 Encrypted data: PBES2, PBKDF2, AES-128-CBC, Iteration 2048, PRF hmacWithSHA256",
	},
	{
		testName:        "AES192CBC",
		pfxData:         fileExampleComAesCbc192,
		password:        "password",
		commonName:      "example-com",
		testDescription: "PKCS7 Encrypted data: PBES2, PBKDF2, AES-192-CBC, Iteration 2048, PRF hmacWithSHA256",
	},
	{
		testName:        "AES256CBC",
		pfxData:         fileAdStandaloneComAesCbc256,
		password:        "password",
		commonName:      "*.ad.standalone.com",
		testDescription: "This P12 PDU is a self-signed certificate exported via Windows certmgr. It is encrypted with the following options (verified via openssl): PBES2, PBKDF2, AES-256-CBC, Iteration 2000, PRF hmacWithSHA256",
	},
}

func Test_DecodeChain_PBES2(t *testing.T) {
	for _, tt := range decodeChainTests {
		t.Run(tt.testName, func(t *testing.T) {
			pk, cert, caCerts, err := DecodeChain(tt.pfxData, tt.password)
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

//go:embed test-data/example_signed_certificates_chain.p12
var fileExampleSignedCertificatesChain []byte

func Test_DecodeChains(t *testing.T) {
	tests := []struct {
		testName string
		pfxData  []byte
		password string
	}{
		{
			testName: "example_signed_certificates_chain.p12",
			pfxData:  fileExampleSignedCertificatesChain,
			password: "password",
		},
	}
	// testing special pfx file with 3 keys
	for _, tt := range tests {
		t.Run(tt.testName, func(t *testing.T) {
			certs, err := DecodeChains(tt.pfxData, tt.password)
			if err != nil {
				t.Fatal(err)
			}
			if len(certs) != 3 {
				t.Errorf("unexpected # of caCerts: got %d, want 3", len(certs))
			}
		})
	}

	// also the other pfx files should work
	for _, tt := range decodeChainTests {
		t.Run(tt.testName, func(t *testing.T) {
			certs, err := DecodeChains(tt.pfxData, tt.password)
			if err != nil {
				t.Fatal(err)
			}
			if len(certs) != 1 {
				t.Errorf("unexpected # of caCerts: got %d, want 1", len(certs))
			}
		})
	}
}
