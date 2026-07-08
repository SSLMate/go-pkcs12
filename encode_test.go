package pkcs12

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"testing"
	"time"
)

func TestEncode(t *testing.T) {
	testCases := []struct {
		name    string
		encoder *Encoder
	}{
		{name: "legacy", encoder: Legacy},
		{name: "legacy_rc2", encoder: LegacyRC2},
		{name: "legacy_des", encoder: LegacyDES},
		{name: "modern2023", encoder: Modern2023},
		{name: "modern2026", encoder: Modern2026},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := testEncoder(tc.encoder)
			if err != nil {
				t.Errorf("pfx test failed with encoder '%s': %v", tc.name, err)
			}
		})
	}
}

func testEncoder(encoder *Encoder) error {
	const bitSize = 2048
	const password = "password-more-than-14"
	privateKey, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		return fmt.Errorf("error generating rsa private key: %w", err)
	}
	cert, err := newCertificate(privateKey)
	if err != nil {
		return fmt.Errorf("error creating certificate: %w", err)
	}

	pfx, err := encoder.Encode(privateKey, cert, []*x509.Certificate{}, password)
	if err != nil {
		return fmt.Errorf("error encoding modern2023 pfx: %w", err)
	}
	decodedPrivateKey, decodedCert, err := Decode(pfx, password)
	if err != nil {
		return fmt.Errorf("error decoding modern2023 pfx: %w", err)
	}

	if !isSameRSA(privateKey, decodedPrivateKey) {
		return fmt.Errorf("error decoding pfx; an unexpected private key was decoded")
	}
	if !isSameSerialNumber(cert, decodedCert) {
		return fmt.Errorf("error decoding pfx: an unexpected certificate was decoded")
	}
	return nil
}

func isSameSerialNumber(c1 *x509.Certificate, c2 *x509.Certificate) bool {
	return c1.SerialNumber.Cmp(c2.SerialNumber) == 0
}

func isSameRSA(k1 crypto.PrivateKey, k2 crypto.PrivateKey) bool {
	rsaK1, ok1 := k1.(*rsa.PrivateKey)
	rsaK2, ok2 := k2.(*rsa.PrivateKey)
	if !(ok1 && ok2) {
		return false
	}
	return rsaK1.N.Cmp(rsaK2.N) == 0 && rsaK1.D.Cmp(rsaK2.D) == 0 && rsaK1.E == rsaK2.E
}

func newCertificate(privateKey *rsa.PrivateKey) (*x509.Certificate, error) {
	template, err := newCertificateTemplate()
	if err != nil {
		return nil, err
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(derBytes)
}

func newCertificateTemplate() (*x509.Certificate, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	return &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Test"},
			CommonName:   "localhost",
		},
		NotBefore:             now,
		NotAfter:              now.Add(time.Hour * 24), // valid for 1d
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}, nil
}
