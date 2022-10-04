package pkcs12

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"

	"golang.org/x/crypto/ssh"
)

func hashKey(key interface{}) (fingerprint []byte, err error) {
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		fingerprint, err = hashPublicKey(k.Public())
	case ecdsa.PrivateKey:
		fingerprint, err = hashPublicKey(k.Public())

	case *rsa.PrivateKey:
		fingerprint, err = hashPublicKey(k.Public())
	case rsa.PrivateKey:
		fingerprint, err = hashPublicKey(k.Public())

	case *ed25519.PrivateKey:
		fingerprint, err = hashPublicKey(k.Public())
	case ed25519.PrivateKey:
		fingerprint, err = hashPublicKey(k.Public())

	case *ecdsa.PublicKey:
		fingerprint, err = hashPublicKey(k)
	case ecdsa.PublicKey:
		fingerprint, err = hashPublicKey(&k)

	case *rsa.PublicKey:
		fingerprint, err = hashPublicKey(k)
	case rsa.PublicKey:
		fingerprint, err = hashPublicKey(&k)

	case *ed25519.PublicKey:
		fingerprint, err = hashPublicKey(k)
	case ed25519.PublicKey:
		fingerprint, err = hashPublicKey(&k)
	default:
		return nil, fmt.Errorf("pkcs12: unable to hash key format: %T", key)
	}
	return
}

func hashPublicKey(pub interface{}) (fingerprint []byte, err error) {
	pk, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("pkcs12: unknown key format: %T", pub)
	}
	hash_sha256 := sha256.New()
	hash_sha256.Write(pk.Marshal())
	fingerprint = hash_sha256.Sum(nil)
	return
}

// Attempt to parse the given private key DER block. OpenSSL 0.9.8 generates
// PKCS #1 private keys by default, while OpenSSL 1.0.0 generates PKCS #8 keys.
// OpenSSL ecparam generates SEC1 EC private keys for ECDSA. We try all three.
func parsePrivateKey(der []byte) (crypto.PrivateKey, error) {
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		switch key := key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey:
			return key, nil
		default:
			return nil, errors.New("pkcs12: found unknown private key type")
		}
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}

	return nil, errors.New("pkcs12: failed to parse private key")
}
