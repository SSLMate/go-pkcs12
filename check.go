package pkcs12

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
)

func checkCert(prefix string, c *x509.Certificate) error {
	if c == nil {
		return fmt.Errorf("%s, pointer has no value", prefix)
	}
	if len(c.Raw) == 0 {
		return fmt.Errorf("%s, empty (raw bytes)", prefix)
	}
	var raw asn1.RawValue
	rest, err := asn1.Unmarshal(c.Raw, &raw)
	if err != nil {
		return fmt.Errorf("%s, error parsing %s", prefix, err)
	}
	if len(rest) > 0 {
		return fmt.Errorf("%s, malformed (raw bytes)", prefix)
	}
	return nil
}
