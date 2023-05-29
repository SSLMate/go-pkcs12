package pkcs12_test

import (
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"testing"

	"software.sslmate.com/src/go-pkcs12"
)

func Test_additionalOIDs(t *testing.T) {
	rawP12 := `
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
cLXjHUOhDDyqBAhlzWP0LJxhZQICCAA=`
	p12, err := base64.StdEncoding.DecodeString(rawP12)
	if err != nil {
		log.Fatal(err)
	}

	// Create a P12 to unmarshal the p12 into
	p := pkcs12.NewWithPassword("testme")

	err = pkcs12.Unmarshal(p12, &p)
	if err != nil {
		log.Fatal(err)
	}

	// Create a P12 to marshal the new p12 into
	newP12 := pkcs12.NewWithPassword("test")

	for _, entry := range p.CertEntries {
		newP12.CertEntries = append(newP12.CertEntries, pkcs12.CertEntry{Cert: entry.Cert})
	}
	for _, entry := range p.KeyEntries {
		newP12.KeyEntries = append(newP12.KeyEntries, pkcs12.KeyEntry{Key: entry.Key})
	}

	{
		out, err := pkcs12.Marshal(&newP12)
		if err != nil {
			t.Fatal(err)
		}
		err = os.WriteFile("default.p12", out, 0644)
		if err != nil {
			t.Fatal(err)
		}
	}

	oids := []asn1.ObjectIdentifier{
		pkcs12.OidPBEWithSHAAnd128BitRC4,
		pkcs12.OidPBEWithSHAAnd40BitRC4,
		pkcs12.OidPBEWithSHAAnd2KeyTripleDESCBC,
		pkcs12.OidPBEWithSHAAnd128BitRC2CBC,
		pkcs12.OidPBES2,
	}
	names := []string{
		"test-128-rc4-cbc",
		"test-40-rc4-cbc",
		"test-2key-3des-cbc",
		"test-128-rc2-cbc",
		"test-pbes2",
	}
	for i, oid := range oids {
		fmt.Println("Writing file " + names[i] + ".p12 for verification")
		//newP12.KeyBagAlgorithm = oid
		newP12.CertBagAlgorithm = oid
		var out []byte
		out, err = pkcs12.Marshal(&newP12)
		if err != nil {
			t.Fatal(err)
		}
		err := os.WriteFile(names[i]+".p12", out, 0644)
		if err != nil {
			t.Fatal(err)
		}
	}
}
