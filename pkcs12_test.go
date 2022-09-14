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
		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`
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
		MIIJzgIBAzCCCZQGCSqGSIb3DQEHAaCCCYUEggmBMIIJfTCCA/cGCSqGSIb3DQEHBqCCA+gwggPk
		AgEAMIID3QYJKoZIhvcNAQcBMBwGCiqGSIb3DQEMAQYwDgQIIszfRGqcmPcCAggAgIIDsOZ9Eg1L
		s5Wx8JhYoV3HAL4aRnkAWvTYB5NISZOgSgIQTssmt/3A7134dibTmaT/93LikkL3cTKLnQzJ4wDf
		YZ1bprpVJvUqz+HFT79m27bP9zYXFrvxWBJbxjYKTSjQMgz+h8LAEpXXGajCmxMJ1oCOtdXkhhzc
		LdZN6SAYgtmtyFnCdMEDskSggGuLb3fw84QEJ/Sj6FAULXunW/CPaS7Ce0TMsKmNU/jfFWj3yXXw
		ro0kwjKiVLpVFlnBlHo2OoVU7hmkm59YpGhLgS7nxLD3n7nBroQ0ID1+8R01NnV9XLGoGzxMm1te
		6UyTCkr5mj+kEQ8EP1Ys7g/TC411uhVWySMt/rcpkx7Vz1r9kYEAzJpONAfr6cuEVkPKrxpq4Fh0
		2fzlKBky0i/hrfIEUmngh+ERHUb/Mtv/fkv1j5w9suESbhsMLLiCXAlsP1UWMX+3bNizi3WVMEts
		FM2k9byn+p8IUD/A8ULlE4kEaWeoc+2idkCNQkLGuIdGUXUFVm58se0auUkVRoRJx8x4CkMesT8j
		b1H831W66YRWoEwwDQp2kK1lA2vQXxdVHWlFevMNxJeromLzj3ayiaFrfByeUXhR2S+Hpm+c0yNR
		4UVU9WED2kacsZcpRm9nlEa5sr28mri5JdBrNa/K02OOhvKCxr5ZGmbOVzUQKla2z4w+Ku9k8POm
		dfDNU/fGx1b5hcFWtghXe3msWVsSJrQihnN6q1ughzNiYZlJUGcHdZDRtiWwCFI0bR8h/Dmg9uO9
		4rawQQrjIRT7B8yF3UbkZyAqs8Ppb1TsMeNPHh1rxEfGVQknh/48ouJYsmtbnzugTUt3mJCXXiL+
		XcPMV6bBVAUu4aaVKSmg9+yJtY4/VKv10iw88ktv29fViIdBe3t6l/oPuvQgbQ8dqf4T8w0l/uKZ
		9lS1Na9jfT1vCoS7F5TRi+tmyj1vL5kr/amEIW6xKEP6oeAMvCMtbPAzVEj38zdJ1R22FfuIBxkh
		f0Zl7pdVbmzRxl/SBx9iIBJSqAvcXItiT0FIj8HxQ+0iZKqMQMiBuNWJf5pYOLWGrIyntCWwHuaQ
		wrx0sTGuEL9YXLEAsBDrsvzLkx/56E4INGZFrH8G7HBdW6iGqb22IMI4GHltYSyBRKbB0gadYTyv
		abPEoqww8o7/85aPSzOTJ/53ozD438Q+d0u9SyDuOb60SzCD/zPuCEd78YgtXJwBYTuUNRT27FaM
		3LGMX8Hz+6yPNRnmnA2XKPn7dx/IlaqAjIs8MIIFfgYJKoZIhvcNAQcBoIIFbwSCBWswggVnMIIF
		YwYLKoZIhvcNAQwKAQKgggTuMIIE6jAcBgoqhkiG9w0BDAEDMA4ECJr0cClYqOlcAgIIAASCBMhe
		OQSiP2s0/46ONXcNeVAkz2ksW3u/+qorhSiskGZ0b3dFa1hhgBU2Q7JVIkc4Hf7OXaT1eVQ8oqND
		uhqsNz83/kqYo70+LS8Hocj49jFgWAKrf/yQkdyP1daHa2yzlEw4mkpqOfnIORQHvYCa8nEApspZ
		wVu8y6WVuLHKU67mel7db2xwstQp7PRuSAYqGjTfAylElog8ASdaqqYbYIrCXucF8iF9oVgmb/Qo
		xrXshJ9aSLO4MuXlTPELmWgj07AXKSb90FKNihE+y0bWb9LPVFY1Sly3AX9PfrtkSXIZwqW3phpv
		MxGxQl/R6mr1z+hlTfY9Wdpb5vlKXPKA0L0Rt8d2pOesylFi6esJoS01QgP1kJILjbrV731kvDc0
		Jsd+Oxv4BMwA7ClG8w1EAOInc/GrV1MWFGw/HeEqj3CZ/l/0jv9bwkbVeVCiIhoL6P6lVx9pXq4t
		KZ0uKg/tk5TVJmG2vLcMLvezD0Yk3G2ZOMrywtmskrwoF7oAUpO9e87szoH6fEvUZlkDkPVW1NV4
		cZk3DBSQiuA3VOOg8qbo/tx/EE3H59P0axZWno2GSB0wFPWd1aj+b//tJEJHaaNR6qPRj4IWj9ru
		Qbc8eRAcVWleHg8uAehSvUXlFpyMQREyrnpvMGddpiTC8N4UMrrBRhV7+UbCOWhxPCbItnInBqgl
		1JpSZIP7iUtsIMdu3fEC2cdbXMTRul+4rdzUR7F9OaezV3jjvcAbDvgbK1CpyC+MJ1Mxm/iTgk9V
		iUArydhlR8OniN84GyGYoYCW9O/KUwb6ASmeFOu/msx8x6kAsSQHIkKqMKv0TUR3kZnkxUvdpBGP
		KTl4YCTvNGX4dYALBqrAETRDhua2KVBD/kEttDHwBNVbN2xi81+Mc7ml461aADfk0c66R/m2sjHB
		2tN9+wG12OIWFQjL6wF/UfJMYamxx2zOOExiId29Opt57uYiNVLOO4ourPewHPeH0u8Gz35aero7
		lkt7cZAe1Q0038JUuE/QGlnK4lESK9UkSIQAjSaAlTsrcfwtQxB2EjoOoLhwH5mvxUEmcNGNnXUc
		9xj3M5BD3zBz3Ft7G3YMMDwB1+zC2l+0UG0MGVjMVaeoy32VVNvxgX7jk22OXG1iaOB+PY9kdk+O
		X+52BGSf/rD6X0EnqY7XuRPkMGgjtpZeAYxRQnFtCZgDY4wYheuxqSSpdF49yNczSPLkgB3CeCfS
		+9NTKN7aC6hBbmW/8yYh6OvSiCEwY0lFS/T+7iaVxr1loE4zI1y/FFp4Pe1qfLlLttVlkygga2UU
		SCunTQ8UB/M5IXWKkhMOO11dP4niWwb39Y7pCWpau7mwbXOKfRPX96cgHnQJK5uG+BesDD1oYnX0
		6frN7FOnTSHKruRIwuI8KnOQ/I+owmyz71wiv5LMQt+yM47UrEjB/EZa5X8dpEwOZvkdqL7utcyo
		l0XH5kWMXdW856LL/FYftAqJIDAmtX1TXF/rbP6mPyN/IlDC0gjP84Uzd/a2UyTIWr+wk49Ek3vQ
		/uDamq6QrwAxVmNh5Tset5Vhpc1e1kb7mRMZIzxSP8JcTuYd45oFKi98I8YjvueHVZce1g7OudQP
		SbFQoJvdT46iBg1TTatlltpOiH2mFaxWVS0xYjAjBgkqhkiG9w0BCRUxFgQUdA9eVqvETX4an/c8
		p8SsTugkit8wOwYJKoZIhvcNAQkUMS4eLABGAHIAaQBlAG4AZABsAHkAIABuAGEAbQBlACAAZgBv
		AHIAIABjAGUAcgB0MDEwITAJBgUrDgMCGgUABBRFsNz3Zd1O1GI8GTuFwCWuDOjEEwQIuBEfIcAy
		HQ8CAggA`,
}

func TestDecodeAES256(t *testing.T) {
	for _, b := range base64P12AES256 {
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

		if cert.Subject.CommonName != "test.schou.me" {
			t.Errorf("expected common name to be %q, but found %q", "test.schou.me", cert.Subject.CommonName)
		}
	}
}

// test decode of AES256 and DES3
var base64P12AES256 = []string{`
	MIIH8wIBAzCCB6kGCSqGSIb3DQEHAaCCB5oEggeWMIIHkjCCBGQGCSqGSIb3DQEHBqCCBFUwggRR
	AgEAMIIESgYJKoZIhvcNAQcBMEkGCSqGSIb3DQEFDTA8MBsGCSqGSIb3DQEFDDAOBAjmgi6E9uMt
	xQICCAAwHQYJYIZIAWUDBAEqBBDq9Ujo4ucqbIt5t8W+2PU+gIID8LYBghz0ZLURRNCsnyU1TJgE
	4imhauCXzVmUOFQbJM7f60fMUVs3Eetoy91Z1Wy5fwrZ20TTIOhkzVxEmEwl+9u9O2WnCOoCyaLW
	5yvtiD0G7U/soBHMvijTf/IY38sjsOwyK1MYE66Wqj7pDLaHU5/lzQZXq1jTQMALNCzWqo1bZu+g
	fbtsBklvDNsLRPEbnd0ov6EV2+knMVH5jh0LFHnOB/FoQYCHHXCT5pU3Ts5ExqRUPeV+jA43lccQ
	3UmeraAPqKIV5UH8VALB+7h1P3v6wglTNoBuuGEkffzypJuDkWgDHhlFtM/EF5Mgi+ZNaE31FGpT
	9X40sMOUD6u9dH9e4y6SvDjwhamC88zg3d/T5xQc7oOnmFb36aLHszT2NjE/NS/8/mbgqkJyHR2t
	xRuObkDGObSjUt6m6p4p0AnrkO+eIzaVLggykj+hUz81Sj/rKmQFBMWsL7JNLjFRZjX6nH7XKMXB
	atLJayQAawWzbqUvKyO9ekBS+7bcWWySx4XyiaHNQBY53Ep9RC75dQla4Zr3fRSoQLBaQp8oemIy
	vORvnq30EFz+0cWcB+D/gkOM4hNSNeSyypZNxvAYz8Mv/Cn/hjWNYTyEklI0GiP9ZJA5rT+3xyOz
	z6m4UgZRTmxM4bT2D3wrWrtN543GXUH6Pi1JWddGAxCL5SdrtohtoQgEWYgqGeqZU5A+HMuAGUsJ
	JmC/ZeZfyDTA1Zi5HfVdqqSLhVW/XwmUtFNc0xMzHW7E8m7eIvh1yCE25J4fsm97nmda9GYMywb8
	snReYPGOyaf80nDetFyHJNEvUuVG2XG7o6qfq8dCcw8r2sUwv78Yg3ElwhiU/WZjnESRAWCQ3nbs
	6lvv6AvaB7jQEUrLCpGQlnDxdLx9IaFVwWTa7hOd9UQvgSnTezH8Wk/y4X1GZCZWw9EwrncDzumR
	g9dlDYxDCFa0qQ2ZxVUAJQ4WnJFzPb0i6QxA7+QVVWxplbero93TKZKuncm+Ra3v92BK0VpVRG58
	D+ExeSl4PIdzRFTDu2Q+Z8Cxqre9rCs7W+noI2i7T6lhvgMiDRYfAbouqf8krDRWEfd5FtByksfH
	LuKUOIXPssMlA3QYNlxXUse43CWjgmHAGj149PyqKNG997bTV1T91sXQv+qFxhzPRnwJl4ELOHHg
	L5mULUrQhJ03o114JjsXPCgYv5hjVWbrL/zO0ZGKRADEYKTqrwkioPF4kvveQ3SX6PL4GeHtmaZ0
	aL5NjWdXVUgGPN0gZ1JuqRHuzIC2jKBMaC7MZPBJnHh1Em75311xAlwfbVvXvVA4jKn062u44X+W
	/X0JB5AhTWMRBAlOobVdgRmDQInDZTCCAyYGCSqGSIb3DQEHAaCCAxcEggMTMIIDDzCCAwsGCyqG
	SIb3DQEMCgECoIIC0zCCAs8wSQYJKoZIhvcNAQUNMDwwGwYJKoZIhvcNAQUMMA4ECPOQaBCc4rXa
	AgIIADAdBglghkgBZQMEASoEEEEzJ5rtzF1xPIVV0Ss9WkYEggKA71SlsDTqmPJGsPljIiga7EvW
	C1Z7qrg93TdJL+d8P+IzXCiZwzDsnApPuz6pvqg5YAzbcEBAdldPIS+L9zPeNv7kqHR9E+WTori6
	zs/cVPx8vjxsGsLPNIfX3pOc9fPscz1StOeM0n84b0lOQH9NvrvKcq9D4ndsO0A2t5f1VVh7S/oC
	9nc5E4i8gmC+lbgwV/OKv2Vi9H+yM30i5RqiFPDqv+EEn/elkPkhOydyM+/SgJNurbHNnE5QEWtg
	L7ZAFO/+5bdTWuuKGLLErvEnYoEBOi89rdao75KzApAVi/VnVYMMGXKaTrp9dbWxPWDSPzzxLuA8
	gL3qVa1XR9yspvnbXPgoQsxdtDGHz6P+rXTAM0fkiJmRevSN0qvw6TtlVDNPQHKvre3eQGdmfQN/
	46OzJEaGosYjeOXC/fCc+RLJmqs4U2+5HwmBzGa2V5HfhtQe4Jd+uzqBbEBm282F4SFByaXogMok
	c/sdYwK91SH5wLZy9HtlaUsKvIjc5Lg69MnPOLZzj5CWo386h2zzdaY+1xKetRwp4KVJeHWVV3XR
	UC8vGul9GL0V+AsguSrHiRihX7KhB6L6+YxGa6eXrPjXwkUSJTtaDDixSBkAP0/I2i/n7rWFbDY0
	Aebd/P/1woiN1DSvueHoCI0ZwDru6SenfEYGvSGx6LtGOwToBKoqwqsyDJc+4bD819/3JtiLNwLT
	iwVXGKEdshMqfp3nsM1yLDcfhBXz33CsQAGVvZNqlm+xCuE+Z7EWh88hNM9sQ2UXTHjOcHRVY/4k
	Olo9O7Rj1SDuoSA/DJvdic/sV1IhSJBO2cUT7hWE718i9iNOsqF6KJ6GQkMhiLc7aqnHETElMCMG
	CSqGSIb3DQEJFTEWBBRi1odMENLOCkHDzBhD3P8f2JS5izBBMDEwDQYJYIZIAWUDBAIBBQAEIHyS
	9xS0feZ9s/vMzfyRDGbWbJQt9PebdKuBpEKnPLrGBAgk01YkCC5E/wICCAA=`,

	`
	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`,
}

func base64decode(b64 string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(
		strings.TrimSpace(strings.ReplaceAll(b64, "\t", "")))
}
