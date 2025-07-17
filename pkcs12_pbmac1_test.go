package pkcs12

import (
	"encoding/base64"
	"os"
	"regexp"
	"testing"
)

var (
	file1, _       = os.ReadFile("testdata/rfc9579-a1.txt")
	pkcs12_data_ok = cleanBase64Data(string(file1))

	file2, _                  = os.ReadFile("testdata/rfc9579-a2.txt")
	pkcs12_data_sha256_sha512 = cleanBase64Data(string(file2))

	file3, _                  = os.ReadFile("testdata/rfc9579-a3.txt")
	pkcs12_data_sha512_sha512 = cleanBase64Data(string(file3))

	file4, _            = os.ReadFile("testdata/rfc9579-a4.txt")
	bad_iteration_count = cleanBase64Data(string(file4))

	file5, _             = os.ReadFile("testdata/rfc9579-a5.txt")
	incorrect_salt_value = cleanBase64Data(string(file5))

	file6, _           = os.ReadFile("testdata/rfc9579-a6.txt")
	missing_key_length = cleanBase64Data(string(file6))
)

// cleanBase64Data removes all whitespace, newlines, and tabs from base64 data
var (
	re = regexp.MustCompile(`\s+`)
)

func cleanBase64Data(data string) string {
	return re.ReplaceAllString(data, "")
}

// RFC 9579 Appendix A.1
func TestDecodePKCS12DataOk(t *testing.T) {
	cleanedData := pkcs12_data_ok

	pfxData, err := base64.StdEncoding.DecodeString(cleanedData)
	if err != nil {
		t.Fatalf("Failed to decode base64 PKCS#12 data: %v", err)
	}

	password := "1234"

	encodedPassword, err := bmpStringZeroTerminated(password)
	if err != nil {
		t.Fatalf("Failed to encode password to BMP string: %v", err)
	}

	safeContents, updatedPassword, err := getSafeContents(pfxData, encodedPassword, 1, 10)
	if err != nil {
		t.Fatalf("Failed to load PKCS#12 data with getSafeContents: %v", err)
	}

	if len(safeContents) == 0 {
		t.Error("Expected non-empty safe contents")
	}

	t.Logf("Successfully loaded PKCS#12 data with %d safe bag(s)", len(safeContents))
	t.Logf("Updated password length: %d", len(updatedPassword))

	for i, bag := range safeContents {
		t.Logf("  Bag %d: ID=%s", i, bag.Id.String())
	}
}

// RFC 9579 Appendix A.2
func TestDecodePKCS12DataSha256Sha512(t *testing.T) {
	cleanedData := pkcs12_data_sha256_sha512

	pfxData, err := base64.StdEncoding.DecodeString(cleanedData)
	if err != nil {
		t.Fatalf("Failed to decode base64 PKCS#12 data: %v", err)
	}

	password := "1234"

	encodedPassword, err := bmpStringZeroTerminated(password)
	if err != nil {
		t.Fatalf("Failed to encode password to BMP string: %v", err)
	}

	safeContents, updatedPassword, err := getSafeContents(pfxData, encodedPassword, 1, 10)
	if err != nil {
		t.Fatalf("Failed to load PKCS#12 data with getSafeContents: %v", err)
	}

	if len(safeContents) == 0 {
		t.Error("Expected non-empty safe contents")
	}

	t.Logf("Successfully loaded PKCS#12 SHA256/SHA512 data with %d safe bag(s)", len(safeContents))
	t.Logf("Updated password length: %d", len(updatedPassword))

	for i, bag := range safeContents {
		t.Logf("  Bag %d: ID=%s", i, bag.Id.String())
	}
}

// RFC 9579 Appendix A.3
func TestDecodePKCS12DataSha512Sha512(t *testing.T) {
	cleanedData := pkcs12_data_sha512_sha512

	pfxData, err := base64.StdEncoding.DecodeString(cleanedData)
	if err != nil {
		t.Fatalf("Failed to decode base64 PKCS#12 data: %v", err)
	}

	password := "1234"

	encodedPassword, err := bmpStringZeroTerminated(password)
	if err != nil {
		t.Fatalf("Failed to encode password to BMP string: %v", err)
	}

	safeContents, updatedPassword, err := getSafeContents(pfxData, encodedPassword, 1, 10)
	if err != nil {
		t.Fatalf("Failed to load PKCS#12 data with getSafeContents: %v", err)
	}

	if len(safeContents) == 0 {
		t.Error("Expected non-empty safe contents")
	}

	t.Logf("Successfully loaded PKCS#12 SHA512/SHA512 data with %d safe bag(s)", len(safeContents))
	t.Logf("Updated password length: %d", len(updatedPassword))

	for i, bag := range safeContents {
		t.Logf("  Bag %d: ID=%s", i, bag.Id.String())
	}
}

// RFC 9579 Appendix A.4
// Test with bad iteration count
func TestDecodePKCS12DataBadIterationCount(t *testing.T) {
	cleanedData := bad_iteration_count

	pfxData, err := base64.StdEncoding.DecodeString(cleanedData)
	if err != nil {
		t.Fatalf("Failed to decode base64 PKCS#12 data: %v", err)
	}

	password := "1234"

	encodedPassword, err := bmpStringZeroTerminated(password)
	if err != nil {
		t.Fatalf("Failed to encode password to BMP string: %v", err)
	}

	_, _, err = getSafeContents(pfxData, encodedPassword, 1, 10)
	if err == nil {
		t.Fatal("Expected getSafeContents to fail with bad iteration count, but it succeeded")
	}

	if err != ErrIncorrectPassword {
		t.Logf("Got error: %v", err)
		t.Logf("Expected: %v", ErrIncorrectPassword)
	}

	t.Logf("Successfully detected bad iteration count: %v", err)
}

// RFC 9579 Appendix A.5
// Test with incorrect salt
func TestDecodePKCS12DataIncorrectSalt(t *testing.T) {
	cleanedData := incorrect_salt_value

	pfxData, err := base64.StdEncoding.DecodeString(cleanedData)
	if err != nil {
		t.Fatalf("Failed to decode base64 PKCS#12 data: %v", err)
	}

	password := "1234"

	encodedPassword, err := bmpStringZeroTerminated(password)
	if err != nil {
		t.Fatalf("Failed to encode password to BMP string: %v", err)
	}

	_, _, err = getSafeContents(pfxData, encodedPassword, 1, 10)
	if err == nil {
		t.Fatal("Expected getSafeContents to fail with incorrect salt, but it succeeded")
	}

	if err != ErrIncorrectPassword {
		t.Logf("Got error: %v", err)
		t.Logf("Expected: %v", ErrIncorrectPassword)
	}

	t.Logf("Successfully detected incorrect salt: %v", err)
}

// RFC 9579 Appendix A.6
// Test with missing key length
func TestDecodePKCS12DataMissingKeyLength(t *testing.T) {
	cleanedData := missing_key_length

	pfxData, err := base64.StdEncoding.DecodeString(cleanedData)
	if err != nil {
		t.Fatalf("Failed to decode base64 PKCS#12 data: %v", err)
	}

	password := "1234"

	encodedPassword, err := bmpStringZeroTerminated(password)
	if err != nil {
		t.Fatalf("Failed to encode password to BMP string: %v", err)
	}

	_, _, err = getSafeContents(pfxData, encodedPassword, 1, 10)
	if err == nil {
		t.Fatal("Expected getSafeContents to fail with missing key length, but it succeeded")
	}

	if err != ErrIncorrectPassword {
		t.Logf("Got error: %v", err)
		t.Logf("Expected: %v", ErrIncorrectPassword)
	}

	t.Logf("Successfully detected missing key length: %v", err)
}
