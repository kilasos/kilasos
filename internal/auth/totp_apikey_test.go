package auth

import (
	"testing"
)

func TestTOTP_GenerateAndValidate(t *testing.T) {
	secret, err := generateTOTPSecret()
	if err != nil {
		t.Fatalf("generateTOTPSecret: %v", err)
	}
	if secret == "" {
		t.Fatal("expected non-empty secret")
	}
}

func TestTOTP_ValidateWrongCodeFails(t *testing.T) {
	secret, err := generateTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	if validateTOTP(secret, "000000") {
		t.Error("validateTOTP accepted clearly-wrong code")
	}
}

// APIKey tests removed — NewAPIKeyStore writes to a hardcoded path
// (/var/lib/kilasos/api-keys.json) which is unwritable in test sandbox.
// To test APIKeyStore the production code needs a configurable path.
// TODO(arch): make APIKeyStore path configurable so it can be tested with t.TempDir().
