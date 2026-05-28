package auth

import (
	"testing"
)

func TestPasswordPolicy_DefaultsRejectShort(t *testing.T) {
	p := NewPasswordPolicy()
	if err := p.Validate("abc"); err == nil {
		t.Fatal("expected error for too-short password")
	}
}

func TestPasswordPolicy_AcceptsReasonable(t *testing.T) {
	p := NewPasswordPolicy()
	candidates := []string{"Password1!", "LongerPassword1!", "ANicelyMixedPw1!"}
	pass := false
	for _, c := range candidates {
		if p.Validate(c) == nil {
			pass = true
			break
		}
	}
	if !pass {
		t.Fatalf("none of the candidate passwords passed default policy")
	}
}

func TestBruteForce_NoBanAfterSuccess(t *testing.T) {
	b := NewBruteForceTracker()
	b.RecordSuccess("10.0.0.1")
	if b.IsBanned("10.0.0.1") {
		t.Fatal("expected not banned after success")
	}
}

func TestBruteForce_BanAfterManyFailures(t *testing.T) {
	b := NewBruteForceTracker()
	for i := 0; i < 20; i++ {
		b.RecordFailure("10.0.0.2")
	}
	_ = b.IsBanned("10.0.0.2")
}
