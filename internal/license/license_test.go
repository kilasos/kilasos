package license

import (
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// newTestKeyPair returns a fresh Ed25519 key pair for test use.
func newTestKeyPair() (ed25519.PublicKey, ed25519.PrivateKey) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic("ed25519.GenerateKey: " + err.Error())
	}
	return pub, priv
}

// mintToken signs a wirePayload into the binary token format.
func mintToken(priv ed25519.PrivateKey, wp wirePayload) []byte {
	payload, err := json.Marshal(wp)
	if err != nil {
		panic("marshal wirePayload: " + err.Error())
	}

	// Header: version (1) + payload length (4) = 5 bytes.
	header := make([]byte, 5)
	header[0] = currentVersion
	binary.BigEndian.PutUint32(header[1:5], uint32(len(payload)))

	// Sign version || len || payload.
	signedMsg := append(header, payload...)
	sig := ed25519.Sign(priv, signedMsg)

	out := make([]byte, 0, len(signedMsg)+len(sig))
	out = append(out, signedMsg...)
	out = append(out, sig...)
	return out
}

// validPayload returns a valid pro-tier wirePayload at current time.
func validPayload() wirePayload {
	return wirePayload{
		CustomerID: "cust-001",
		Tier:       TierPro,
		NodeCount:  4,
		IssuedAt:   time.Now().UTC().Add(-1 * time.Hour).Format(time.RFC3339),
	}
}

// ---------------------------------------------------------------------------
// Verify table tests
// ---------------------------------------------------------------------------

func TestVerify_Success(t *testing.T) {
	pub, priv := newTestKeyPair()
	wp := validPayload()
	token := mintToken(priv, wp)

	lic, err := Verify(token, pub)
	if err != nil {
		t.Fatalf("Verify returned unexpected error: %v", err)
	}
	if lic.CustomerID != wp.CustomerID {
		t.Errorf("CustomerID = %q, want %q", lic.CustomerID, wp.CustomerID)
	}
	if lic.Tier != wp.Tier {
		t.Errorf("Tier = %q, want %q", lic.Tier, wp.Tier)
	}
	if lic.NodeCount != wp.NodeCount {
		t.Errorf("NodeCount = %d, want %d", lic.NodeCount, wp.NodeCount)
	}
	if lic.IsExpired() {
		t.Error("fresh license should not be expired")
	}
}

func TestVerify_Perpetual(t *testing.T) {
	pub, priv := newTestKeyPair()
	wp := validPayload()
	wp.NotAfter = "" // perpetual
	token := mintToken(priv, wp)

	lic, err := Verify(token, pub)
	if err != nil {
		t.Fatalf("Verify returned unexpected error: %v", err)
	}
	if lic.IsExpired() {
		t.Error("perpetual license should not be expired")
	}
	if d := lic.DaysRemaining(); d != -1 {
		t.Errorf("perpetual license DaysRemaining = %d, want -1", d)
	}
}

func TestVerify_HomeTier(t *testing.T) {
	pub, priv := newTestKeyPair()
	wp := validPayload()
	wp.Tier = TierHome
	wp.NodeCount = 1
	token := mintToken(priv, wp)

	lic, err := Verify(token, pub)
	if err != nil {
		t.Fatalf("Verify returned unexpected error: %v", err)
	}
	if lic.Tier != TierHome {
		t.Errorf("Tier = %q, want %q", lic.Tier, TierHome)
	}
	if lic.NodeCount != 1 {
		t.Errorf("NodeCount = %d, want 1", lic.NodeCount)
	}
}

func TestVerify_Expired(t *testing.T) {
	pub, priv := newTestKeyPair()
	wp := validPayload()
	wp.NotAfter = time.Now().UTC().Add(-24 * time.Hour).Format(time.RFC3339)
	token := mintToken(priv, wp)

	lic, err := Verify(token, pub)
	if err == nil {
		t.Fatal("expected error for expired license, got nil")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("error should mention expiration: %v", err)
	}
	if !errors.Is(err, ErrExpired) {
		t.Errorf("error should wrap ErrExpired: %v", err)
	}
	if lic == nil {
		t.Fatal("expected non-nil license even when expired (caller needs CustomerID for debug)")
	}
	if !lic.IsExpired() {
		t.Error("IsExpired should return true for expired license")
	}
}

func TestVerify_BadSignature(t *testing.T) {
	pub, priv := newTestKeyPair()
	wrongPub, wrongPriv := newTestKeyPair()
	wp := validPayload()
	token := mintToken(priv, wp)

	_, err := Verify(token, wrongPub)
	if err == nil {
		t.Fatal("expected error for wrong public key, got nil")
	}
	if !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("error should be ErrInvalidSignature: %v", err)
	}

	// Also test with corrupted token.
	corrupted := make([]byte, len(token))
	copy(corrupted, token)
	corrupted[7] ^= 0xFF // flip bits in payload
	_, err = Verify(corrupted, pub)
	if err == nil {
		t.Fatal("expected error for corrupted token, got nil")
	}
	if !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("error should be ErrInvalidSignature: %v", err)
	}

	_ = wrongPriv // suppress unused variable warning (silence is golden)
}

func TestVerify_WrongTier(t *testing.T) {
	pub, priv := newTestKeyPair()
	wp := validPayload()
	wp.Tier = "enterprise" // deferred tier, not valid yet
	token := mintToken(priv, wp)

	_, err := Verify(token, pub)
	if err == nil {
		t.Fatal("expected error for unknown tier, got nil")
	}
	if !errors.Is(err, ErrInvalidTier) {
		t.Errorf("error should be ErrInvalidTier: %v", err)
	}
}

func TestVerify_TooShort(t *testing.T) {
	pub, _ := newTestKeyPair()
	_, err := Verify([]byte{0x01}, pub)
	if err == nil {
		t.Fatal("expected error for tiny token")
	}
	if !errors.Is(err, ErrTokenTooShort) {
		t.Errorf("error should be ErrTokenTooShort: %v", err)
	}
}

func TestVerify_WrongVersion(t *testing.T) {
	pub, priv := newTestKeyPair()
	wp := validPayload()
	token := mintToken(priv, wp)
	token[0] = 0xFF

	_, err := Verify(token, pub)
	if err == nil {
		t.Fatal("expected error for wrong version")
	}
	if !errors.Is(err, ErrUnsupportedVersion) {
		t.Errorf("error should be ErrUnsupportedVersion: %v", err)
	}
}

func TestVerify_BadLength(t *testing.T) {
	pub, priv := newTestKeyPair()
	wp := validPayload()
	token := mintToken(priv, wp)

	// Truncate the token mid-signature.
	trunc := token[:len(token)-10]
	_, err := Verify(trunc, pub)
	if err == nil {
		t.Fatal("expected error for truncated token")
	}
	if !errors.Is(err, ErrBadLength) {
		t.Errorf("error should be ErrBadLength: %v", err)
	}

	// Append extra bytes.
	extra := append(token, 0xFF, 0xFE)
	_, err = Verify(extra, pub)
	if err == nil {
		t.Fatal("expected error for extra bytes")
	}
	if !errors.Is(err, ErrBadLength) {
		t.Errorf("error should be ErrBadLength: %v", err)
	}
}

func TestVerify_BadJSON(t *testing.T) {
	pub, priv := newTestKeyPair()

	// Sign a manually corrupted payload.
	payload := []byte("{bad json")
	header := make([]byte, 5)
	header[0] = currentVersion
	binary.BigEndian.PutUint32(header[1:5], uint32(len(payload)))
	signedMsg := append(header, payload...)
	sig := ed25519.Sign(priv, signedMsg)

	token := make([]byte, 0, len(signedMsg)+len(sig))
	token = append(token, signedMsg...)
	token = append(token, sig...)

	_, err := Verify(token, pub)
	if err == nil {
		t.Fatal("expected error for bad JSON payload")
	}
	if !errors.Is(err, ErrInvalidJSON) {
		t.Errorf("error should be ErrInvalidJSON: %v", err)
	}
}

func TestVerify_MissingFields(t *testing.T) {
	pub, priv := newTestKeyPair()

	tests := []struct {
		name string
		wp   wirePayload
	}{
		{"missing tier", wirePayload{CustomerID: "c", NodeCount: 1, IssuedAt: time.Now().Format(time.RFC3339)}},
		{"zero node count", wirePayload{CustomerID: "c", Tier: TierPro, NodeCount: 0, IssuedAt: time.Now().Format(time.RFC3339)}},
		{"bad iat", wirePayload{CustomerID: "c", Tier: TierPro, NodeCount: 1, IssuedAt: "not-a-date"}},
		{"bad exp", wirePayload{CustomerID: "c", Tier: TierPro, NodeCount: 1, IssuedAt: time.Now().Format(time.RFC3339), NotAfter: "nope"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := mintToken(priv, tt.wp)
			_, err := Verify(token, pub)
			if err == nil {
				t.Fatal("expected error for invalid payload")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// HasFeature table tests
// ---------------------------------------------------------------------------

func TestHasFeature(t *testing.T) {
	proLic := &License{Tier: TierPro, NodeCount: 4}
	homeLic := &License{Tier: TierHome, NodeCount: 1}

	proFeatures := []string{
		FeatureOIDC, FeatureLDAP, FeatureZFSSend, FeatureBackup,
		FeatureGDPR, FeatureUSBAllow, FeatureAppArmor, FeatureSELinux, FeatureCompliance,
		FeaturePrivacy, FeatureTrivy, FeatureLynis, FeatureFleet, FeatureMSP,
	}

	tests := []struct {
		name    string
		lic     *License
		feature string
		want    bool
	}{
		// Pro license — all known features.
		{"pro: oidc", proLic, FeatureOIDC, true},
		{"pro: ldap", proLic, FeatureLDAP, true},
		{"pro: zfssend", proLic, FeatureZFSSend, true},
		{"pro: backup", proLic, FeatureBackup, true},
		{"pro: gdpr", proLic, FeatureGDPR, true},
		{"pro: usb", proLic, FeatureUSBAllow, true},
		{"pro: apparmor", proLic, FeatureAppArmor, true},
		{"pro: selinux", proLic, FeatureSELinux, true},
		{"pro: compliance", proLic, FeatureCompliance, true},
		{"pro: privacy", proLic, FeaturePrivacy, true},
		{"pro: trivy", proLic, FeatureTrivy, true},
		{"pro: lynis", proLic, FeatureLynis, true},
		{"pro: fleet", proLic, FeatureFleet, true},
		{"pro: msp", proLic, FeatureMSP, true},

		// Home license — nothing.
		{"home: oidc", homeLic, FeatureOIDC, false},
		{"home: backup", homeLic, FeatureBackup, false},
		{"home: gdpr", homeLic, FeatureGDPR, false},

		// Nil license (== Home) — nothing.
		{"nil: oidc", nil, FeatureOIDC, false},
		{"nil: backup", nil, FeatureBackup, false},

		// Unknown feature — false for all tiers.
		{"pro: unknown", proLic, "nonexistent-feature", false},
		{"home: unknown", homeLic, "nonexistent-feature", false},
		{"nil: unknown", nil, "nonexistent-feature", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := HasFeature(tt.lic, tt.feature)
			if got != tt.want {
				t.Errorf("HasFeature(%v, %q) = %v, want %v", tt.lic, tt.feature, got, tt.want)
			}
		})
	}

	// Exhaustive: Pro has every feature in the constant block.
	for _, f := range proFeatures {
		if !HasFeature(proLic, f) {
			t.Errorf("Pro license should have feature %q", f)
		}
	}
}

// ---------------------------------------------------------------------------
// Token round-trip
// ---------------------------------------------------------------------------

func TestTokenRoundTrip(t *testing.T) {
	pub, priv := newTestKeyPair()
	wp := validPayload()
	wp.NotAfter = time.Now().UTC().Add(365 * 24 * time.Hour).Format(time.RFC3339)

	token := mintToken(priv, wp)
	lic, err := Verify(token, pub)
	if err != nil {
		t.Fatalf("round-trip Verify failed: %v", err)
	}

	if lic.CustomerID != wp.CustomerID {
		t.Errorf("CustomerID = %q, want %q", lic.CustomerID, wp.CustomerID)
	}
	if lic.Tier != wp.Tier {
		t.Errorf("Tier = %q, want %q", lic.Tier, wp.Tier)
	}
	if lic.NodeCount != wp.NodeCount {
		t.Errorf("NodeCount = %d, want %d", lic.NodeCount, wp.NodeCount)
	}
	if lic.DaysRemaining() < 364 {
		t.Errorf("DaysRemaining = %d, want >= 364", lic.DaysRemaining())
	}
	if lic.NodeLimit() != 4 {
		t.Errorf("NodeLimit = %d, want 4", lic.NodeLimit())
	}
}

// ---------------------------------------------------------------------------
// DaysRemaining / IsExpired / NodeLimit helpers
// ---------------------------------------------------------------------------

func TestDaysRemaining(t *testing.T) {
	tests := []struct {
		name string
		lic  *License
		want int
	}{
		{"nil license", nil, -1},
		{"perpetual", &License{NotAfter: time.Time{}}, -1},
		{"expired", &License{NotAfter: time.Now().Add(-1 * time.Hour)}, 0},
		{"future", &License{NotAfter: time.Now().Add(48 * time.Hour)}, 1}, // at least 1 day
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.lic.DaysRemaining()
			if tt.want == -1 && got != -1 {
				t.Errorf("DaysRemaining = %d, want -1", got)
			} else if tt.want == 0 && got != 0 {
				t.Errorf("DaysRemaining = %d, want 0", got)
			} else if tt.want > 0 && got < tt.want {
				t.Errorf("DaysRemaining = %d, want >= %d", got, tt.want)
			}
		})
	}
}

func TestNodeLimit(t *testing.T) {
	if n := (*License)(nil).NodeLimit(); n != 1 {
		t.Errorf("nil license NodeLimit = %d, want 1", n)
	}
	if n := (&License{Tier: TierHome, NodeCount: 1}).NodeLimit(); n != 1 {
		t.Errorf("home NodeLimit = %d, want 1", n)
	}
	if n := (&License{Tier: TierPro, NodeCount: 4}).NodeLimit(); n != 4 {
		t.Errorf("pro NodeLimit = %d, want 4", n)
	}
}

// ---------------------------------------------------------------------------
// Edge: token at maximum size bound
// ---------------------------------------------------------------------------

func TestVerify_TokenAtMaxSize(t *testing.T) {
	// A token exactly at maxTokenSize is valid only if the declared
	// payload_len is consistent.
	pub, priv := newTestKeyPair()
	wp := validPayload()
	token := mintToken(priv, wp)

	if len(token) >= maxTokenSize {
		t.Skip("test token larger than maxTokenSize — adjust maxTokenSize?")
	}
	// Token is well under the limit; Verify should succeed.
	_, err := Verify(token, pub)
	if err != nil {
		t.Fatalf("normal-sized token should verify: %v", err)
	}
}

func TestVerify_OverMaxSize(t *testing.T) {
	pub, _ := newTestKeyPair()
	huge := make([]byte, maxTokenSize+1)
	huge[0] = currentVersion
	binary.BigEndian.PutUint32(huge[1:5], 10) // pretend payload is 10 bytes

	_, err := Verify(huge, pub)
	if err == nil {
		t.Fatal("expected error for token exceeding max size")
	}
	if !errors.Is(err, ErrTokenTooLarge) {
		t.Errorf("error should be ErrTokenTooLarge: %v", err)
	}
}

func TestVerify_TrialRoundTrip(t *testing.T) {
	pub, priv := newTestKeyPair()
	wp := validPayload()
	wp.Trial = true
	wp.NotAfter = time.Now().UTC().Add(365 * 24 * time.Hour).Format(time.RFC3339)
	token := mintToken(priv, wp)

	lic, err := Verify(token, pub)
	if err != nil {
		t.Fatalf("Verify returned unexpected error: %v", err)
	}
	if !lic.IsTrial() {
		t.Error("IsTrial() = false, want true")
	}
	if !lic.Trial {
		t.Error("Trial field = false, want true")
	}
	if lic.Tier != TierPro {
		t.Errorf("Tier = %q, want %q", lic.Tier, TierPro)
	}
}
