// Package license provides Ed25519-signed license token verification for
// KilasOS tier gating. The token format is a compact binary envelope:
//
//	Byte 0:     version (0x01)
//	Bytes 1-4:  payload length as uint32 big-endian
//	Bytes 5..:  JSON payload (minified UTF-8)
//	Last 64..:  Ed25519 signature over version || len_bytes || payload
//
// The JSON payload has this shape:
//
//	{
//	  "cid":  "customer-identifier",
//	  "tier": "pro",
//	  "n":    4,
//	  "iat":  "2026-05-28T00:00:00Z",
//	  "exp":  "2027-05-28T00:00:00Z"
//	}
//
// "exp" is optional; when absent the license is perpetual.
//
// License keys are generated offline by the operator with an Ed25519 private
// key. Only the public key is embedded in nasd.  The daemon reads the token
// from /etc/kilasos/license.key at startup, calls Verify, and caches the
// result for the lifetime of the process.
package license

import (
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

const currentVersion byte = 0x01

const (
	maxTokenSize = 4096 // generous upper bound; a real token is ~200 bytes
	sigLen       = ed25519.SignatureSize
)

// Tier constants.
const (
	TierHome = "home"
	TierPro  = "pro"
)

// Pro feature gates. Adding a feature here means HasFeature("name") returns
// true only for Pro license holders.
const (
	FeatureOIDC       = "oidc"
	FeatureLDAP       = "ldap"
	FeatureZFSSend    = "zfssend"
	FeatureBackup     = "backup"
	FeatureGDPR       = "gdpr"
	FeatureUSBAllow   = "usb-allowlist"
	FeatureAppArmor   = "apparmor"
	FeatureSELinux   = "selinux"
	FeatureCompliance = "compliance"
	FeaturePrivacy    = "privacy"
	FeatureTrivy      = "trivy"
	FeatureLynis      = "lynis"
	FeatureFleet      = "fleet"
	FeatureMSP        = "msp"
)

// License represents a decoded and verified license token.
type License struct {
	CustomerID string    `json:"cid"`
	Tier       string    `json:"tier"`
	NodeCount  int       `json:"n"`
	IssuedAt   time.Time `json:"iat"`
	NotAfter   time.Time `json:"exp"` // zero = perpetual
	Trial      bool      `json:"trial,omitempty"`
	// MaxVersion is not enforced in v1; reserved for v2 major-version gating.
	MaxVersion string `json:"max_version,omitempty"`
}

type wirePayload struct {
	CustomerID string `json:"cid"`
	Tier       string `json:"tier"`
	NodeCount  int    `json:"n"`
	IssuedAt   string `json:"iat"`
	NotAfter   string `json:"exp,omitempty"`
	Trial      bool   `json:"trial,omitempty"`
	MaxVersion string `json:"max_version,omitempty"`
}

// Known errors returned by Verify.
var (
	ErrTokenTooShort        = errors.New("token too short")
	ErrTokenTooLarge        = errors.New("token exceeds maximum size")
	ErrUnsupportedVersion   = errors.New("unsupported token version")
	ErrBadLength            = errors.New("declared payload length inconsistent with token size")
	ErrInvalidSignature     = errors.New("signature verification failed")
	ErrInvalidTier          = errors.New("unknown tier")
	ErrExpired              = errors.New("license has expired")
	ErrInvalidJSON          = errors.New("invalid JSON payload")
	ErrFeatureNotLicensed   = errors.New("feature requires Pro license")
)

// Verify decodes and cryptographically verifies a license token.
//
// It checks the envelope version, extracts the JSON payload, verifies the
// Ed25519 signature, parses the payload, and validates the tier and expiry.
//
// Returns (*License, nil) when everything checks out.  Errors are
// distinguishable via errors.Is with the sentinel values above.
func Verify(tokenBytes []byte, publicKey ed25519.PublicKey) (*License, error) {
	if len(tokenBytes) < 5+sigLen {
		return nil, fmt.Errorf("%w: got %d bytes, minimum is %d", ErrTokenTooShort, len(tokenBytes), 5+sigLen)
	}
	if len(tokenBytes) > maxTokenSize {
		return nil, fmt.Errorf("%w: got %d bytes, max is %d", ErrTokenTooLarge, len(tokenBytes), maxTokenSize)
	}

	// Envelope header.
	ver := tokenBytes[0]
	if ver != currentVersion {
		return nil, fmt.Errorf("%w: got 0x%02x, expected 0x%02x", ErrUnsupportedVersion, ver, currentVersion)
	}

	payloadLen := binary.BigEndian.Uint32(tokenBytes[1:5])
	expectedTotal := int(5 + payloadLen + sigLen)
	if len(tokenBytes) != expectedTotal {
		return nil, fmt.Errorf("%w: declared %d payload bytes, but token is %d bytes (expected %d)",
			ErrBadLength, payloadLen, len(tokenBytes), expectedTotal)
	}

	payload := tokenBytes[5 : 5+payloadLen]
	signature := tokenBytes[5+payloadLen:]

	// Verify Ed25519 signature over version || len || payload.
	signedMsg := tokenBytes[:5+payloadLen]
	if !ed25519.Verify(publicKey, signedMsg, signature) {
		return nil, ErrInvalidSignature
	}

	// Parse JSON payload.
	var wp wirePayload
	if err := json.Unmarshal(payload, &wp); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidJSON, err)
	}

	if wp.Tier != TierHome && wp.Tier != TierPro {
		return nil, fmt.Errorf("%w: %q (must be %q or %q)", ErrInvalidTier, wp.Tier, TierHome, TierPro)
	}

	iat, err := time.Parse(time.RFC3339, wp.IssuedAt)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid iat timestamp %q: %v", ErrInvalidJSON, wp.IssuedAt, err)
	}
	if wp.NodeCount < 1 {
		return nil, fmt.Errorf("%w: node count must be >= 1, got %d", ErrInvalidJSON, wp.NodeCount)
	}

	lic := &License{
		CustomerID: wp.CustomerID,
		Tier:       wp.Tier,
		NodeCount:  wp.NodeCount,
		IssuedAt:   iat,
	}

	if wp.NotAfter != "" {
		exp, err := time.Parse(time.RFC3339, wp.NotAfter)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid exp timestamp %q: %v", ErrInvalidJSON, wp.NotAfter, err)
		}
		lic.NotAfter = exp
		if time.Now().After(exp) {
			return lic, fmt.Errorf("%w: expired %s (now %s)", ErrExpired, exp.Format(time.RFC3339), time.Now().Format(time.RFC3339))
		}
	}
	lic.Trial = wp.Trial
	lic.MaxVersion = wp.MaxVersion

	return lic, nil
}

// HasFeature reports whether the license authorises a named Pro feature.
//
// Home-tier licenses return false for all features.  Pro licenses return
// true for all known features.  A nil license is treated as Home.
//
// Unknown feature names return false (closed-world policy — new features
// must be explicitly added to the constant block).
func HasFeature(lic *License, feature string) bool {
	if lic == nil || lic.Tier != TierPro {
		return false
	}
	switch feature {
	case FeatureOIDC, FeatureLDAP, FeatureZFSSend, FeatureBackup,
		FeatureGDPR, FeatureUSBAllow, FeatureAppArmor, FeatureSELinux, FeatureCompliance,
		FeaturePrivacy, FeatureTrivy, FeatureLynis, FeatureFleet, FeatureMSP:
		return true
	default:
		return false
	}
}

// IsExpired reports whether a non-perpetual license has passed its not-after
// date.  Perpetual licenses (NotAfter.IsZero()) return false.
func (l *License) IsExpired() bool {
	if l == nil || l.NotAfter.IsZero() {
		return false
	}
	return time.Now().After(l.NotAfter)
}

// IsTrial reports whether this is a trial license.  Nil-safe; returns false
// for nil license.
func (l *License) IsTrial() bool {
	if l == nil {
		return false
	}
	return l.Trial
}

// DaysRemaining returns the number of days until expiry (rounded down), or
// -1 for perpetual licenses.  Returns 0 when already expired.
func (l *License) DaysRemaining() int {
	if l == nil || l.NotAfter.IsZero() {
		return -1
	}
	d := time.Until(l.NotAfter)
	if d <= 0 {
		return 0
	}
	return int(d.Hours() / 24)
}

// NodeLimit returns the licensed node count (0 for nil license => 1 implied for Home).
func (l *License) NodeLimit() int {
	if l == nil {
		return 1
	}
	return l.NodeCount
}
