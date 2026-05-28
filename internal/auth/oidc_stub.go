package auth

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"

	"github.com/kilasos/kilasos/internal/audit"
	"github.com/kilasos/kilasos/internal/license"
)

// OIDCConfig holds OIDC provider configuration.
// Exposed so the UI can render the config form; secrets are masked on read.
type OIDCConfig struct {
	Enabled          bool              `json:"enabled"`
	IssuerURL        string            `json:"issuer_url"`
	ClientID         string            `json:"client_id"`
	ClientSecret     string            `json:"client_secret"`
	RedirectURL      string            `json:"redirect_url"`
	Scopes           []string          `json:"scopes"`
	GroupsClaim      string            `json:"groups_claim"`
	GroupRoleMapping map[string]string `json:"group_role_mapping"`
	DefaultRole      string            `json:"default_role"`
	AutoProvision    bool              `json:"auto_provision"`
}

// homeOIDC is the Home-tier OIDC stub. All operations fail with a
// "requires Pro license" message or no-op.
type homeOIDC struct{}

// NewHomeOIDC returns a Home-tier OIDCAuthenticator stub.
func NewHomeOIDC(users *UserStore, auditLog *audit.Logger) OIDCAuthenticator {
	return &homeOIDC{}
}

func (m *homeOIDC) BeginLogin(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "OIDC requires a Pro license", http.StatusPaymentRequired)
}

func (m *homeOIDC) HandleCallback(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "OIDC requires a Pro license", http.StatusPaymentRequired)
}

func (m *homeOIDC) GetConfig() OIDCConfig              { return OIDCConfig{} }
func (m *homeOIDC) SetConfig(cfg OIDCConfig) error     { return license.ErrFeatureNotLicensed }

// genRandomString returns a base64url-encoded random string of n bytes of
// entropy. Package-level helper used by webauthn.go for session IDs (the
// pre-B2 oidc.go defined it here; pro/auth has its own copy for the Pro
// build). Keep its real implementation: a stub that returns "" would yield
// non-unique WebAuthn session IDs.
func genRandomString(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}
