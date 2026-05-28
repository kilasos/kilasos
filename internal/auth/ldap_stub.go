package auth

import "github.com/kilasos/kilasos/internal/license"

// LDAPConfig holds LDAP provider configuration.
// Exposed so the UI can render the config form; secrets are masked on read.
type LDAPConfig struct {
	Enabled            bool              `json:"enabled"`
	URL                string            `json:"url"`
	StartTLS           bool              `json:"start_tls"`
	InsecureSkipVerify bool              `json:"insecure_skip_verify"`
	BindDN             string            `json:"bind_dn"`
	BindPassword       string            `json:"bind_password"`
	BaseDN             string            `json:"base_dn"`
	UserFilter         string            `json:"user_filter"`
	GroupBaseDN        string            `json:"group_base_dn,omitempty"`
	GroupFilter        string            `json:"group_filter,omitempty"`
	GroupRoleMapping   map[string]string `json:"group_role_mapping"`
	DefaultRole        string            `json:"default_role"`
	AutoProvision      bool              `json:"auto_provision"`
	UsernameAttr       string            `json:"username_attr,omitempty"`
}

// homeLDAP is the Home-tier LDAP stub. All operations fail with a
// "requires Pro license" message or no-op.
type homeLDAP struct{}

// NewHomeLDAP returns a Home-tier LDAPAuthenticator stub.
func NewHomeLDAP(users *UserStore) LDAPAuthenticator {
	return &homeLDAP{}
}

func (m *homeLDAP) Enabled() bool                                         { return false }
func (m *homeLDAP) Authenticate(username, password string) (string, error) {
	return "", license.ErrFeatureNotLicensed
}
func (m *homeLDAP) GetConfig() LDAPConfig                { return LDAPConfig{} }
func (m *homeLDAP) SetConfig(cfg LDAPConfig) error       { return license.ErrFeatureNotLicensed }
func (m *homeLDAP) TestConnection() error                { return license.ErrFeatureNotLicensed }
func (m *homeLDAP) SyncUsers() (int, int, error)         { return 0, 0, license.ErrFeatureNotLicensed }

