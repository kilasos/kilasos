package auth

// LDAPAuthenticator is the interface for LDAP authentication providers.
// Both the Home-tier stub and the Pro-tier real implementation satisfy it.
type LDAPAuthenticator interface {
	Enabled() bool
	Authenticate(username, password string) (string, error)
	GetConfig() LDAPConfig
	SetConfig(cfg LDAPConfig) error
	TestConnection() error
	SyncUsers() (int, int, error)
}
