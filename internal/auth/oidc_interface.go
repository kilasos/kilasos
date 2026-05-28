package auth

import (
	"net/http"
)

// OIDCAuthenticator is the interface for OIDC authentication providers.
// Both the Home-tier stub and the Pro-tier real implementation satisfy it.
type OIDCAuthenticator interface {
	BeginLogin(w http.ResponseWriter, r *http.Request)
	HandleCallback(w http.ResponseWriter, r *http.Request)
	GetConfig() OIDCConfig
	SetConfig(cfg OIDCConfig) error
}
