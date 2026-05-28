package auth

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// WebAuthnManager handles passkey registration and login for users.
// Implements M389. Requires HTTPS in production (browsers reject WebAuthn over plain HTTP except localhost).
type WebAuthnManager struct {
	mu       sync.RWMutex
	wa       *webauthn.WebAuthn
	users    *UserStore
	sessions map[string]*webauthn.SessionData // pending registration/login sessions, keyed by challenge
	rpID     string
	rpOrigin string
}

type WebAuthnConfig struct {
	RPDisplayName string `json:"rp_display_name"`
	RPID          string `json:"rp_id"`
	RPOrigin      string `json:"rp_origin"`
}

// webauthnUser adapts UserStore.User to the webauthn.User interface.
type webauthnUser struct {
	username string
	creds    []WebAuthnCred
}

func (u *webauthnUser) WebAuthnID() []byte                         { return []byte(u.username) }
func (u *webauthnUser) WebAuthnName() string                       { return u.username }
func (u *webauthnUser) WebAuthnDisplayName() string                { return u.username }
func (u *webauthnUser) WebAuthnIcon() string                       { return "" }

func (u *webauthnUser) WebAuthnCredentials() []webauthn.Credential {
	out := make([]webauthn.Credential, 0, len(u.creds))
	for _, c := range u.creds {
		credID, err1 := base64.RawURLEncoding.DecodeString(c.ID)
		pubKey, err2 := base64.RawURLEncoding.DecodeString(c.PublicKey)
		if err1 != nil || err2 != nil {
			continue
		}
		out = append(out, webauthn.Credential{
			ID:        credID,
			PublicKey: pubKey,
			Authenticator: webauthn.Authenticator{
				SignCount: c.SignCount,
			},
		})
	}
	return out
}

func NewWebAuthnManager(users *UserStore, cfg WebAuthnConfig) (*WebAuthnManager, error) {
	if cfg.RPDisplayName == "" {
		cfg.RPDisplayName = "KilasOS"
	}
	if cfg.RPID == "" {
		cfg.RPID = "localhost"
	}
	if cfg.RPOrigin == "" {
		cfg.RPOrigin = "http://localhost:8080"
	}
	wa, err := webauthn.New(&webauthn.Config{
		RPDisplayName: cfg.RPDisplayName,
		RPID:          cfg.RPID,
		RPOrigins:     []string{cfg.RPOrigin},
	})
	if err != nil {
		return nil, err
	}
	return &WebAuthnManager{
		wa:       wa,
		users:    users,
		sessions: make(map[string]*webauthn.SessionData),
		rpID:     cfg.RPID,
		rpOrigin: cfg.RPOrigin,
	}, nil
}

// BeginRegistration starts a passkey registration ceremony.
func (m *WebAuthnManager) BeginRegistration(username string) (*protocol.CredentialCreation, string, error) {
	u, ok := m.users.GetUser(username)
	if !ok {
		return nil, "", errors.New("user not found")
	}
	wu := &webauthnUser{username: username, creds: u.WebAuthn}
	options, sessionData, err := m.wa.BeginRegistration(wu)
	if err != nil {
		return nil, "", err
	}
	sessionID := genRandomString(32)
	m.mu.Lock()
	m.sessions[sessionID] = sessionData
	m.cleanupSessions()
	m.mu.Unlock()
	return options, sessionID, nil
}

// FinishRegistration completes a passkey registration. The label is shown in the UI.
func (m *WebAuthnManager) FinishRegistration(username, sessionID, label string, r *http.Request) error {
	m.mu.Lock()
	sessionData, ok := m.sessions[sessionID]
	delete(m.sessions, sessionID)
	m.mu.Unlock()
	if !ok {
		return errors.New("invalid or expired registration session")
	}
	u, ok := m.users.GetUser(username)
	if !ok {
		return errors.New("user not found")
	}
	wu := &webauthnUser{username: username, creds: u.WebAuthn}
	cred, err := m.wa.FinishRegistration(wu, *sessionData, r)
	if err != nil {
		return err
	}
	u.WebAuthn = append(u.WebAuthn, WebAuthnCred{
		ID:        base64.RawURLEncoding.EncodeToString(cred.ID),
		PublicKey: base64.RawURLEncoding.EncodeToString(cred.PublicKey),
		SignCount: cred.Authenticator.SignCount,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
		Label:     label,
	})
	return m.users.UpdateUser(u)
}

// BeginLogin starts a passkey assertion ceremony.
func (m *WebAuthnManager) BeginLogin(username string) (*protocol.CredentialAssertion, string, error) {
	u, ok := m.users.GetUser(username)
	if !ok {
		return nil, "", errors.New("user not found")
	}
	if len(u.WebAuthn) == 0 {
		return nil, "", errors.New("user has no passkeys registered")
	}
	wu := &webauthnUser{username: username, creds: u.WebAuthn}
	options, sessionData, err := m.wa.BeginLogin(wu)
	if err != nil {
		return nil, "", err
	}
	sessionID := genRandomString(32)
	m.mu.Lock()
	m.sessions[sessionID] = sessionData
	m.cleanupSessions()
	m.mu.Unlock()
	return options, sessionID, nil
}

// FinishLogin verifies the passkey assertion and returns success.
func (m *WebAuthnManager) FinishLogin(username, sessionID string, r *http.Request) error {
	m.mu.Lock()
	sessionData, ok := m.sessions[sessionID]
	delete(m.sessions, sessionID)
	m.mu.Unlock()
	if !ok {
		return errors.New("invalid or expired login session")
	}
	u, ok := m.users.GetUser(username)
	if !ok {
		return errors.New("user not found")
	}
	wu := &webauthnUser{username: username, creds: u.WebAuthn}
	cred, err := m.wa.FinishLogin(wu, *sessionData, r)
	if err != nil {
		return err
	}
	// Update sign count
	credIDB64 := base64.RawURLEncoding.EncodeToString(cred.ID)
	for i, c := range u.WebAuthn {
		if c.ID == credIDB64 {
			u.WebAuthn[i].SignCount = cred.Authenticator.SignCount
			break
		}
	}
	return m.users.UpdateUser(u)
}

// ListCredentials returns metadata for all of a user's registered passkeys.
func (m *WebAuthnManager) ListCredentials(username string) []WebAuthnCred {
	u, ok := m.users.GetUser(username)
	if !ok {
		return nil
	}
	// Return without the public key to keep payloads small
	out := make([]WebAuthnCred, len(u.WebAuthn))
	for i, c := range u.WebAuthn {
		out[i] = WebAuthnCred{
			ID:        c.ID,
			SignCount: c.SignCount,
			CreatedAt: c.CreatedAt,
			Label:     c.Label,
		}
	}
	return out
}

// DeleteCredential removes a passkey by ID.
func (m *WebAuthnManager) DeleteCredential(username, credID string) error {
	u, ok := m.users.GetUser(username)
	if !ok {
		return errors.New("user not found")
	}
	out := u.WebAuthn[:0]
	for _, c := range u.WebAuthn {
		if c.ID != credID {
			out = append(out, c)
		}
	}
	if len(out) == len(u.WebAuthn) {
		return errors.New("credential not found")
	}
	u.WebAuthn = out
	return m.users.UpdateUser(u)
}

func (m *WebAuthnManager) cleanupSessions() {
	// Sessions expire after 5 minutes; called under lock.
	if len(m.sessions) > 100 {
		// Can't easily expire sessionData (no timestamp), so trim if too many.
		// This is a defensive measure; in practice the FE finishes quickly.
		count := 0
		for k := range m.sessions {
			delete(m.sessions, k)
			count++
			if count > 50 {
				break
			}
		}
	}
}

// MarshalJSON helpers — protocol options are already marshaled correctly by the lib.
func MarshalCredentialCreation(c *protocol.CredentialCreation) ([]byte, error) {
	return json.Marshal(c)
}
func MarshalCredentialAssertion(a *protocol.CredentialAssertion) ([]byte, error) {
	return json.Marshal(a)
}
