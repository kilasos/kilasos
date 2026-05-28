package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"time"
)

const (
	RoleAdmin    = "admin"
	RoleReadonly = "readonly"
	RoleUser     = "user"
)

type WebAuthnCred struct {
	ID         string `json:"id"`
	PublicKey  string `json:"public_key"`
	SignCount  uint32 `json:"sign_count"`
	CreatedAt  string `json:"created_at"`
	Label      string `json:"label,omitempty"`
}

type User struct {
	Username     string         `json:"username"`
	PasswordHash string         `json:"password_hash"`
	Role         string         `json:"role"`
	TOTPSecret   string         `json:"totp_secret,omitempty"`
	TOTPEnabled  bool           `json:"totp_enabled,omitempty"`
	Source       string         `json:"source,omitempty"` // "" (local), "oidc", "ldap"
	BackupCodes  []string       `json:"backup_codes,omitempty"`
	WebAuthn     []WebAuthnCred `json:"webauthn,omitempty"`
	LastLogin    string         `json:"last_login,omitempty"`
	LastLoginIP  string         `json:"last_login_ip,omitempty"`
	Disabled     bool           `json:"disabled,omitempty"`
	PWChangedAt  string         `json:"pw_changed_at,omitempty"`
}

type UserView struct {
	Username    string `json:"username"`
	Role        string `json:"role"`
	TOTPEnabled bool   `json:"totp_enabled"`
	Source      string `json:"source,omitempty"`
	LastLogin   string `json:"last_login,omitempty"`
	Disabled    bool   `json:"disabled,omitempty"`
}

type session struct {
	Username  string    `json:"username"`
	Role      string    `json:"role"`
	Expires   time.Time `json:"expires"`
	CreatedAt time.Time `json:"created_at"`
	Source    string    `json:"source,omitempty"` // "" (local), "oidc", "ldap", "apikey", "webauthn"
	IP        string    `json:"ip,omitempty"`
	UserAgent string    `json:"user_agent,omitempty"`
}

type SessionView struct {
	Token     string `json:"token"`
	Username  string `json:"username"`
	Role      string `json:"role"`
	CreatedAt string `json:"created_at"`
	ExpiresAt string `json:"expires_at"`
	Source    string `json:"source"`
	IP        string `json:"ip,omitempty"`
	UserAgent string `json:"user_agent,omitempty"`
}

type UserStore struct {
	mu              sync.RWMutex
	path            string
	sessionsPath    string
	users           []User
	sessions        map[string]session
	policy          *PasswordPolicy
	sessionDuration time.Duration
	bf              *BruteForceTracker
}

func NewUserStore(path, sessionsPath string, sessionDuration time.Duration) (*UserStore, error) {
	if sessionDuration <= 0 {
		sessionDuration = 24 * time.Hour
	}
	s := &UserStore{path: path, sessionsPath: sessionsPath, sessions: make(map[string]session), sessionDuration: sessionDuration}
	if err := s.load(); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	s.loadSessions()
	return s, nil
}

func (s *UserStore) SetBruteForceTracker(bf *BruteForceTracker) {
	s.mu.Lock()
	s.bf = bf
	s.mu.Unlock()
}

func (s *UserStore) SetPasswordPolicy(p *PasswordPolicy) {
	s.mu.Lock()
	s.policy = p
	s.mu.Unlock()
}

func (s *UserStore) load() error {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, &s.users)
}

func (s *UserStore) save() error {
	data, err := json.MarshalIndent(s.users, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, data, 0600)
}

func (s *UserStore) loadSessions() {
	if s.sessionsPath == "" {
		return
	}
	data, err := os.ReadFile(s.sessionsPath)
	if err != nil {
		return
	}
	json.Unmarshal(data, &s.sessions) //nolint:errcheck
}

func (s *UserStore) saveSessions() {
	if s.sessionsPath == "" {
		return
	}
	data, err := json.MarshalIndent(s.sessions, "", "  ")
	if err != nil {
		return
	}
	os.MkdirAll(fileDir(s.sessionsPath), 0755) //nolint:errcheck
	os.WriteFile(s.sessionsPath, data, 0600)   //nolint:errcheck
}

func (s *UserStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.users)
}

func (s *UserStore) Register(username, password, role string) error {
	if username == "" || password == "" {
		return errors.New("username and password are required")
	}
	if role != RoleAdmin && role != RoleReadonly && role != RoleUser {
		return errors.New("role must be admin, user, or readonly")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range s.users {
		if u.Username == username {
			return errors.New("user already exists")
		}
	}
	hash, err := hashPassword(password)
	if err != nil {
		return err
	}
	s.users = append(s.users, User{Username: username, PasswordHash: hash, Role: role})
	return s.save()
}

func (s *UserStore) Login(username, password, totpCode string) (token, role string, requiresTOTP bool, err error) {
	s.mu.Lock()
	for i, u := range s.users {
		if u.Username == username {
			if u.Disabled {
				s.mu.Unlock()
				return "", "", false, errors.New("account disabled")
			}
			if s.bf != nil && s.bf.IsUsernameBanned(username) {
				s.mu.Unlock()
				return "", "", false, errors.New("account locked: too many failed attempts")
			}
			if !checkPassword(password, u.PasswordHash) {
				if s.bf != nil && u.Source != "oidc" && u.Source != "ldap" {
					s.bf.RecordUsernameFailure(username)
				}
				s.mu.Unlock()
				return "", "", false, errors.New("invalid credentials")
			}
			if s.policy != nil && u.Source != "oidc" && u.Source != "ldap" {
				if maxDays := s.policy.Get().MaxAgeDays; maxDays > 0 && u.PWChangedAt != "" {
					if ts, err := time.Parse(time.RFC3339, u.PWChangedAt); err == nil {
						if time.Since(ts).Hours() > float64(maxDays*24) {
							s.mu.Unlock()
							return "", "", false, errors.New("password expired: please change your password")
						}
					}
				}
			}
			if u.TOTPEnabled {
				if totpCode == "" {
					s.mu.Unlock()
					return "", "", true, nil
				}
				if !validateTOTP(u.TOTPSecret, totpCode) {
					// M388: try as a backup code
					// Need to release lock to call ConsumeBackupCode (which takes its own lock)
					s.mu.Unlock()
					if !s.ConsumeBackupCode(username, totpCode) {
						if s.bf != nil && u.Source != "oidc" && u.Source != "ldap" {
							s.bf.RecordUsernameFailure(username)
						}
						return "", "", false, errors.New("invalid credentials")
					}
					s.mu.Lock()
				}
			}
			s.users[i].LastLogin = time.Now().UTC().Format(time.RFC3339)
			t := genToken()
			s.sessions[t] = session{
				Username:  username,
				Role:      u.Role,
				Expires:   time.Now().Add(s.sessionDuration),
				CreatedAt: time.Now(),
				Source:    "local",
			}
			s.save()         //nolint:errcheck
			s.saveSessions() //nolint:errcheck
			role := u.Role
			s.mu.Unlock()
			if s.bf != nil && u.Source != "oidc" && u.Source != "ldap" {
				s.bf.RecordUsernameSuccess(username)
			}
			return t, role, false, nil
		}
	}
	s.mu.Unlock()
	return "", "", false, errors.New("invalid credentials")
}

func (s *UserStore) EnrollTOTP(username string) (secret, uri string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, u := range s.users {
		if u.Username == username {
			if u.TOTPEnabled {
				return "", "", errors.New("TOTP already enabled — disable it first")
			}
			sec, err := generateTOTPSecret()
			if err != nil {
				return "", "", err
			}
			s.users[i].TOTPSecret = sec
			if err := s.save(); err != nil {
				return "", "", err
			}
			return sec, totpURI(sec, username, "KilasOS"), nil
		}
	}
	return "", "", errors.New("user not found")
}

func (s *UserStore) ConfirmTOTP(username, code string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, u := range s.users {
		if u.Username == username {
			if u.TOTPSecret == "" {
				return errors.New("no pending TOTP enrollment")
			}
			if !validateTOTP(u.TOTPSecret, code) {
				return errors.New("invalid code")
			}
			s.users[i].TOTPEnabled = true
			return s.save()
		}
	}
	return errors.New("user not found")
}

func (s *UserStore) DisableTOTP(username, code string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, u := range s.users {
		if u.Username == username {
			if !u.TOTPEnabled {
				return errors.New("TOTP not enabled")
			}
			if !validateTOTP(u.TOTPSecret, code) {
				return errors.New("invalid code")
			}
			s.users[i].TOTPSecret = ""
			s.users[i].TOTPEnabled = false
			return s.save()
		}
	}
	return errors.New("user not found")
}

func (s *UserStore) TOTPStatus(username string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.users {
		if u.Username == username {
			return u.TOTPEnabled
		}
	}
	return false
}

func (s *UserStore) ValidateToken(token string) (username, role string, ok bool) {
	s.mu.Lock()
	sess, found := s.sessions[token]
	if found && time.Now().After(sess.Expires) {
		delete(s.sessions, token)
		found = false
	}
	s.mu.Unlock()
	if !found {
		return "", "", false
	}
	return sess.Username, sess.Role, true
}

func (s *UserStore) PruneExpiredSessions() {
	s.mu.Lock()
	now := time.Now()
	for tok, sess := range s.sessions {
		if now.After(sess.Expires) {
			delete(s.sessions, tok)
		}
	}
	s.mu.Unlock()
	go s.saveSessions()
}

func (s *UserStore) Logout(token string) {
	s.mu.Lock()
	delete(s.sessions, token)
	s.mu.Unlock()
	go s.saveSessions()
}

func (s *UserStore) Users() []UserView {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]UserView, len(s.users))
	for i, u := range s.users {
		out[i] = UserView{Username: u.Username, Role: u.Role, TOTPEnabled: u.TOTPEnabled}
	}
	return out
}

func (s *UserStore) DeleteUser(username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, u := range s.users {
		if u.Username == username {
			s.users = append(s.users[:i], s.users[i+1:]...)
			for tok, sess := range s.sessions {
				if sess.Username == username {
					delete(s.sessions, tok)
				}
			}
			if err := s.save(); err != nil {
				return err
			}
			go s.saveSessions()
			return nil
		}
	}
	return errors.New("user not found")
}

func (s *UserStore) SetRole(username, role string) error {
	if role != RoleAdmin && role != RoleReadonly && role != RoleUser {
		return errors.New("role must be admin, user, or readonly")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, u := range s.users {
		if u.Username == username {
			s.users[i].Role = role
			for tok, sess := range s.sessions {
				if sess.Username == username {
					s.sessions[tok] = session{Username: username, Role: role}
				}
			}
			return s.save()
		}
	}
	return errors.New("user not found")
}

// hashPassword returns salt:hash using 65536 rounds of SHA-256.
func hashPassword(password string) (string, error) {
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	h := deriveKey(salt, password)
	return hex.EncodeToString(salt) + ":" + hex.EncodeToString(h), nil
}

func checkPassword(password, stored string) bool {
	if len(stored) < 65 || stored[64] != ':' {
		return false
	}
	salt, err := hex.DecodeString(stored[:64])
	if err != nil {
		return false
	}
	want := stored[65:]
	h := deriveKey(salt, password)
	return hex.EncodeToString(h) == want
}

func deriveKey(salt []byte, password string) []byte {
	h := sha256.Sum256(append(salt, []byte(password)...))
	for i := 0; i < 65536; i++ {
		h = sha256.Sum256(h[:])
	}
	return h[:]
}

func genToken() string {
	b := make([]byte, 24)
	rand.Read(b) //nolint:errcheck
	return hex.EncodeToString(b)
}

func fileDir(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[:i]
		}
	}
	return "."
}

// ─── M376-M380: external auth integration ────────────────────────────────────

func (s *UserStore) Exists(username string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.users {
		if u.Username == username {
			return true
		}
	}
	return false
}

func (s *UserStore) RegisterExternal(username, role, source string) error {
	if username == "" {
		return errors.New("username required")
	}
	if role != RoleAdmin && role != RoleReadonly && role != RoleUser {
		return errors.New("invalid role")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range s.users {
		if u.Username == username {
			return errors.New("user already exists")
		}
	}
	s.users = append(s.users, User{
		Username: username,
		Role:     role,
		Source:   source,
	})
	return s.save()
}

// IssueToken creates a session for an already-authenticated user (used by OIDC, LDAP, WebAuthn).
func (s *UserStore) IssueToken(username, source string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var user *User
	for i := range s.users {
		if s.users[i].Username == username {
			user = &s.users[i]
			break
		}
	}
	if user == nil {
		return "", errors.New("user not found")
	}
	if user.Disabled {
		return "", errors.New("user disabled")
	}
	if s.policy != nil && source != "oidc" && source != "ldap" {
		if maxDays := s.policy.Get().MaxAgeDays; maxDays > 0 && user.PWChangedAt != "" {
			if ts, err := time.Parse(time.RFC3339, user.PWChangedAt); err == nil {
				if time.Since(ts).Hours() > float64(maxDays*24) {
					return "", errors.New("password expired: please change your password")
				}
			}
		}
	}
	user.LastLogin = time.Now().UTC().Format(time.RFC3339)
	token := genToken()
	s.sessions[token] = session{
		Username:  username,
		Role:      user.Role,
		Expires:   time.Now().Add(s.sessionDuration),
		CreatedAt: time.Now(),
		Source:    source,
	}
	s.save()         //nolint:errcheck
	s.saveSessions() //nolint:errcheck
	return token, nil
}

// IssueTokenWithMeta records source, IP, and user agent on the session.
func (s *UserStore) IssueTokenWithMeta(username, source, ip, userAgent string) (string, error) {
	token, err := s.IssueToken(username, source)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess, ok := s.sessions[token]; ok {
		sess.IP = ip
		sess.UserAgent = userAgent
		s.sessions[token] = sess
		s.saveSessions() //nolint:errcheck
	}
	if user := s.findUserLocked(username); user != nil {
		user.LastLoginIP = ip
		s.save() //nolint:errcheck
	}
	return token, nil
}

func (s *UserStore) findUserLocked(username string) *User {
	for i := range s.users {
		if s.users[i].Username == username {
			return &s.users[i]
		}
	}
	return nil
}

// ─── M383: session listing & revocation ──────────────────────────────────────

func (s *UserStore) ListSessions() []SessionView {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []SessionView
	now := time.Now()
	for token, sess := range s.sessions {
		if now.After(sess.Expires) {
			continue
		}
		// Mask the token (show first 8 chars only)
		mask := token
		if len(mask) > 12 {
			mask = mask[:8] + "…"
		}
		out = append(out, SessionView{
			Token:     mask,
			Username:  sess.Username,
			Role:      sess.Role,
			CreatedAt: sess.CreatedAt.UTC().Format(time.RFC3339),
			ExpiresAt: sess.Expires.UTC().Format(time.RFC3339),
			Source:    sess.Source,
			IP:        sess.IP,
			UserAgent: sess.UserAgent,
		})
	}
	return out
}

func (s *UserStore) RevokeSessionByPrefix(tokenPrefix string) error {
	if len(tokenPrefix) < 6 {
		return errors.New("token prefix too short")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var matched string
	for token := range s.sessions {
		if len(token) >= len(tokenPrefix) && token[:len(tokenPrefix)] == tokenPrefix {
			matched = token
			break
		}
	}
	if matched == "" {
		return errors.New("no matching session")
	}
	delete(s.sessions, matched)
	s.saveSessions() //nolint:errcheck
	return nil
}

func (s *UserStore) RevokeAllSessionsForUser(username string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for token, sess := range s.sessions {
		if sess.Username == username {
			delete(s.sessions, token)
			count++
		}
	}
	s.saveSessions() //nolint:errcheck
	return count
}

// SetDisabled marks a user as disabled (rejects future logins).
func (s *UserStore) SetDisabled(username string, disabled bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	user := s.findUserLocked(username)
	if user == nil {
		return errors.New("user not found")
	}
	user.Disabled = disabled
	if disabled {
		// Revoke all sessions for this user
		for token, sess := range s.sessions {
			if sess.Username == username {
				delete(s.sessions, token)
			}
		}
		s.saveSessions() //nolint:errcheck
	}
	return s.save()
}

// GetUser returns a copy of the user record.
func (s *UserStore) GetUser(username string) (User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.users {
		if u.Username == username {
			return u, true
		}
	}
	return User{}, false
}

// UpdateUser replaces a user record (caller must hold validation responsibility).
func (s *UserStore) UpdateUser(u User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.users {
		if s.users[i].Username == u.Username {
			s.users[i] = u
			return s.save()
		}
	}
	return errors.New("user not found")
}

// ─── M388: TOTP backup codes ────────────────────────────────────────────────

// SetBackupCodes hashes and stores backup codes for a user.
func (s *UserStore) SetBackupCodes(username string, codes []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	user := s.findUserLocked(username)
	if user == nil {
		return errors.New("user not found")
	}
	hashed := make([]string, 0, len(codes))
	for _, code := range codes {
		h, err := hashPassword(code)
		if err != nil {
			return err
		}
		hashed = append(hashed, h)
	}
	user.BackupCodes = hashed
	return s.save()
}

// ConsumeBackupCode validates a backup code and removes it on success.
// Returns true if the code was valid.
func (s *UserStore) ConsumeBackupCode(username, code string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	user := s.findUserLocked(username)
	if user == nil || len(user.BackupCodes) == 0 {
		return false
	}
	for i, hash := range user.BackupCodes {
		if checkPassword(code, hash) {
			user.BackupCodes = append(user.BackupCodes[:i], user.BackupCodes[i+1:]...)
			s.save() //nolint:errcheck
			return true
		}
	}
	return false
}

// BackupCodeCount returns how many unused backup codes a user has.
func (s *UserStore) BackupCodeCount(username string) int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.users {
		if u.Username == username {
			return len(u.BackupCodes)
		}
	}
	return 0
}

// ─── M387: Password change endpoint helper ──────────────────────────────────

// ChangePassword validates the old password and sets a new one.
func (s *UserStore) ChangePassword(username, oldPassword, newPassword string) error {
	if newPassword == "" {
		return errors.New("new password required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	user := s.findUserLocked(username)
	if user == nil {
		return errors.New("user not found")
	}
	if user.Source != "" && user.Source != "local" {
		return errors.New("password change not allowed for externally-managed users")
	}
	if !checkPassword(oldPassword, user.PasswordHash) {
		return errors.New("invalid current password")
	}
	hash, err := hashPassword(newPassword)
	if err != nil {
		return err
	}
	user.PasswordHash = hash
	user.PWChangedAt = time.Now().UTC().Format(time.RFC3339)
	return s.save()
}
