package auth

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"sync"
)

const passwordPolicyPath = "/etc/kilasos/password-policy.json"

// PasswordPolicy implements M387.
type PasswordPolicyConfig struct {
	MinLength            int  `json:"min_length"`
	RequireUppercase     bool `json:"require_uppercase"`
	RequireLowercase     bool `json:"require_lowercase"`
	RequireDigit         bool `json:"require_digit"`
	RequireSymbol        bool `json:"require_symbol"`
	MaxAgeDays           int  `json:"max_age_days"`           // 0 = no expiry
	HistoryDepth         int  `json:"history_depth"`          // remember last N hashes (anti-reuse)
	BackupCodeCount      int  `json:"backup_code_count"`      // M388
}

type PasswordPolicy struct {
	mu  sync.RWMutex
	cfg PasswordPolicyConfig
}

func NewPasswordPolicy() *PasswordPolicy {
	p := &PasswordPolicy{
		cfg: PasswordPolicyConfig{
			MinLength:        12,
			RequireUppercase: true,
			RequireLowercase: true,
			RequireDigit:     true,
			RequireSymbol:    false,
			MaxAgeDays:       0,
			HistoryDepth:     0,
			BackupCodeCount:  10,
		},
	}
	p.Load()
	return p
}

func (p *PasswordPolicy) Load() error {
	data, err := os.ReadFile(passwordPolicyPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var cfg PasswordPolicyConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return err
	}
	p.mu.Lock()
	p.cfg = cfg
	p.mu.Unlock()
	return nil
}

func (p *PasswordPolicy) Set(cfg PasswordPolicyConfig) error {
	if cfg.MinLength < 4 {
		return errors.New("min_length must be at least 4")
	}
	if cfg.BackupCodeCount < 0 || cfg.BackupCodeCount > 50 {
		return errors.New("backup_code_count must be 0-50")
	}
	p.mu.Lock()
	p.cfg = cfg
	p.mu.Unlock()
	data, _ := json.MarshalIndent(cfg, "", "  ")
	os.MkdirAll("/etc/kilasos", 0755)
	return os.WriteFile(passwordPolicyPath, data, 0600)
}

func (p *PasswordPolicy) Get() PasswordPolicyConfig {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.cfg
}

// Validate returns nil if the password meets the policy, or an error describing what's wrong.
func (p *PasswordPolicy) Validate(password string) error {
	cfg := p.Get()
	if len(password) < cfg.MinLength {
		return fmt.Errorf("password must be at least %d characters", cfg.MinLength)
	}
	hasUpper, hasLower, hasDigit, hasSymbol := false, false, false, false
	for _, c := range password {
		switch {
		case c >= 'A' && c <= 'Z':
			hasUpper = true
		case c >= 'a' && c <= 'z':
			hasLower = true
		case c >= '0' && c <= '9':
			hasDigit = true
		case strings.ContainsRune("!@#$%^&*()_+-=[]{};':\",./<>?\\|`~", c):
			hasSymbol = true
		}
	}
	if cfg.RequireUppercase && !hasUpper {
		return errors.New("password must contain an uppercase letter")
	}
	if cfg.RequireLowercase && !hasLower {
		return errors.New("password must contain a lowercase letter")
	}
	if cfg.RequireDigit && !hasDigit {
		return errors.New("password must contain a digit")
	}
	if cfg.RequireSymbol && !hasSymbol {
		return errors.New("password must contain a symbol")
	}
	return nil
}

// GenerateBackupCodes creates N random backup codes (formatted XXXX-XXXX).
// Implements M388.
func (p *PasswordPolicy) GenerateBackupCodes() ([]string, error) {
	cfg := p.Get()
	count := cfg.BackupCodeCount
	if count <= 0 {
		count = 10
	}
	codes := make([]string, count)
	const charset = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789" // omit ambiguous chars
	for i := 0; i < count; i++ {
		var sb strings.Builder
		for j := 0; j < 8; j++ {
			n, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
			if err != nil {
				return nil, err
			}
			sb.WriteByte(charset[n.Int64()])
			if j == 3 {
				sb.WriteByte('-')
			}
		}
		codes[i] = sb.String()
	}
	return codes, nil
}

// Login customization (M390).
type LoginCustomization struct {
	Title         string `json:"title"`
	SubtitleHTML  string `json:"subtitle_html"`
	LogoURL       string `json:"logo_url,omitempty"`
	BackgroundCSS string `json:"background_css,omitempty"`
	AccentColor   string `json:"accent_color,omitempty"`
	MOTDHTML      string `json:"motd_html,omitempty"`
}

const loginCustomizationPath = "/etc/kilasos/login-customization.json"

func GetLoginCustomization() LoginCustomization {
	data, err := os.ReadFile(loginCustomizationPath)
	if err != nil {
		return LoginCustomization{Title: "KilasOS", SubtitleHTML: "Sign in to continue."}
	}
	var c LoginCustomization
	if err := json.Unmarshal(data, &c); err != nil {
		return LoginCustomization{Title: "KilasOS", SubtitleHTML: "Sign in to continue."}
	}
	if c.Title == "" {
		c.Title = "KilasOS"
	}
	if c.SubtitleHTML == "" {
		c.SubtitleHTML = "Sign in to continue."
	}
	return c
}

func SetLoginCustomization(c LoginCustomization) error {
	data, _ := json.MarshalIndent(c, "", "  ")
	os.MkdirAll("/etc/kilasos", 0755)
	return os.WriteFile(loginCustomizationPath, data, 0644)
}
