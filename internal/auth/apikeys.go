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

const apiKeysPath = "/var/lib/kilasos/api-keys.json"

type APIKey struct {
	ID         string `json:"id"`         // public identifier (8 chars)
	Username   string `json:"username"`
	Label      string `json:"label"`
	HashedKey  string `json:"hashed_key"` // sha256 of full key
	Role       string `json:"role"`       // copy of user role at creation time
	CreatedAt  string `json:"created_at"`
	LastUsedAt string `json:"last_used_at,omitempty"`
	ExpiresAt  string `json:"expires_at,omitempty"`
}

type APIKeyView struct {
	ID         string `json:"id"`
	Username   string `json:"username"`
	Label      string `json:"label"`
	Role       string `json:"role"`
	CreatedAt  string `json:"created_at"`
	LastUsedAt string `json:"last_used_at,omitempty"`
	ExpiresAt  string `json:"expires_at,omitempty"`
}

type APIKeyStore struct {
	mu    sync.RWMutex
	keys  []APIKey
	users *UserStore
}

func NewAPIKeyStore(users *UserStore) *APIKeyStore {
	s := &APIKeyStore{users: users}
	s.load()
	return s
}

func (s *APIKeyStore) load() {
	data, err := os.ReadFile(apiKeysPath)
	if err != nil {
		return
	}
	json.Unmarshal(data, &s.keys) //nolint:errcheck
}

func (s *APIKeyStore) save() error {
	data, err := json.MarshalIndent(s.keys, "", "  ")
	if err != nil {
		return err
	}
	os.MkdirAll("/var/lib/kilasos", 0755)
	return os.WriteFile(apiKeysPath, data, 0600)
}

// Create issues a new API key for a user. Returns the public ID and the full key
// (the only time the full key is ever returned).
func (s *APIKeyStore) Create(username, label string, ttl time.Duration) (id, fullKey string, err error) {
	user, ok := s.users.GetUser(username)
	if !ok {
		return "", "", errors.New("user not found")
	}
	idBytes := make([]byte, 4)
	keyBytes := make([]byte, 32)
	rand.Read(idBytes)
	rand.Read(keyBytes)
	id = hex.EncodeToString(idBytes)
	fullKey = id + "." + hex.EncodeToString(keyBytes)
	hash := sha256.Sum256([]byte(fullKey))

	entry := APIKey{
		ID:        id,
		Username:  username,
		Label:     label,
		HashedKey: hex.EncodeToString(hash[:]),
		Role:      user.Role,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	if ttl > 0 {
		entry.ExpiresAt = time.Now().Add(ttl).UTC().Format(time.RFC3339)
	}

	s.mu.Lock()
	s.keys = append(s.keys, entry)
	if err := s.save(); err != nil {
		s.mu.Unlock()
		return "", "", err
	}
	s.mu.Unlock()
	return id, fullKey, nil
}

// Validate checks if a presented key is valid and returns the username and role.
func (s *APIKeyStore) Validate(presentedKey string) (username, role string, ok bool) {
	if len(presentedKey) < 16 {
		return "", "", false
	}
	hash := sha256.Sum256([]byte(presentedKey))
	hashHex := hex.EncodeToString(hash[:])
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.keys {
		k := &s.keys[i]
		if k.HashedKey != hashHex {
			continue
		}
		if k.ExpiresAt != "" {
			if t, err := time.Parse(time.RFC3339, k.ExpiresAt); err == nil && now.After(t) {
				return "", "", false
			}
		}
		k.LastUsedAt = now.UTC().Format(time.RFC3339)
		s.save() //nolint:errcheck
		return k.Username, k.Role, true
	}
	return "", "", false
}

// List returns all API keys for a user (or all if username is empty).
func (s *APIKeyStore) List(username string) []APIKeyView {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []APIKeyView
	for _, k := range s.keys {
		if username != "" && k.Username != username {
			continue
		}
		out = append(out, APIKeyView{
			ID:         k.ID,
			Username:   k.Username,
			Label:      k.Label,
			Role:       k.Role,
			CreatedAt:  k.CreatedAt,
			LastUsedAt: k.LastUsedAt,
			ExpiresAt:  k.ExpiresAt,
		})
	}
	return out
}

func (s *APIKeyStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, k := range s.keys {
		if k.ID == id {
			s.keys = append(s.keys[:i], s.keys[i+1:]...)
			return s.save()
		}
	}
	return errors.New("key not found")
}

func (s *APIKeyStore) DeleteAllForUser(username string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	filtered := s.keys[:0]
	for _, k := range s.keys {
		if k.Username == username {
			count++
			continue
		}
		filtered = append(filtered, k)
	}
	s.keys = filtered
	s.save() //nolint:errcheck
	return count
}
