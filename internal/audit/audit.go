package audit

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

const maxEntries = 1000

type Entry struct {
	Time      time.Time `json:"time"`
	User      string    `json:"user"`
	Action    string    `json:"action"`
	Detail    string    `json:"detail,omitempty"`
	IP        string    `json:"ip,omitempty"`
	OK        bool      `json:"ok"`
	Source    string    `json:"source,omitempty"`     // M385: local/oidc/ldap/apikey/webauthn
	Role      string    `json:"role,omitempty"`       // M385: user role at time of action
	UserAgent string    `json:"user_agent,omitempty"` // M385
	Resource  string    `json:"resource,omitempty"`   // M385: object affected (e.g., dataset name)
}

type Logger struct {
	mu            sync.RWMutex
	path          string
	entries       []Entry
	retentionDays int
	anonymizeIP   bool
}

func New(path string) (*Logger, error) {
	l := &Logger{path: path}
	data, err := os.ReadFile(path)
	if err == nil && len(data) > 0 {
		json.Unmarshal(data, &l.entries) //nolint:errcheck
	}
	return l, nil
}

func (l *Logger) SetAnonymizeIP(v bool) {
	l.mu.Lock()
	l.anonymizeIP = v
	l.mu.Unlock()
}

func (l *Logger) SetRetentionDays(days int) {
	l.mu.Lock()
	l.retentionDays = days
	l.mu.Unlock()
}

func (l *Logger) Log(user, action, detail, ip string, ok bool) {
	l.LogEnriched(Entry{
		User:   user,
		Action: action,
		Detail: detail,
		IP:     ip,
		OK:     ok,
	})
}

// LogEnriched (M385) records an audit entry with full auth context.
// Caller fills in any subset of {User, Action, Detail, IP, OK, Source, Role, UserAgent, Resource}.
func (l *Logger) LogEnriched(e Entry) {
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	if l.anonymizeIP && e.IP != "" {
		e.IP = "0.0.0.0"
	}
	l.mu.Lock()
	l.entries = append([]Entry{e}, l.entries...)
	if len(l.entries) > maxEntries {
		l.entries = l.entries[:maxEntries]
	}
	if l.retentionDays > 0 {
		cutoff := time.Now().UTC().Add(-time.Duration(l.retentionDays) * 24 * time.Hour)
		n := len(l.entries)
		for n > 0 && l.entries[n-1].Time.Before(cutoff) {
			n--
		}
		if n < len(l.entries) {
			l.entries = l.entries[:n]
		}
	}
	l.mu.Unlock()
	go l.persist() //nolint:errcheck
}

func (l *Logger) Recent(n int) []Entry {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if n <= 0 || n > len(l.entries) {
		n = len(l.entries)
	}
	out := make([]Entry, n)
	copy(out, l.entries[:n])
	return out
}

func (l *Logger) persist() {
	l.mu.RLock()
	data, err := json.MarshalIndent(l.entries, "", "  ")
	l.mu.RUnlock()
	if err != nil {
		return
	}
	os.MkdirAll(fileDir(l.path), 0755) //nolint:errcheck
	os.WriteFile(l.path, data, 0600)   //nolint:errcheck
}

func fileDir(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[:i]
		}
	}
	return "."
}
