package auth

import (
	"os/exec"
	"strconv"
	"sync"
	"time"
)

// BruteForceTracker tracks failed login attempts per IP and per username, and integrates with fail2ban.
// Implements M386.
type BruteForceTracker struct {
	mu               sync.Mutex
	attempts         map[string]*ipAttempts
	usernameAttempts map[string]*ipAttempts
	maxAttempts      int
	windowDuration   time.Duration
	banDuration      time.Duration
}

type ipAttempts struct {
	Count       int
	FirstFailed time.Time
	LastFailed  time.Time
	BannedUntil time.Time
}

type BruteForceStats struct {
	IP          string `json:"ip"`
	FailedCount int    `json:"failed_count"`
	LastFailed  string `json:"last_failed"`
	BannedUntil string `json:"banned_until,omitempty"`
}

func NewBruteForceTracker() *BruteForceTracker {
	return &BruteForceTracker{
		attempts:         make(map[string]*ipAttempts),
		usernameAttempts: make(map[string]*ipAttempts),
		maxAttempts:      5,
		windowDuration:   10 * time.Minute,
		banDuration:      30 * time.Minute,
	}
}

// RecordFailure records a failed login attempt and returns true if the IP should now be banned.
func (b *BruteForceTracker) RecordFailure(ip string) (banned bool, attemptsLeft int) {
	if ip == "" {
		return false, b.maxAttempts
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	a, ok := b.attempts[ip]
	if !ok || now.Sub(a.FirstFailed) > b.windowDuration {
		a = &ipAttempts{FirstFailed: now}
		b.attempts[ip] = a
	}
	a.Count++
	a.LastFailed = now
	if a.Count >= b.maxAttempts {
		a.BannedUntil = now.Add(b.banDuration)
		// Trigger fail2ban (best-effort, fire-and-forget)
		go banIPViaFail2ban(ip)
		return true, 0
	}
	return false, b.maxAttempts - a.Count
}

// IsBanned returns true if the IP is currently banned.
func (b *BruteForceTracker) IsBanned(ip string) bool {
	if ip == "" {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	a, ok := b.attempts[ip]
	if !ok {
		return false
	}
	if time.Now().Before(a.BannedUntil) {
		return true
	}
	return false
}

// RecordSuccess clears failed-attempt history for an IP.
func (b *BruteForceTracker) RecordSuccess(ip string) {
	if ip == "" {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.attempts, ip)
}

func (b *BruteForceTracker) RecordUsernameFailure(username string) (banned bool) {
	if username == "" {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	a, ok := b.usernameAttempts[username]
	if !ok || now.Sub(a.FirstFailed) > b.windowDuration {
		a = &ipAttempts{FirstFailed: now}
		b.usernameAttempts[username] = a
	}
	a.Count++
	a.LastFailed = now
	if a.Count >= b.maxAttempts {
		a.BannedUntil = now.Add(b.banDuration)
		return true
	}
	return false
}

func (b *BruteForceTracker) IsUsernameBanned(username string) bool {
	if username == "" {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	a, ok := b.usernameAttempts[username]
	if !ok {
		return false
	}
	if time.Now().Before(a.BannedUntil) {
		return true
	}
	return false
}

func (b *BruteForceTracker) RecordUsernameSuccess(username string) {
	if username == "" {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.usernameAttempts, username)
}

// Stats returns the current state of all tracked IPs.
func (b *BruteForceTracker) Stats() []BruteForceStats {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]BruteForceStats, 0, len(b.attempts)+len(b.usernameAttempts))
	for ip, a := range b.attempts {
		out = append(out, makeStatsEntry(ip, a))
	}
	for username, a := range b.usernameAttempts {
		out = append(out, makeStatsEntry("user:"+username, a))
	}
	return out
}

func makeStatsEntry(key string, a *ipAttempts) BruteForceStats {
	entry := BruteForceStats{
		IP:          key,
		FailedCount: a.Count,
		LastFailed:  a.LastFailed.UTC().Format(time.RFC3339),
	}
	if !a.BannedUntil.IsZero() {
		entry.BannedUntil = a.BannedUntil.UTC().Format(time.RFC3339)
	}
	return entry
}

// SetThresholds updates the brute-force tracking parameters.
func (b *BruteForceTracker) SetThresholds(maxAttempts int, windowMinutes int, banMinutes int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if maxAttempts > 0 {
		b.maxAttempts = maxAttempts
	}
	if windowMinutes > 0 {
		b.windowDuration = time.Duration(windowMinutes) * time.Minute
	}
	if banMinutes > 0 {
		b.banDuration = time.Duration(banMinutes) * time.Minute
	}
}

// GetThresholds returns the current tracking thresholds.
func (b *BruteForceTracker) GetThresholds() (maxAttempts, windowMinutes, banMinutes int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.maxAttempts, int(b.windowDuration.Minutes()), int(b.banDuration.Minutes())
}

// banIPViaFail2ban tries to issue a fail2ban-client manual ban (best effort).
func banIPViaFail2ban(ip string) {
	exec.Command("fail2ban-client", "set", "kilasos", "banip", ip).Run() //nolint:errcheck
}

// UnbanIP clears the ban for an IP (in our tracker AND fail2ban).
func (b *BruteForceTracker) UnbanIP(ip string) {
	b.mu.Lock()
	delete(b.attempts, ip)
	b.mu.Unlock()
	exec.Command("fail2ban-client", "set", "kilasos", "unbanip", ip).Run() //nolint:errcheck
}

// FormatThresholds for human consumption.
func (b *BruteForceTracker) String() string {
	max, win, ban := b.GetThresholds()
	return strconv.Itoa(max) + " attempts in " + strconv.Itoa(win) + "m → ban " + strconv.Itoa(ban) + "m"
}
