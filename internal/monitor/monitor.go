package monitor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/kilasos/kilasos/internal/notify"
	"github.com/kilasos/kilasos/internal/storage"
)

const (
	defaultTempWarn            = 55
	defaultTempCrit            = 65
	maxAlerts                  = 100
	pollInterval               = 60 * time.Second
	reAlertAfter               = time.Hour
	defaultBackupConsecutiveCrit = 3
	defaultBackupAlertRecoveryH  = 24
	backupAlertStateFile         = "/var/lib/kilasos/monitor-backup-state.json"
)

type MonitorConfig struct {
	TempWarn              int `json:"temp_warn"`
	TempCrit              int `json:"temp_crit"`
	BackupConsecutiveCrit int `json:"backup_consecutive_crit"`
	BackupAlertRecoveryH  int `json:"backup_alert_recovery_h"`
}

type BackupJobAlertState struct {
	JobID             string    `json:"job_id"`
	ConsecutiveFails int       `json:"consecutive_fails"`
	LastAlertedAt     time.Time `json:"last_alerted_at"`
}

type Alert struct {
	ID      string    `json:"id"`
	Level   string    `json:"level"`  // warn | crit | info
	Source  string    `json:"source"` // disk | pool | test
	Disk    string    `json:"disk"`
	Path    string    `json:"path"`
	Message string    `json:"message"`
	At      time.Time `json:"at"`
}

type WebhookConfig struct {
	URL    string `json:"url"`
	Secret string `json:"secret,omitempty"`
}

type Monitor struct {
	provider storage.Provider

	configMu sync.RWMutex
	config   WebhookConfig

	mailerMu sync.RWMutex
	mailer   *notify.Mailer

	mu       sync.RWMutex
	alerts   []Alert
	lastSeen map[string]time.Time

	diskState map[string]string
	poolState map[string]string

	thresholdMu              sync.RWMutex
	threshold                MonitorConfig

	backupAlertMu  sync.RWMutex
	backupAlertState []BackupJobAlertState
}

func New(p storage.Provider, url, secret string) *Monitor {
	m := &Monitor{
		provider:  p,
		config:    WebhookConfig{URL: url, Secret: secret},
		lastSeen:  make(map[string]time.Time),
		diskState: make(map[string]string),
		poolState: make(map[string]string),
		threshold: MonitorConfig{
			TempWarn:              defaultTempWarn,
			TempCrit:              defaultTempCrit,
			BackupConsecutiveCrit: defaultBackupConsecutiveCrit,
			BackupAlertRecoveryH:  defaultBackupAlertRecoveryH,
		},
	}
	m.backupAlertState, _ = loadBackupAlertState()
	return m
}

func (m *Monitor) GetThresholds() MonitorConfig {
	m.thresholdMu.RLock()
	defer m.thresholdMu.RUnlock()
	return m.threshold
}

func (m *Monitor) SetThresholds(cfg MonitorConfig) {
	if cfg.TempWarn > 0 {
		m.thresholdMu.Lock()
		m.threshold.TempWarn = cfg.TempWarn
		m.thresholdMu.Unlock()
	}
	if cfg.TempCrit > 0 {
		m.thresholdMu.Lock()
		m.threshold.TempCrit = cfg.TempCrit
		m.thresholdMu.Unlock()
	}
	if cfg.BackupConsecutiveCrit > 0 {
		m.thresholdMu.Lock()
		m.threshold.BackupConsecutiveCrit = cfg.BackupConsecutiveCrit
		m.thresholdMu.Unlock()
	}
	if cfg.BackupAlertRecoveryH > 0 {
		m.thresholdMu.Lock()
		m.threshold.BackupAlertRecoveryH = cfg.BackupAlertRecoveryH
		m.thresholdMu.Unlock()
	}
}

func (m *Monitor) SetWebhook(url, secret string) {
	m.configMu.Lock()
	m.config = WebhookConfig{URL: url, Secret: secret}
	m.configMu.Unlock()
}

func (m *Monitor) GetWebhook() WebhookConfig {
	m.configMu.RLock()
	defer m.configMu.RUnlock()
	return m.config
}

func (m *Monitor) SetMailer(ml *notify.Mailer) {
	m.mailerMu.Lock()
	m.mailer = ml
	m.mailerMu.Unlock()
}

func (m *Monitor) GetMailer() *notify.Mailer {
	m.mailerMu.RLock()
	defer m.mailerMu.RUnlock()
	return m.mailer
}

func (m *Monitor) TestEmail() error {
	m.mailerMu.RLock()
	ml := m.mailer
	m.mailerMu.RUnlock()
	if ml == nil {
		return fmt.Errorf("email not configured")
	}
	return ml.Test()
}

func (m *Monitor) Start(ctx context.Context) {
	go func() {
		m.poll(ctx)
		t := time.NewTicker(pollInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				m.poll(ctx)
			}
		}
	}()
}

func (m *Monitor) Alerts() []Alert {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Alert, len(m.alerts))
	copy(out, m.alerts)
	return out
}

func (m *Monitor) Dismiss(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, a := range m.alerts {
		if a.ID == id {
			m.alerts = append(m.alerts[:i], m.alerts[i+1:]...)
			return
		}
	}
}

func (m *Monitor) poll(ctx context.Context) {
	m.pollDisks(ctx)
	m.pollPools(ctx)
	m.pollBackupJobs(ctx)
}

func (m *Monitor) pollDisks(ctx context.Context) {
	disks, err := m.provider.Disks(ctx)
	if err != nil {
		slog.Error("monitor poll failed", "method", "pollDisks", "err", err)
		return
	}
	for _, d := range disks {
		if !d.SmartOK {
			m.raise("crit", "disk", d.Name, d.Path, "SMART self-test failed",
				fmt.Sprintf("smart:%s:fail", d.Path))
		}
		if d.TempCelsius != nil {
			t := *d.TempCelsius
			switch {
			case t >= m.threshold.TempCrit:
				m.raise("crit", "disk", d.Name, d.Path, fmt.Sprintf("temperature critical: %d°C", t),
					fmt.Sprintf("temp:%s:crit", d.Path))
			case t >= m.threshold.TempWarn:
				m.raise("warn", "disk", d.Name, d.Path, fmt.Sprintf("temperature high: %d°C", t),
					fmt.Sprintf("temp:%s:warn", d.Path))
			}
		}
	if d.ReallocatedSectors != nil && *d.ReallocatedSectors > 0 {
			m.raise("warn", "disk", d.Name, d.Path,
				fmt.Sprintf("reallocated sectors: %d", *d.ReallocatedSectors),
				fmt.Sprintf("realloc:%s", d.Path))
		}
		prev, had := m.diskState[d.Path]
		cur := "ok"
		if !d.SmartOK {
			cur = "smart-fail"
		} else if d.TempCelsius != nil && *d.TempCelsius >= m.threshold.TempCrit {
			cur = "temp-crit"
		}
		m.diskState[d.Path] = cur
		if had && prev != "ok" && cur == "ok" {
			m.raise("info", "disk", d.Name, d.Path, "SMART and temperature returned to normal",
				fmt.Sprintf("recovery:disk:%s", d.Path))
		}
	}
}

func (m *Monitor) pollPools(ctx context.Context) {
	arrays, err := m.provider.Arrays(ctx)
	if err != nil || len(arrays) == 0 {
		if err != nil {
			slog.Error("monitor poll failed", "method", "pollPools", "err", err)
		}
		return
	}
	for _, a := range arrays {
		h, err := m.provider.PoolHealth(ctx, a.Name)
		if err != nil {
			continue
		}
		if h.State != "" && h.State != "online" {
			m.raise("crit", "pool", a.Name, a.Name, fmt.Sprintf("pool state: %s", h.State),
				fmt.Sprintf("pool:%s:state:%s", a.Name, h.State))
		}
		if h.Scrub.State == "completed" && h.Scrub.Errors > 0 {
			m.raise("crit", "pool", a.Name, a.Name,
				fmt.Sprintf("scrub completed with %d errors", h.Scrub.Errors),
				fmt.Sprintf("pool:%s:scrub-errors", a.Name))
		}
		prev, had := m.poolState[a.Name]
		cur := h.State
		if cur == "" {
			cur = "online"
		}
		m.poolState[a.Name] = cur
		if had && prev != "online" && cur == "online" {
			m.raise("info", "pool", a.Name, a.Name, "pool returned to online state",
				fmt.Sprintf("recovery:pool:%s", a.Name))
		}
	}
}

func (m *Monitor) pollBackupJobs(ctx context.Context) {
	jobs, err := m.provider.BackupJobs(ctx)
	if err != nil {
		slog.Error("monitor poll failed", "method", "pollBackupJobs", "err", err)
		return
	}

	m.backupAlertMu.Lock()
	defer m.backupAlertMu.Unlock()

	stateMap := make(map[string]*BackupJobAlertState, len(m.backupAlertState))
	for i := range m.backupAlertState {
		stateMap[m.backupAlertState[i].JobID] = &m.backupAlertState[i]
	}

	for _, job := range jobs {
		if !job.Enabled {
			continue
		}
		state := stateMap[job.ID]
		if state == nil {
			state = &BackupJobAlertState{JobID: job.ID}
			stateMap[job.ID] = state
		}

		switch job.LastResult {
		case "failed":
			state.ConsecutiveFails++
			severity := "warn"
			if state.ConsecutiveFails >= m.threshold.BackupConsecutiveCrit {
				severity = "crit"
			}
			rateLimited := time.Since(state.LastAlertedAt) < time.Duration(m.threshold.BackupAlertRecoveryH)*time.Hour
			if !rateLimited {
				state.LastAlertedAt = time.Now()
				m.raise(severity, "backup", job.Name, job.Destination,
					fmt.Sprintf("backup job %s failed (consecutive fails: %d)", job.Name, state.ConsecutiveFails),
					fmt.Sprintf("backup:%s:fail", job.ID))
			}
		case "ok":
			if state.ConsecutiveFails > 0 {
				m.raise("info", "backup", job.Name, job.Destination,
					fmt.Sprintf("backup job %s recovered", job.Name),
					fmt.Sprintf("backup:%s:recovery", job.ID))
			}
			state.ConsecutiveFails = 0
		}
	}

	m.backupAlertState = make([]BackupJobAlertState, 0, len(stateMap))
	for _, s := range stateMap {
		m.backupAlertState = append(m.backupAlertState, *s)
	}

	saveBackupAlertState(m.backupAlertState)
}

func loadBackupAlertState() ([]BackupJobAlertState, error) {
	data, err := os.ReadFile(backupAlertStateFile)
	if err != nil {
		return nil, err
	}
	var state []BackupJobAlertState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, err
	}
	return state, nil
}

func saveBackupAlertState(state []BackupJobAlertState) {
	data, err := json.Marshal(state)
	if err != nil {
		slog.Warn("failed to marshal backup alert state", "err", err)
		return
	}
	if err := os.WriteFile(backupAlertStateFile, data, 0644); err != nil {
		slog.Warn("failed to write backup alert state", "err", err)
	}
}

// TestPing sends a test webhook payload and returns any error.
func (m *Monitor) TestPing() error {
	return m.sendWebhook(Alert{
		ID:      fmt.Sprintf("%d", time.Now().UnixNano()),
		Level:   "info",
		Source:  "test",
		Disk:    "kilasos",
		Message: "KilasOS webhook test ping",
		At:      time.Now().UTC(),
	})
}

func (m *Monitor) raise(level, source, disk, path, message, key string) {
	m.mu.Lock()
	if last, seen := m.lastSeen[key]; seen && time.Since(last) < reAlertAfter {
		m.mu.Unlock()
		return
	}
	a := Alert{
		ID:      fmt.Sprintf("%d", time.Now().UnixNano()),
		Level:   level,
		Source:  source,
		Disk:    disk,
		Path:    path,
		Message: message,
		At:      time.Now().UTC(),
	}
	m.lastSeen[key] = a.At
	m.alerts = append([]Alert{a}, m.alerts...)
	if len(m.alerts) > maxAlerts {
		m.alerts = m.alerts[:maxAlerts]
	}
	now := a.At
	for k, v := range m.lastSeen {
		if now.Sub(v) > reAlertAfter*2 {
			delete(m.lastSeen, k)
		}
	}
	m.mu.Unlock()

	go m.sendWebhook(a) //nolint:errcheck
	go m.sendEmail(a)   //nolint:errcheck
}

func (m *Monitor) sendEmail(a Alert) error {
	m.mailerMu.RLock()
	ml := m.mailer
	m.mailerMu.RUnlock()
	if ml == nil {
		return nil
	}
	subject := fmt.Sprintf("[KilasOS] %s alert: %s", a.Level, a.Disk)
	body := fmt.Sprintf("Level:   %s\nSource:  %s\nDisk:    %s\nPath:    %s\nMessage: %s\nTime:    %s\n",
		a.Level, a.Source, a.Disk, a.Path, a.Message, a.At.Format("2006-01-02 15:04:05 UTC"))
	return ml.Send(subject, body)
}

func (m *Monitor) sendWebhook(a Alert) error {
	m.configMu.RLock()
	cfg := m.config
	m.configMu.RUnlock()
	if cfg.URL == "" {
		return nil
	}
	body, err := json.Marshal(a)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if cfg.Secret != "" {
		req.Header.Set("X-KilasOS-Secret", cfg.Secret)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook returned HTTP %d", resp.StatusCode)
	}
	return nil
}
