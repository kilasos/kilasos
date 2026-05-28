package scheduler

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/kilasos/kilasos/internal/audit"
	"github.com/kilasos/kilasos/internal/storage"
	"github.com/kilasos/kilasos/internal/zfssend"
	"github.com/robfig/cron/v3"
)

type Freq string

const (
	FreqHourly Freq = "hourly"
	FreqDaily  Freq = "daily"
	FreqWeekly Freq = "weekly"
)

type Schedule struct {
	ID         string    `json:"id"`
	Kind       string    `json:"kind,omitempty"` // snapshot | scrub | replication
	Pool       string    `json:"pool"`
	Freq       Freq      `json:"freq"`
	Keep       int       `json:"keep"`
	Enabled    bool      `json:"enabled"`
	LastRun    time.Time `json:"last_run,omitempty"`
	NextRun    time.Time `json:"next_run"`
	RemoteID   string    `json:"remote_id,omitempty"`
	RemoteName string    `json:"remote_name,omitempty"`
}

type Scheduler struct {
	mu         sync.RWMutex
	path       string
	schedules  []Schedule
	provider   storage.Provider
	sender     zfssend.Replicator
	cronParser cron.Parser
	running    sync.Map
	logger     *audit.Logger
}

func (s *Scheduler) SetSender(replicator zfssend.Replicator) {
	s.mu.Lock()
	s.sender = replicator
	s.mu.Unlock()
}

func (s *Scheduler) SetLogger(logger *audit.Logger) {
	s.mu.Lock()
	s.logger = logger
	s.mu.Unlock()
}

func New(path string, p storage.Provider) (*Scheduler, error) {
	s := &Scheduler{
		path:       path,
		provider:   p,
		cronParser: cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow),
	}
	if err := s.load(); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return s, nil
}

func (s *Scheduler) load() error {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, &s.schedules)
}

func (s *Scheduler) save() error {
	data, err := json.MarshalIndent(s.schedules, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, data, 0644)
}

func (s *Scheduler) Start(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.tick(ctx)
			}
		}
	}()
}

func (s *Scheduler) tick(ctx context.Context) {
	s.mu.RLock()
	var due []Schedule
	now := time.Now()
	for _, sc := range s.schedules {
		if sc.Enabled && now.After(sc.NextRun) {
			due = append(due, sc)
		}
	}
	s.mu.RUnlock()

	for _, sc := range due {
		sc := sc
		go s.run(ctx, sc)
	}

	go s.pollBackupJobs(ctx)
}

func (s *Scheduler) run(ctx context.Context, sc Schedule) {
	kind := sc.Kind
	if kind == "" {
		if sc.RemoteID != "" {
			kind = "replication"
		} else {
			kind = "snapshot"
		}
	}
	switch kind {
	case "replication":
		s.mu.RLock()
		sender := s.sender
		s.mu.RUnlock()
		if sender != nil {
			sender.StartSend(sc.Pool, sc.RemoteID) //nolint:errcheck
		}
	case "scrub":
		s.provider.StartScrub(ctx, sc.Pool) //nolint:errcheck
	default: // snapshot
		name := "auto-" + time.Now().UTC().Format("20060102-150405")
		if _, err := s.provider.CreateSnapshot(ctx, sc.Pool, name); err != nil {
			return
		}
		if sc.Keep > 0 {
			s.prune(ctx, sc)
		}
	}
	s.mu.Lock()
	for i, t := range s.schedules {
		if t.ID == sc.ID {
			s.schedules[i].LastRun = time.Now()
			s.schedules[i].NextRun = nextRun(sc.Freq, time.Now())
			break
		}
	}
	s.save() //nolint:errcheck
	s.mu.Unlock()
}

func (s *Scheduler) prune(ctx context.Context, sc Schedule) {
	snaps, err := s.provider.Snapshots(ctx, sc.Pool)
	if err != nil {
		return
	}
	var auto []storage.Snapshot
	for _, snap := range snaps {
		if strings.HasPrefix(snap.Name, "auto-") {
			auto = append(auto, snap)
		}
	}
	sort.Slice(auto, func(i, j int) bool { return auto[i].Created < auto[j].Created })
	for len(auto) > sc.Keep {
		s.provider.DeleteSnapshot(ctx, sc.Pool, auto[0].Name) //nolint:errcheck
		auto = auto[1:]
	}
}

func (s *Scheduler) pollBackupJobs(ctx context.Context) {
	jobs, err := s.provider.BackupJobs(ctx)
	if err != nil {
		return
	}
	now := time.Now()
	for _, job := range jobs {
		if !job.Enabled || job.Schedule == "" {
			continue
		}
		schedule, err := s.cronParser.Parse(job.Schedule)
		if err != nil {
			continue
		}
		next := schedule.Next(now.Add(-time.Minute))
		if !now.After(next) {
			continue
		}
		if _, loaded := s.running.LoadOrStore(job.ID, struct{}{}); loaded {
			continue
		}
		go s.runBackupJob(ctx, job)
	}
}

func (s *Scheduler) runBackupJob(ctx context.Context, job storage.BackupJob) {
	defer s.running.Delete(job.ID)

	runCtx, cancel := context.WithTimeout(context.Background(), 6*time.Hour)
	defer cancel()

	err := s.provider.RunBackupJob(runCtx, job.ID)
	detail := fmt.Sprintf("type=%s excludes=%d", job.Type, len(job.Excludes))
	if err != nil {
		s.logEnriched(audit.Entry{
			User:   "scheduler",
			IP:     "",
			Action: "backup_job_run",
			OK:     false,
			Detail: detail + " err=" + err.Error(),
		})
	} else {
		s.logEnriched(audit.Entry{
			User:   "scheduler",
			IP:     "",
			Action: "backup_job_run",
			OK:     true,
			Detail: detail,
		})
	}
}

func (s *Scheduler) logEnriched(e audit.Entry) {
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	s.mu.RLock()
	logger := s.logger
	s.mu.RUnlock()
	if logger != nil {
		logger.LogEnriched(e)
	}
}

func (s *Scheduler) Schedules() []Schedule {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Schedule, len(s.schedules))
	copy(out, s.schedules)
	return out
}

func (s *Scheduler) SchedulesForPool(pool string) []Schedule {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []Schedule
	for _, sc := range s.schedules {
		if sc.Pool == pool {
			out = append(out, sc)
		}
	}
	return out
}

func (s *Scheduler) Add(pool string, freq Freq, keep int) (Schedule, error) {
	if pool == "" {
		return Schedule{}, errors.New("pool is required")
	}
	if freq != FreqHourly && freq != FreqDaily && freq != FreqWeekly {
		return Schedule{}, errors.New("freq must be hourly, daily, or weekly")
	}
	if keep <= 0 {
		keep = 7
	}
	sc := Schedule{
		ID:      genID(),
		Pool:    pool,
		Freq:    freq,
		Keep:    keep,
		Enabled: true,
		NextRun: nextRun(freq, time.Now()),
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.schedules = append(s.schedules, sc)
	if err := s.save(); err != nil {
		return Schedule{}, err
	}
	return sc, nil
}

func (s *Scheduler) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, sc := range s.schedules {
		if sc.ID == id {
			s.schedules = append(s.schedules[:i], s.schedules[i+1:]...)
			return s.save()
		}
	}
	return errors.New("schedule not found")
}

func (s *Scheduler) SetEnabled(id string, enabled bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, sc := range s.schedules {
		if sc.ID == id {
			s.schedules[i].Enabled = enabled
			if enabled {
				s.schedules[i].NextRun = nextRun(sc.Freq, time.Now())
			}
			return s.save()
		}
	}
	return errors.New("schedule not found")
}

func (s *Scheduler) AddReplication(pool, remoteID, remoteName string, freq Freq) (Schedule, error) {
	if pool == "" || remoteID == "" {
		return Schedule{}, errors.New("pool and remote_id are required")
	}
	if freq != FreqHourly && freq != FreqDaily && freq != FreqWeekly {
		return Schedule{}, errors.New("freq must be hourly, daily, or weekly")
	}
	sc := Schedule{
		ID:         genID(),
		Pool:       pool,
		Freq:       freq,
		Enabled:    true,
		NextRun:    nextRun(freq, time.Now()),
		RemoteID:   remoteID,
		RemoteName: remoteName,
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.schedules = append(s.schedules, sc)
	if err := s.save(); err != nil {
		return Schedule{}, err
	}
	return sc, nil
}

func (s *Scheduler) AddScrub(pool string, freq Freq) (Schedule, error) {
	if pool == "" {
		return Schedule{}, errors.New("pool is required")
	}
	if freq != FreqHourly && freq != FreqDaily && freq != FreqWeekly {
		return Schedule{}, errors.New("freq must be hourly, daily, or weekly")
	}
	sc := Schedule{
		ID:      genID(),
		Kind:    "scrub",
		Pool:    pool,
		Freq:    freq,
		Enabled: true,
		NextRun: nextRun(freq, time.Now()),
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.schedules = append(s.schedules, sc)
	if err := s.save(); err != nil {
		return Schedule{}, err
	}
	return sc, nil
}

func nextRun(freq Freq, from time.Time) time.Time {
	switch freq {
	case FreqHourly:
		return from.Add(time.Hour)
	case FreqWeekly:
		return from.Add(7 * 24 * time.Hour)
	default:
		return from.Add(24 * time.Hour)
	}
}

func genID() string {
	b := make([]byte, 6)
	rand.Read(b) //nolint:errcheck
	return hex.EncodeToString(b)
}
