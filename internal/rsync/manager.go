package rsync

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

type Freq string

const (
	FreqHourly Freq = "hourly"
	FreqDaily  Freq = "daily"
	FreqWeekly Freq = "weekly"
)

type Job struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Source      string    `json:"source"`      // local path e.g. /mnt/datapool/media
	Destination string    `json:"destination"` // local path or user@host:path
	Freq        Freq      `json:"freq"`
	Enabled     bool      `json:"enabled"`
	DeleteExtra bool      `json:"delete_extra"` // pass --delete
	LastRun     time.Time `json:"last_run,omitempty"`
	NextRun     time.Time `json:"next_run"`
}

type JobStatus struct {
	JobID   string    `json:"job_id"`
	Running bool      `json:"running"`
	Started time.Time `json:"started,omitempty"`
	Lines   []string  `json:"lines"`
	ExitErr string    `json:"exit_err,omitempty"`
	Done    bool      `json:"done"`
}

type Manager struct {
	mu      sync.RWMutex
	path    string
	jobs    []Job
	statuses map[string]*JobStatus
}

func NewManager(path string) (*Manager, error) {
	m := &Manager{path: path, statuses: make(map[string]*JobStatus)}
	if err := m.load(); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return m, nil
}

func (m *Manager) load() error {
	data, err := os.ReadFile(m.path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, &m.jobs)
}

func (m *Manager) save() error {
	data, err := json.MarshalIndent(m.jobs, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(m.path, data, 0644)
}

func (m *Manager) Start(ctx context.Context) {
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				m.tick(ctx)
			}
		}
	}()
}

func (m *Manager) tick(ctx context.Context) {
	m.mu.RLock()
	var due []Job
	now := time.Now()
	for _, j := range m.jobs {
		if j.Enabled && now.After(j.NextRun) {
			due = append(due, j)
		}
	}
	m.mu.RUnlock()
	for _, j := range due {
		j := j
		go m.run(ctx, j)
	}
}

func (m *Manager) run(ctx context.Context, j Job) {
	m.mu.Lock()
	st := &JobStatus{JobID: j.ID, Running: true, Started: time.Now()}
	m.statuses[j.ID] = st
	m.mu.Unlock()

	args := []string{"-avz", "--progress"}
	if j.DeleteExtra {
		args = append(args, "--delete")
	}
	src := j.Source
	if !strings.HasSuffix(src, "/") {
		src += "/"
	}
	args = append(args, src, j.Destination)

	cmd := exec.CommandContext(ctx, "rsync", args...)
	stdout, _ := cmd.StdoutPipe()
	cmd.Stderr = cmd.Stdout
	err := cmd.Start()
	if err == nil && stdout != nil {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			m.mu.Lock()
			st.Lines = append(st.Lines, line)
			if len(st.Lines) > 500 {
				st.Lines = st.Lines[len(st.Lines)-500:]
			}
			m.mu.Unlock()
		}
		err = cmd.Wait()
	}

	m.mu.Lock()
	st.Running = false
	st.Done = true
	if err != nil {
		st.ExitErr = err.Error()
	}
	for i, jj := range m.jobs {
		if jj.ID == j.ID {
			m.jobs[i].LastRun = time.Now()
			m.jobs[i].NextRun = nextRun(j.Freq, time.Now())
			break
		}
	}
	m.save() //nolint:errcheck
	m.mu.Unlock()
}

func (m *Manager) Jobs() []Job {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Job, len(m.jobs))
	copy(out, m.jobs)
	return out
}

func (m *Manager) Add(j Job) (Job, error) {
	if j.Name == "" || j.Source == "" || j.Destination == "" {
		return Job{}, errors.New("name, source, and destination are required")
	}
	if j.Freq != FreqHourly && j.Freq != FreqDaily && j.Freq != FreqWeekly {
		j.Freq = FreqDaily
	}
	j.ID = genID()
	j.Enabled = true
	j.NextRun = nextRun(j.Freq, time.Now())
	m.mu.Lock()
	defer m.mu.Unlock()
	m.jobs = append(m.jobs, j)
	if err := m.save(); err != nil {
		return Job{}, err
	}
	return j, nil
}

func (m *Manager) Delete(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, j := range m.jobs {
		if j.ID == id {
			m.jobs = append(m.jobs[:i], m.jobs[i+1:]...)
			return m.save()
		}
	}
	return errors.New("job not found")
}

func (m *Manager) SetEnabled(id string, enabled bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, j := range m.jobs {
		if j.ID == id {
			m.jobs[i].Enabled = enabled
			if enabled {
				m.jobs[i].NextRun = nextRun(j.Freq, time.Now())
			}
			return m.save()
		}
	}
	return errors.New("job not found")
}

func (m *Manager) RunNow(ctx context.Context, id string) error {
	m.mu.RLock()
	var found *Job
	for _, j := range m.jobs {
		if j.ID == id {
			jj := j
			found = &jj
			break
		}
	}
	m.mu.RUnlock()
	if found == nil {
		return errors.New("job not found")
	}
	// Use background context so the job survives the HTTP request completion.
	go m.run(context.Background(), *found)
	return nil
}

func (m *Manager) Status(id string) *JobStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()
	st := m.statuses[id]
	if st == nil {
		return nil
	}
	out := *st
	out.Lines = append([]string(nil), st.Lines...)
	return &out
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
