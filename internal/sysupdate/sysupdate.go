package sysupdate

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"io"
	"os/exec"
	"strings"
	"sync"
	"time"
)

type UpdateInfo struct {
	Upgradable  int   `json:"upgradable"`
	LastChecked int64 `json:"last_checked"` // unix; 0 = never checked
}

type job struct {
	mu         sync.Mutex
	ID         string     `json:"id"`
	Action     string     `json:"action"` // "check" | "apply"
	Status     string     `json:"status"` // "running" | "done" | "failed"
	Lines      []string   `json:"lines"`
	StartedAt  time.Time  `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
}

func (j *job) emit(line string) {
	j.mu.Lock()
	j.Lines = append(j.Lines, line)
	j.mu.Unlock()
}

func (j *job) finish(err error) {
	now := time.Now()
	j.mu.Lock()
	j.FinishedAt = &now
	if err != nil {
		j.Status = "failed"
		j.Lines = append(j.Lines, "FAILED: "+err.Error())
	} else {
		j.Status = "done"
		j.Lines = append(j.Lines, "Done.")
	}
	j.mu.Unlock()
}

// JobView is the public snapshot returned to callers.
type JobView struct {
	ID         string     `json:"id"`
	Action     string     `json:"action"`
	Status     string     `json:"status"`
	Lines      []string   `json:"lines"`
	StartedAt  time.Time  `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
}

type Manager struct {
	infoMu sync.RWMutex
	info   UpdateInfo

	jobsMu sync.RWMutex
	jobs   map[string]*job
}

func NewManager() *Manager {
	return &Manager{jobs: make(map[string]*job)}
}

func (m *Manager) Info() UpdateInfo {
	m.infoMu.RLock()
	defer m.infoMu.RUnlock()
	return m.info
}

func (m *Manager) GetJob(id string) (JobView, bool) {
	m.jobsMu.RLock()
	j, ok := m.jobs[id]
	m.jobsMu.RUnlock()
	if !ok {
		return JobView{}, false
	}
	j.mu.Lock()
	v := JobView{
		ID: j.ID, Action: j.Action, Status: j.Status,
		Lines:      append([]string{}, j.Lines...),
		StartedAt:  j.StartedAt,
		FinishedAt: j.FinishedAt,
	}
	j.mu.Unlock()
	return v, true
}

func (m *Manager) newJob(action string) *job {
	j := &job{ID: genID(), Action: action, Status: "running", StartedAt: time.Now()}
	m.jobsMu.Lock()
	m.jobs[j.ID] = j
	m.jobsMu.Unlock()
	return j
}

// StartCheck runs apt-get update then counts upgradable packages.
func (m *Manager) StartCheck() string {
	j := m.newJob("check")
	go func() {
		j.emit("Running apt-get update…")
		if out, err := exec.Command("apt-get", "update", "-qq").CombinedOutput(); err != nil {
			for _, line := range splitLines(string(out)) {
				j.emit(line)
			}
			j.finish(err)
			return
		}
		j.emit("Counting upgradable packages…")
		out, _ := exec.Command("apt", "list", "--upgradable").CombinedOutput()
		count := countUpgradable(string(out))
		for _, line := range splitLines(string(out)) {
			j.emit(line)
		}
		m.infoMu.Lock()
		m.info = UpdateInfo{Upgradable: count, LastChecked: time.Now().Unix()}
		m.infoMu.Unlock()
		j.finish(nil)
	}()
	return j.ID
}

// StartApply runs apt-get upgrade -y with live output.
func (m *Manager) StartApply() string {
	j := m.newJob("apply")
	go func() {
		j.emit("Running apt-get upgrade…")
		cmd := exec.Command("apt-get", "upgrade", "-y",
			"-o", "Dpkg::Options::=--force-confdef",
			"-o", "Dpkg::Options::=--force-confold")
		cmd.Env = append(cmd.Environ(), "DEBIAN_FRONTEND=noninteractive")
		pr, pw := io.Pipe()
		cmd.Stdout = pw
		cmd.Stderr = pw
		if err := cmd.Start(); err != nil {
			pw.Close()
			pr.Close()
			j.finish(err)
			return
		}
		waitDone := make(chan error, 1)
		go func() { waitDone <- cmd.Wait(); pw.Close() }()
		sc := bufio.NewScanner(pr)
		for sc.Scan() {
			j.emit(sc.Text())
		}
		err := <-waitDone

		// Re-check count after applying
		if err == nil {
			out, _ := exec.Command("apt", "list", "--upgradable").CombinedOutput()
			count := countUpgradable(string(out))
			m.infoMu.Lock()
			m.info.Upgradable = count
			m.info.LastChecked = time.Now().Unix()
			m.infoMu.Unlock()
		}
		j.finish(err)
	}()
	return j.ID
}

func countUpgradable(output string) int {
	n := 0
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		// Each upgradable package line contains "/" (e.g. "bash/focal 5.0 amd64")
		if strings.Contains(line, "/") {
			n++
		}
	}
	return n
}

func splitLines(s string) []string {
	var out []string
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		out = append(out, sc.Text())
	}
	return out
}

func genID() string {
	b := make([]byte, 8)
	rand.Read(b) //nolint:errcheck
	return hex.EncodeToString(b)
}
