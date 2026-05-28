package zfssend

import (
	"github.com/kilasos/kilasos/internal/license"
)

type Remote struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Host     string `json:"host"`
	User     string `json:"user"`
	DestPool string `json:"dest_pool"`
	Port     int    `json:"port,omitempty"`
}

type JobView struct {
	ID         string `json:"id"`
	Pool       string `json:"pool"`
	RemoteName string `json:"remote_name"`
	Status     string `json:"status"`
}

type Manager struct{}

func NewManager(path string) (*Manager, error) {
	return &Manager{}, nil
}

func (m *Manager) Remotes() []Remote                          { return nil }
func (m *Manager) AddRemote(name, host, user, destPool string, port int) (Remote, error) {
	return Remote{}, license.ErrFeatureNotLicensed
}
func (m *Manager) DeleteRemote(id string) error { return license.ErrFeatureNotLicensed }
func (m *Manager) GetJob(id string) (JobView, bool) { return JobView{}, false }
func (m *Manager) AllJobs() []JobView                   { return nil }
func (m *Manager) StartSend(pool, remoteID string) (string, error) {
	return "", license.ErrFeatureNotLicensed
}
