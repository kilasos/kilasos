package zfssend

// Replicator is the interface for ZFS send/receive replication.
// Both the Home-tier stub and the Pro-tier real implementation satisfy it.
type Replicator interface {
	Remotes() []Remote
	AddRemote(name, host, user, destPool string, port int) (Remote, error)
	DeleteRemote(id string) error
	StartSend(pool, remoteID string) (string, error)
	GetJob(id string) (JobView, bool)
	AllJobs() []JobView
}
