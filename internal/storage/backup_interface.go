package storage

import "context"

// Backuper is the interface for backup & cloud sync operations.
// Both the Home-tier provider stub and the Pro-tier pro/backup implementation satisfy it.
type Backuper interface {
	BorgInit(ctx context.Context, name, passphrase, encryption string) (BorgRepo, error)
	BorgCreateBackup(ctx context.Context, repoName, archiveName, paths string, excludes []string) (BorgArchive, error)
	BorgListArchives(ctx context.Context, repoName string) ([]BorgArchive, error)
	BorgDeleteArchive(ctx context.Context, repoName, archiveName string) error
	BorgPrune(ctx context.Context, repoName, policy string) (string, error)
	BorgRestore(ctx context.Context, repoName, archiveName, targetPath string) error
	BorgVerify(ctx context.Context, repoName, archiveName string) (BackupVerification, error)
	ResticInit(ctx context.Context, name, passphrase, backend string, creds map[string]string) (ResticRepo, error)
	ResticCreateBackup(ctx context.Context, repoName, paths string, tags []string) (ResticSnapshot, error)
	ResticListSnapshots(ctx context.Context, repoName string) ([]ResticSnapshot, error)
	ResticDeleteSnapshot(ctx context.Context, repoName, snapshotID string) error
	ResticRestore(ctx context.Context, repoName, snapshotID, targetPath string) error
	ResticVerify(ctx context.Context, repoName, snapshotID string) (BackupVerification, error)
	ResticForget(ctx context.Context, repoName string, keepHourly, keepDaily, keepWeekly, keepMonthly, keepYearly int) (string, error)
	RcloneRemoteAdd(ctx context.Context, name, remoteType, endpoint, sourcePath, destPath, bandwidth string) (RcloneRemote, error)
	RcloneRemoteRemove(ctx context.Context, name string) error
	RcloneRemoteList(ctx context.Context) ([]RcloneRemote, error)
	RcloneSync(ctx context.Context, name string, oneWay bool, srcPath, destPath, bandwidth string) (string, error)
	BackupJobs(ctx context.Context) ([]BackupJob, error)
	CreateBackupJob(ctx context.Context, j BackupJob) (BackupJob, error)
	DeleteBackupJob(ctx context.Context, id string) error
	UpdateBackupJob(ctx context.Context, j BackupJob) (BackupJob, error)
	RunBackupJob(ctx context.Context, id string) error
	BackupJobRuns(ctx context.Context, jobID string) ([]BackupJobRun, error)
	BackupJobRun(ctx context.Context, jobID, runID string) (BackupJobRun, error)
	RestorePoints(ctx context.Context, backupType, repo string) ([]RestorePoint, error)
	CloudCostEstimate(ctx context.Context, provider string, sizeGB float64) (CloudCostEstimate, error)
}
