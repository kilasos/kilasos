package storage

import (
	"context"

	"github.com/kilasos/kilasos/internal/license"
)

func (p *linuxProvider) BorgInit(ctx context.Context, name, passphrase, encryption string) (BorgRepo, error) {
	return BorgRepo{}, license.ErrFeatureNotLicensed
}

func (p *linuxProvider) BorgCreateBackup(ctx context.Context, repoName, archiveName, paths string, excludes []string) (BorgArchive, error) {
	return BorgArchive{}, license.ErrFeatureNotLicensed
}

func (p *linuxProvider) BorgListArchives(ctx context.Context, repoName string) ([]BorgArchive, error) {
	return nil, license.ErrFeatureNotLicensed
}

func (p *linuxProvider) BorgDeleteArchive(ctx context.Context, repoName, archiveName string) error {
	return license.ErrFeatureNotLicensed
}

func (p *linuxProvider) BorgPrune(ctx context.Context, repoName, policy string) (string, error) {
	return "", license.ErrFeatureNotLicensed
}

func (p *linuxProvider) BorgRestore(ctx context.Context, repoName, archiveName, targetPath string) error {
	return license.ErrFeatureNotLicensed
}

func (p *linuxProvider) BorgVerify(ctx context.Context, repoName, archiveName string) (BackupVerification, error) {
	return BackupVerification{}, license.ErrFeatureNotLicensed
}

func (p *linuxProvider) ResticInit(ctx context.Context, name, passphrase, backend string, creds map[string]string) (ResticRepo, error) {
	return ResticRepo{}, license.ErrFeatureNotLicensed
}

func (p *linuxProvider) ResticCreateBackup(ctx context.Context, repoName, paths string, tags []string) (ResticSnapshot, error) {
	return ResticSnapshot{}, license.ErrFeatureNotLicensed
}

func (p *linuxProvider) ResticListSnapshots(ctx context.Context, repoName string) ([]ResticSnapshot, error) {
	return nil, license.ErrFeatureNotLicensed
}

func (p *linuxProvider) ResticDeleteSnapshot(ctx context.Context, repoName, snapshotID string) error {
	return license.ErrFeatureNotLicensed
}

func (p *linuxProvider) ResticRestore(ctx context.Context, repoName, snapshotID, targetPath string) error {
	return license.ErrFeatureNotLicensed
}

func (p *linuxProvider) ResticVerify(ctx context.Context, repoName, snapshotID string) (BackupVerification, error) {
	return BackupVerification{}, license.ErrFeatureNotLicensed
}

func (p *linuxProvider) ResticForget(ctx context.Context, repoName string, keepHourly, keepDaily, keepWeekly, keepMonthly, keepYearly int) (string, error) {
	return "", license.ErrFeatureNotLicensed
}

func (p *linuxProvider) RcloneRemoteAdd(ctx context.Context, name, remoteType, endpoint, sourcePath, destPath, bandwidth string) (RcloneRemote, error) {
	return RcloneRemote{}, license.ErrFeatureNotLicensed
}

func (p *linuxProvider) RcloneRemoteRemove(ctx context.Context, name string) error {
	return license.ErrFeatureNotLicensed
}

func (p *linuxProvider) RcloneRemoteList(ctx context.Context) ([]RcloneRemote, error) {
	return nil, license.ErrFeatureNotLicensed
}

func (p *linuxProvider) RcloneSync(ctx context.Context, name string, oneWay bool, srcPath, destPath string, bandwidth string) (string, error) {
	return "", license.ErrFeatureNotLicensed
}

func (p *linuxProvider) BackupJobs(ctx context.Context) ([]BackupJob, error) {
	return nil, license.ErrFeatureNotLicensed
}

func (p *linuxProvider) CreateBackupJob(ctx context.Context, j BackupJob) (BackupJob, error) {
	return BackupJob{}, license.ErrFeatureNotLicensed
}

func (p *linuxProvider) DeleteBackupJob(ctx context.Context, id string) error {
	return license.ErrFeatureNotLicensed
}

func (p *linuxProvider) UpdateBackupJob(ctx context.Context, j BackupJob) (BackupJob, error) {
	return BackupJob{}, license.ErrFeatureNotLicensed
}

func (p *linuxProvider) RunBackupJob(ctx context.Context, id string) error {
	return license.ErrFeatureNotLicensed
}

func (p *linuxProvider) BackupJobRuns(ctx context.Context, jobID string) ([]BackupJobRun, error) {
	return nil, license.ErrFeatureNotLicensed
}

func (p *linuxProvider) BackupJobRun(ctx context.Context, jobID, runID string) (BackupJobRun, error) {
	return BackupJobRun{}, license.ErrFeatureNotLicensed
}

func (p *linuxProvider) RestorePoints(ctx context.Context, backupType, repo string) ([]RestorePoint, error) {
	return nil, license.ErrFeatureNotLicensed
}

func (p *linuxProvider) CloudCostEstimate(ctx context.Context, provider string, sizeGB float64) (CloudCostEstimate, error) {
	return CloudCostEstimate{}, license.ErrFeatureNotLicensed
}

func (p *linuxProvider) BackupSecretsPath() string {
	return "/etc/kilasos/backup-secrets.json"
}
