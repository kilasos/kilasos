package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/kilasos/kilasos/internal/audit"
	"github.com/kilasos/kilasos/internal/storage"
)

const backupJobLogsPath = "/var/lib/kilasos/backup-job-logs"

func backupStatusHandler(b storage.Backuper) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		jobs, err := b.BackupJobs(r.Context())
		if err != nil {
			if handleLicenseErr(w, err) {
				return
			}
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"jobs": jobs, "secrets_path": "/etc/kilasos/backup-secrets.json"})
	}
}

func borgInitHandler(b storage.Backuper) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) { return }
		var req struct {
			Name       string `json:"name"`
			Passphrase string `json:"passphrase"`
			Encryption string `json:"encryption"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		if req.Name == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name required"})
			return
		}
		repo, err := b.BorgInit(r.Context(), req.Name, req.Passphrase, req.Encryption)
		if err != nil {
			if handleLicenseErr(w, err) {
				return
			}
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusCreated, repo)
	}
}

func borgCreateBackupHandler(b storage.Backuper, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) { return }
		var req struct {
			RepoName    string `json:"repo_name"`
			ArchiveName string `json:"archive_name"`
			Paths       string `json:"paths"`
			Excludes    string `json:"excludes"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		if req.Paths == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "paths required"})
			return
		}
		var excludeList []string
		if req.Excludes != "" {
			for _, line := range strings.Split(req.Excludes, "\n") {
				line = strings.TrimSpace(line)
				if line != "" {
					excludeList = append(excludeList, line)
				}
			}
		}
		archive, err := b.BorgCreateBackup(r.Context(), req.RepoName, req.ArchiveName, req.Paths, excludeList)
		if err != nil {
			auditLog.LogEnriched(audit.Entry{
				User: r.Context().Value(ctxUsername).(string), Action: "borg_create",
				Detail: fmt.Sprintf("repo=%s excludes=%d err=%s", req.RepoName, len(excludeList), err.Error()),
				IP: r.RemoteAddr, OK: false,
			})
			if handleLicenseErr(w, err) {
				return
			}
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusCreated, archive)
	}
}

func borgListArchivesHandler(b storage.Backuper) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		repo := r.URL.Query().Get("repo")
		if repo == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "repo required"})
			return
		}
		archives, err := b.BorgListArchives(r.Context(), repo)
		if err != nil {
			if handleLicenseErr(w, err) {
				return
			}
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, archives)
	}
}

func borgDeleteArchiveHandler(b storage.Backuper) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) { return }
		repo := chi.URLParam(r, "repo")
		archive := chi.URLParam(r, "archive")
		if err := b.BorgDeleteArchive(r.Context(), repo, archive); err != nil {
			if handleLicenseErr(w, err) {
				return
			}
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func borgPruneHandler(b storage.Backuper) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) { return }
		var req struct {
			RepoName string `json:"repo_name"`
			Policy   string `json:"policy"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		result, err := b.BorgPrune(r.Context(), req.RepoName, req.Policy)
		if err != nil {
			if handleLicenseErr(w, err) {
				return
			}
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"result": result})
	}
}

func borgRestoreHandler(b storage.Backuper) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) { return }
		var req struct {
			RepoName    string `json:"repo_name"`
			ArchiveName string `json:"archive_name"`
			TargetPath  string `json:"target_path"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		if req.TargetPath == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "target_path required"})
			return
		}
		if err := b.BorgRestore(r.Context(), req.RepoName, req.ArchiveName, req.TargetPath); err != nil {
			if handleLicenseErr(w, err) {
				return
			}
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func borgVerifyHandler(b storage.Backuper) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			RepoName    string `json:"repo_name"`
			ArchiveName string `json:"archive_name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		result, err := b.BorgVerify(r.Context(), req.RepoName, req.ArchiveName)
		if err != nil {
			if handleLicenseErr(w, err) {
				return
			}
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, result)
	}
}

func resticInitHandler(b storage.Backuper) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) { return }
		var req struct {
			Name       string            `json:"name"`
			Passphrase string            `json:"passphrase"`
			Backend    string            `json:"backend"`
			Creds      map[string]string `json:"creds"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		if req.Name == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name required"})
			return
		}
		repo, err := b.ResticInit(r.Context(), req.Name, req.Passphrase, req.Backend, req.Creds)
		if err != nil {
			if handleLicenseErr(w, err) {
				return
			}
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusCreated, repo)
	}
}

func resticCreateBackupHandler(b storage.Backuper) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) { return }
		var req struct {
			RepoName string   `json:"repo_name"`
			Paths    string   `json:"paths"`
			Tags     []string `json:"tags"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		if req.Paths == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "paths required"})
			return
		}
		snapshot, err := b.ResticCreateBackup(r.Context(), req.RepoName, req.Paths, req.Tags)
		if err != nil {
			if handleLicenseErr(w, err) {
				return
			}
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusCreated, snapshot)
	}
}

func resticListSnapshotsHandler(b storage.Backuper) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		repo := r.URL.Query().Get("repo")
		if repo == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "repo required"})
			return
		}
		snapshots, err := b.ResticListSnapshots(r.Context(), repo)
		if err != nil {
			if handleLicenseErr(w, err) {
				return
			}
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, snapshots)
	}
}

func resticDeleteSnapshotHandler(b storage.Backuper) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) { return }
		repo := chi.URLParam(r, "repo")
		snapshotID := chi.URLParam(r, "snapshot")
		if err := b.ResticDeleteSnapshot(r.Context(), repo, snapshotID); err != nil {
			if handleLicenseErr(w, err) {
				return
			}
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func resticRestoreHandler(b storage.Backuper) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) { return }
		var req struct {
			RepoName   string `json:"repo_name"`
			SnapshotID string `json:"snapshot_id"`
			TargetPath string `json:"target_path"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		if req.TargetPath == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "target_path required"})
			return
		}
		if err := b.ResticRestore(r.Context(), req.RepoName, req.SnapshotID, req.TargetPath); err != nil {
			if handleLicenseErr(w, err) {
				return
			}
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func resticVerifyHandler(b storage.Backuper) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			RepoName   string `json:"repo_name"`
			SnapshotID string `json:"snapshot_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		result, err := b.ResticVerify(r.Context(), req.RepoName, req.SnapshotID)
		if err != nil {
			if handleLicenseErr(w, err) {
				return
			}
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, result)
	}
}

func rcloneRemoteAddHandler(b storage.Backuper) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) { return }
		var req struct {
			Name       string `json:"name"`
			RemoteType string `json:"remote_type"`
			Endpoint   string `json:"endpoint"`
			SourcePath string `json:"source_path"`
			DestPath   string `json:"dest_path"`
			Bandwidth  string `json:"bandwidth"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		if req.Name == "" || req.RemoteType == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name and remote_type required"})
			return
		}
		if req.Bandwidth != "" && !regexp.MustCompile(`^[0-9]+[kmgKMG](:[0-9]+[kmgKMG])?$`).MatchString(req.Bandwidth) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid bandwidth syntax"})
			return
		}
		remote, err := b.RcloneRemoteAdd(r.Context(), req.Name, req.RemoteType, req.Endpoint, req.SourcePath, req.DestPath, req.Bandwidth)
		if err != nil {
			if handleLicenseErr(w, err) {
				return
			}
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusCreated, remote)
	}
}

func rcloneRemoteRemoveHandler(b storage.Backuper) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) { return }
		name := chi.URLParam(r, "name")
		if err := b.RcloneRemoteRemove(r.Context(), name); err != nil {
			if handleLicenseErr(w, err) {
				return
			}
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func rcloneRemoteListHandler(b storage.Backuper) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		remotes, err := b.RcloneRemoteList(r.Context())
		if err != nil {
			if handleLicenseErr(w, err) {
				return
			}
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, remotes)
	}
}

func rcloneSyncHandler(b storage.Backuper) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) { return }
		var req struct {
			Name   string `json:"name"`
			OneWay bool   `json:"one_way"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		if req.Name == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name required"})
			return
		}
		remotes, err := b.RcloneRemoteList(r.Context())
		if err != nil {
			if handleLicenseErr(w, err) {
				return
			}
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		var srcPath, destPath, bandwidth string
		for _, rem := range remotes {
			if rem.Name == req.Name {
				srcPath = rem.SourcePath
				destPath = rem.DestPath
				bandwidth = rem.Bandwidth
				break
			}
		}
		result, err := b.RcloneSync(r.Context(), req.Name, req.OneWay, srcPath, destPath, bandwidth)
		if err != nil {
			if handleLicenseErr(w, err) {
				return
			}
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"result": result})
	}
}

func backupJobsHandler(b storage.Backuper) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		jobs, err := b.BackupJobs(r.Context())
		if err != nil {
			if handleLicenseErr(w, err) {
				return
			}
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, jobs)
	}
}

func createBackupJobHandler(b storage.Backuper) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) { return }
		var j storage.BackupJob
		if err := json.NewDecoder(r.Body).Decode(&j); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		job, err := b.CreateBackupJob(r.Context(), j)
		if err != nil {
			if handleLicenseErr(w, err) {
				return
			}
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusCreated, job)
	}
}

func updateBackupJobHandler(b storage.Backuper) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) { return }
		id := chi.URLParam(r, "id")
		var j storage.BackupJob
		if err := json.NewDecoder(r.Body).Decode(&j); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		j.ID = id
		job, err := b.UpdateBackupJob(r.Context(), j)
		if err != nil {
			if handleLicenseErr(w, err) {
				return
			}
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, job)
	}
}

func deleteBackupJobHandler(b storage.Backuper) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) { return }
		id := chi.URLParam(r, "id")
		if err := b.DeleteBackupJob(r.Context(), id); err != nil {
			if handleLicenseErr(w, err) {
				return
			}
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func runBackupJobHandler(b storage.Backuper) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) { return }
		id := chi.URLParam(r, "id")
		if err := b.RunBackupJob(r.Context(), id); err != nil {
			if handleLicenseErr(w, err) {
				return
			}
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func backupJobRunsHandler(b storage.Backuper) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		runs, err := b.BackupJobRuns(r.Context(), id)
		if err != nil {
			if handleLicenseErr(w, err) {
				return
			}
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, runs)
	}
}

func backupJobRunHandler(b storage.Backuper) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		runID := chi.URLParam(r, "runID")
		run, err := b.BackupJobRun(r.Context(), id, runID)
		if err != nil {
			if handleLicenseErr(w, err) {
				return
			}
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, run)
	}
}

func backupJobRunLogHandler(b storage.Backuper) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		runID := chi.URLParam(r, "runID")
		logPath := filepath.Join(backupJobLogsPath, id, runID+".log")
		data, err := os.ReadFile(logPath)
		if os.IsNotExist(err) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "log not found"})
			return
		}
		if err != nil {
			if handleLicenseErr(w, err) {
				return
			}
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write(data)
	}
}

func restorePointsHandler(b storage.Backuper) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		backupType := r.URL.Query().Get("backup_type")
		repo := r.URL.Query().Get("repo")
		if backupType == "" || repo == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "backup_type and repo required"})
			return
		}
		points, err := b.RestorePoints(r.Context(), backupType, repo)
		if err != nil {
			if handleLicenseErr(w, err) {
				return
			}
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, points)
	}
}

func cloudCostEstimateHandler(b storage.Backuper) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		provider := r.URL.Query().Get("provider")
		sizeGB, _ := strconv.ParseFloat(r.URL.Query().Get("size_gb"), 64)
		if sizeGB <= 0 {
			sizeGB = 1000
		}
		result, err := b.CloudCostEstimate(r.Context(), provider, sizeGB)
		if err != nil {
			if handleLicenseErr(w, err) {
				return
			}
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, result)
	}
}
