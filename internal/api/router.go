package api

import (
	"bufio"
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/kilasos/kilasos/internal/appcatalog"
	"github.com/kilasos/kilasos/internal/audit"
	"github.com/kilasos/kilasos/internal/auth"
	kilaoslicense "github.com/kilasos/kilasos/internal/license"
	"github.com/kilasos/kilasos/internal/monitor"
	"github.com/kilasos/kilasos/internal/notify"
	kilaosrsync "github.com/kilasos/kilasos/internal/rsync"
	"github.com/kilasos/kilasos/internal/scheduler"
	"github.com/kilasos/kilasos/internal/storage"
	"github.com/kilasos/kilasos/internal/sysupdate"
	"github.com/kilasos/kilasos/internal/wol"
	"github.com/kilasos/kilasos/internal/zfssend"
)

type auditAdapter struct{ log *audit.Logger }

func (a auditAdapter) LogEnriched(e AuditEntry) {
	a.log.LogEnriched(audit.Entry{
		User: e.User, Action: e.Action, Detail: e.Detail, IP: e.IP, OK: e.OK,
	})
}

func newAuditAdapter(log *audit.Logger) EnrichedAuditLogger {
	return auditAdapter{log: log}
}

type ctxKey int

const (
	ctxRole     ctxKey = iota
	ctxUsername ctxKey = iota
	ctxLicense  ctxKey = iota
)

func licenseFromContext(ctx context.Context) *kilaoslicense.License {
	if lic, ok := ctx.Value(ctxLicense).(*kilaoslicense.License); ok {
		return lic
	}
	return nil
}

func licenseMiddleware(lic *kilaoslicense.License) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), ctxLicense, lic)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

type rateBucket struct {
	count  int
	resetAt time.Time
}

type loginRateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*rateBucket
}

func newLoginRateLimiter() *loginRateLimiter {
	rl := &loginRateLimiter{buckets: make(map[string]*rateBucket)}
	go func() {
		t := time.NewTicker(5 * time.Minute)
		for range t.C {
			rl.mu.Lock()
			now := time.Now()
			for k, b := range rl.buckets {
				if now.After(b.resetAt) {
					delete(rl.buckets, k)
				}
			}
			rl.mu.Unlock()
		}
	}()
	return rl
}

func (rl *loginRateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	b, ok := rl.buckets[ip]
	if !ok || time.Now().After(b.resetAt) {
		rl.buckets[ip] = &rateBucket{count: 1, resetAt: time.Now().Add(15 * time.Minute)}
		return true
	}
	b.count++
	return b.count <= 10
}

func (rl *loginRateLimiter) recordSuccess(ip string) {
	rl.mu.Lock()
	delete(rl.buckets, ip)
	rl.mu.Unlock()
}

//go:embed static
var staticFS embed.FS

func NewRouter(p storage.Provider, token string, mon *monitor.Monitor, hist *monitor.MetricsHistory, auditLog *audit.Logger, users *auth.UserStore, sched *scheduler.Scheduler, replicator zfssend.Replicator, apps *appcatalog.Manager, updater *sysupdate.Manager, webhookCfgPath, smtpCfgPath string, wolStore *wol.Store, rsyncMgr *kilaosrsync.Manager, tools *storage.ToolRegistry, lic *kilaoslicense.License, oidcMgr auth.OIDCAuthenticator, ldapMgr auth.LDAPAuthenticator, backuper storage.Backuper, cm storage.ComplianceManager) http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))

	loginRL := newLoginRateLimiter()
	// M403: separate per-IP rate limiter for public share-link downloads.
	// Reuses the loginRateLimiter token-bucket; share endpoint is unauthenticated
	// so this is the only abuse defence on it.
	shareRL := newLoginRateLimiter()

	// M376-M380: external auth managers (OIDC, LDAP) — injected from main
	apiKeys := auth.NewAPIKeyStore(users)
	pwPolicy := auth.NewPasswordPolicy()
	users.SetPasswordPolicy(pwPolicy)
	bruteForce := auth.NewBruteForceTracker()
	users.SetBruteForceTracker(bruteForce)

	// M391: initialise privacy mode from stored config
	if priv, err := cm.PrivacyMode(context.Background()); err == nil {
		auditLog.SetAnonymizeIP(priv.AnonymizeLogs)
	}

	// M389: WebAuthn manager (best-effort init; requires HTTPS for browser support)
	waMgr, _ := auth.NewWebAuthnManager(users, auth.WebAuthnConfig{
		RPDisplayName: "KilasOS",
		RPID:          "localhost",
		RPOrigin:      "http://localhost:8080",
	})

	r.Get("/", uiHandler)
	r.Get("/healthz", healthzHandler)
	// M406: PWA static assets (no auth required — PWA scrapers hit at origin root)
	r.Get("/manifest.json", pwaManifestHandler)
	r.Get("/sw.js", pwaServiceWorkerHandler)
	// M403: public share-link download (NO auth — token in URL is the credential).
	// Rate-limited per IP via shareRL. Validates expiry/max-uses server-side via
	// p.ResolveShareToken. Audit-logs every access (success and failure).
	r.Get("/share/{token}", publicShareHandler(p, auditLog, shareRL))
	r.Route("/api/v1", func(r chi.Router) {
		r.Get("/system/capabilities", CapabilitiesHandler(tools))
		r.Get("/auth/info", authInfoHandler(users))
		r.Post("/auth/login", loginHandler(token, users, auditLog, loginRL, bruteForce))
		// M390: login customization (public)
		r.Get("/auth/login-customization", loginCustomizationHandler())
		r.Post("/auth/register", registerHandler(users, auditLog))
		// OIDC public routes (login redirect + callback)
		r.Get("/auth/oidc/login", oidcLoginHandler(oidcMgr, loginRL))
		r.Get("/auth/oidc/callback", oidcCallbackHandler(oidcMgr, loginRL))
		// LDAP public route (alternate login)
		r.Post("/auth/ldap/login", ldapLoginHandler(ldapMgr, users, auditLog, loginRL))
		r.Group(func(r chi.Router) {
			r.Use(authMiddleware(token, users, apiKeys))
			r.Use(AuditMiddleware(newAuditAdapter(auditLog)))
			r.Use(licenseMiddleware(lic))
			r.Get("/license/status", func(w http.ResponseWriter, r *http.Request) {
				lic := licenseFromContext(r.Context())
				var tier string
				var daysRemaining int
				var isTrial bool
				var nodeCount int
				var status string
				if lic == nil {
					tier = "home"
					daysRemaining = -1
					isTrial = false
					nodeCount = 1
					status = "missing"
				} else {
					tier = lic.Tier
					daysRemaining = lic.DaysRemaining()
					isTrial = lic.IsTrial()
					nodeCount = lic.NodeCount
					if lic.IsExpired() {
						status = "expired"
					} else if lic.Tier == kilaoslicense.TierPro {
						status = "ok"
					} else {
						status = "ok"
					}
				}
				writeJSON(w, http.StatusOK, map[string]interface{}{
					"tier":          tier,
					"daysRemaining": daysRemaining,
					"isTrial":       isTrial,
					"nodeCount":     nodeCount,
					"status":        status,
				})
			})
			r.Post("/license/upload", licenseUploadHandler())
			r.Post("/license/clear", licenseClearHandler())
			r.Post("/auth/logout", logoutHandler(users, auditLog))
			// OIDC config (Pro)
			r.Group(func(r chi.Router) {
				r.Use(requireFeature(kilaoslicense.FeatureOIDC))
				r.Get("/auth/oidc/config", getOIDCConfigHandler(oidcMgr))
				r.Put("/auth/oidc/config", setOIDCConfigHandler(oidcMgr))
			})
			// LDAP config (Pro)
			r.Group(func(r chi.Router) {
				r.Use(requireFeature(kilaoslicense.FeatureLDAP))
				r.Get("/auth/ldap/config", getLDAPConfigHandler(ldapMgr))
				r.Put("/auth/ldap/config", setLDAPConfigHandler(ldapMgr))
				r.Post("/auth/ldap/test", ldapTestHandler(ldapMgr))
				r.Post("/auth/ldap/sync", ldapSyncHandler(ldapMgr))
			})
			// M382: SMB AD join
			r.Get("/smb/ad-status", smbADStatusHandler(p))
			r.Post("/smb/ad-join", smbADJoinHandler(p, auditLog))
			r.Post("/smb/ad-leave", smbADLeaveHandler(p, auditLog))
			// M383: session management
			r.Get("/auth/sessions", listSessionsHandler(users))
			r.Delete("/auth/sessions/{token}", revokeSessionHandler(users, auditLog))
			r.Post("/auth/sessions/revoke-all", revokeAllSessionsHandler(users, auditLog))
			// M384: API keys
			r.Get("/auth/api-keys", listAPIKeysHandler(apiKeys))
			r.Post("/auth/api-keys", createAPIKeyHandler(apiKeys, auditLog))
			r.Delete("/auth/api-keys/{id}", deleteAPIKeyHandler(apiKeys, auditLog))
			// M386: brute-force admin
			r.Get("/auth/brute-force", bruteForceStatsHandler(bruteForce))
			r.Post("/auth/brute-force/unban", bruteForceUnbanHandler(bruteForce, auditLog))
			r.Put("/auth/brute-force/thresholds", bruteForceThresholdsHandler(bruteForce, auditLog))
			// M387: password policy + change
			r.Get("/auth/password-policy", getPasswordPolicyHandler(pwPolicy))
			r.Put("/auth/password-policy", setPasswordPolicyHandler(pwPolicy, auditLog))
			r.Post("/auth/password/change", changePasswordHandler(users, pwPolicy, auditLog))
			// M388: TOTP backup codes
			r.Post("/totp/backup-codes/generate", generateBackupCodesHandler(users, pwPolicy, auditLog))
			r.Get("/totp/backup-codes/count", backupCodeCountHandler(users))
			// M389: WebAuthn
			r.Post("/auth/webauthn/register/begin", waBeginRegisterHandler(waMgr))
			r.Post("/auth/webauthn/register/finish", waFinishRegisterHandler(waMgr, auditLog))
			r.Post("/auth/webauthn/login/begin", waBeginLoginHandler(waMgr))
			r.Post("/auth/webauthn/login/finish", waFinishLoginHandler(waMgr, users, auditLog))
			r.Get("/auth/webauthn/credentials", waListCredsHandler(waMgr))
			r.Delete("/auth/webauthn/credentials/{id}", waDeleteCredHandler(waMgr, auditLog))
			// M390: login customization (admin set)
			r.Put("/auth/login-customization", setLoginCustomizationHandler(auditLog))
			r.Get("/totp/status", totpStatusHandler(users))
			r.Post("/totp/enroll", totpEnrollHandler(users, auditLog))
			r.Post("/totp/confirm", totpConfirmHandler(users, auditLog))
			r.Delete("/totp", totpDisableHandler(users, auditLog))
			r.Get("/users", usersHandler(users))
			r.Post("/users", createUserHandler(users, auditLog))
			r.Delete("/users/{username}", deleteUserHandler(users, auditLog))
			r.Patch("/users/{username}/role", setRoleHandler(users, auditLog))
			r.Get("/disks", disksHandler(p))
			r.Get("/arrays", arraysHandler(p))
			r.Post("/arrays", createArrayHandler(p))
			r.Get("/arrays/import", importCandidatesHandler(p))
			r.Post("/arrays/import", importPoolHandler(p))
			r.Post("/arrays/{name}/start", startArrayHandler(p))
			r.Post("/arrays/{name}/stop", stopArrayHandler(p))
			r.Delete("/arrays/{name}", deleteArrayHandler(p))
			r.Post("/arrays/{name}/replace", replaceDiskHandler(p))
			r.Get("/arrays/{name}/datasets", datasetsHandler(p))
			r.Post("/arrays/{name}/datasets", createDatasetHandler(p))
			r.Delete("/arrays/{name}/datasets/{dataset}", deleteDatasetHandler(p))
			r.Post("/arrays/{name}/datasets/{dataset}/load-key", loadEncryptionKeyHandler(p))
			r.Get("/shares", sharesHandler(p))
			r.Post("/shares", createShareHandler(p))
			r.Patch("/shares/{name}", updateShareHandler(p))
			r.Delete("/shares/{name}", deleteShareHandler(p))
			r.Get("/arrays/{name}/health", poolHealthHandler(p))
			r.Get("/arrays/{name}/quota", getQuotaHandler(p))
			r.Put("/arrays/{name}/quota", setQuotaHandler(p))
			r.Post("/arrays/{name}/scrub", startScrubHandler(p))
			r.Get("/arrays/{name}/snapshots", snapshotsHandler(p))
			r.Post("/arrays/{name}/snapshots", createSnapshotHandler(p))
			r.Delete("/arrays/{name}/snapshots/{snap}", deleteSnapshotHandler(p))
			r.Post("/arrays/{name}/snapshots/{snap}/rollback", rollbackSnapshotHandler(p))
			r.Get("/metrics", metricsHandler(p))
			r.Get("/metrics/history", metricsHistoryHandler(hist))
			r.Get("/metrics/prometheus", prometheusHandler(p, hist))
			r.Get("/metrics/arc", arcStatsHandler(p))
			r.Get("/sysinfo", sysinfoHandler(p))
			r.Get("/audit-log", auditLogHandler(auditLog))
			r.Get("/audit-log/export", auditLogExportHandler(auditLog))
			r.Get("/containers", containersHandler(p))
			r.Get("/containers/{id}/stats", containerStatsHandler(p))
			r.Get("/containers/{id}/logs", containerLogsHandler(p))
			r.Post("/containers/{id}/start", startContainerHandler(p, auditLog))
			r.Post("/containers/{id}/stop", stopContainerHandler(p, auditLog))
			r.Delete("/containers/{id}", removeContainerHandler(p, auditLog))
			r.Get("/alerts", alertsHandler(mon))
			r.Delete("/alerts/{id}", dismissAlertHandler(mon))
			r.Get("/system/monitor-config", monitorConfigHandler(mon))
			r.Put("/system/monitor-config", setMonitorConfigHandler(mon, auditLog))
			r.Get("/webhook-config", getWebhookConfigHandler(mon))
			r.Put("/webhook-config", putWebhookConfigHandler(mon, webhookCfgPath))
			r.Delete("/webhook-config", deleteWebhookConfigHandler(mon, webhookCfgPath))
			r.Post("/webhook-config/test", testWebhookHandler(mon))
			r.Get("/smtp-config", getSmtpConfigHandler(mon))
			r.Put("/smtp-config", putSmtpConfigHandler(mon, smtpCfgPath))
			r.Delete("/smtp-config", deleteSmtpConfigHandler(mon, smtpCfgPath))
			r.Post("/smtp-config/test", testSmtpHandler(mon))
			r.Get("/logs", logsHandler())
			r.Get("/files", filesListHandler())
			r.Delete("/files", filesDeleteHandler())
			r.Post("/files/mkdir", filesMkdirHandler())
			r.Post("/files/rename", filesRenameHandler())
			r.Post("/files/move", filesMoveHandler())
			r.Get("/network", networkHandler(p))
			r.Post("/network/{iface}/up", setIfaceHandler(p, true))
			r.Post("/network/{iface}/down", setIfaceHandler(p, false))
			r.Get("/wol", wolListHandler(wolStore))
			r.Post("/wol", wolAddHandler(wolStore, auditLog))
			r.Delete("/wol/{id}", wolDeleteHandler(wolStore, auditLog))
			r.Post("/wol/{id}/wake", wolWakeHandler(wolStore, auditLog))
			r.Get("/network/{iface}/config", getIfaceConfigHandler(p))
			r.Put("/network/{iface}/config", setIfaceConfigHandler(p))
			r.Get("/power", powerStatusHandler(p))
			r.Post("/power/shutdown", shutdownHandler(p, auditLog))
			r.Post("/power/reboot", rebootHandler(p, auditLog))
			r.Delete("/power/shutdown", cancelShutdownHandler(p))
			r.Post("/disks/{name}/spindown", spindownHandler(p))
			r.Get("/disks/{name}/smart-test", getSmartTestStatusHandler(p))
			r.Post("/disks/{name}/wipe", wipeDiskHandler(p))
			r.Post("/containers/pull", pullImageHandler(p))
			r.Get("/settings", settingsHandler(p))
			r.Patch("/settings", applySettingsHandler(p))
			r.Get("/backup", backupHandler(p))
			r.Post("/restore", restoreHandler(p))
			r.Get("/schedules", schedulesHandler(sched))
			r.Post("/schedules", createScheduleHandler(sched, replicator))
			r.Group(func(r chi.Router) {
				r.Use(requireFeature(kilaoslicense.FeatureZFSSend))
				r.Get("/remotes", remotesHandler(replicator))
				r.Post("/remotes", addRemoteHandler(replicator))
				r.Delete("/remotes/{id}", deleteRemoteHandler(replicator))
				r.Post("/arrays/{name}/send", startSendHandler(replicator))
				r.Get("/jobs/{id}", jobHandler(replicator))
				r.Get("/jobs", allJobsHandler(replicator))
			})
			r.Get("/updates", updatesInfoHandler(updater))
			r.Post("/updates/check", startCheckHandler(updater))
			r.Post("/updates/apply", startApplyHandler(updater))
			r.Get("/update-jobs/{id}", updateJobHandler(updater))
			r.Get("/ssh-keys", sshKeysHandler(p))
			r.Post("/ssh-keys", addSSHKeyHandler(p))
			r.Delete("/ssh-keys", deleteSSHKeyHandler(p))
			r.Get("/catalog", catalogHandler())
			r.Get("/apps", appsHandler(apps))
			r.Post("/apps", deployAppHandler(apps, auditLog))
			r.Post("/apps/{name}/start", appActionHandler(apps, "start"))
			r.Post("/apps/{name}/stop", appActionHandler(apps, "stop"))
			r.Delete("/apps/{name}", removeAppHandler(apps, auditLog))
			r.Get("/app-jobs/{id}", appJobHandler(apps))
			r.Get("/apps/{id}/template", appTemplateHandler())
			r.Get("/app-stacks", appStacksHandler(p))
			r.Post("/app-stacks", createAppStackHandler(p))
			r.Delete("/app-stacks/{name}", deleteAppStackHandler(p))
			r.Get("/app-update/{name}", appUpdateAvailableHandler(p))
			r.Post("/app-update/{name}", appUpdateHandler(p))
			r.Post("/app-rollback/{name}", appRollbackHandler(p))
			r.Get("/app-health/{name}", appHealthStatusHandler(p))
			r.Get("/app-config/{name}", appExportConfigHandler(p))
			r.Post("/app-config/{name}", appImportConfigHandler(p))
			r.Post("/app-custom", appCustomTemplateHandler(p))
			r.Get("/app-favorites", appFavoritesHandler(p))
			r.Put("/app-favorites/{name}", appSetFavoriteHandler(p))
			r.Get("/app-search", appSearchHandler(p))
			r.Get("/rsync-jobs", rsyncJobsHandler(rsyncMgr))
			r.Post("/rsync-jobs", createRsyncJobHandler(rsyncMgr))
			r.Delete("/rsync-jobs/{id}", deleteRsyncJobHandler(rsyncMgr))
			r.Patch("/rsync-jobs/{id}", patchRsyncJobHandler(rsyncMgr))
			r.Post("/rsync-jobs/{id}/run", runRsyncJobHandler(rsyncMgr))
			r.Get("/rsync-jobs/{id}/status", rsyncJobStatusHandler(rsyncMgr))
			r.Get("/disk-io", diskIOHandler(p))
			r.Get("/processes", processesHandler(p))
			r.Get("/docker-volumes", dockerVolumesHandler(p))
			r.Delete("/docker-volumes/{name}", removeDockerVolumeHandler(p, auditLog))
			r.Post("/net-diag", netDiagHandler(p))
			r.Get("/arrays/{name}/datasets/{dataset}/props", getDatasetPropsHandler(p))
			r.Patch("/arrays/{name}/datasets/{dataset}/props", setDatasetPropsHandler(p))
			r.Get("/disks/{name}/smart-detail", smartDetailHandler(p))
			r.Get("/logs/stream", logsStreamHandler())
			r.Get("/docker-images", dockerImagesHandler(p))
			r.Delete("/docker-images/{id}", removeDockerImageHandler(p, auditLog))
			r.Get("/pool-io", poolIOHandler(p))
			r.Get("/containers/{id}/inspect", containerInspectHandler(p))
			r.Get("/arrays/{name}/events", poolEventsHandler(p))
			r.Post("/arrays/{name}/resilver", resilverHandler(p))
			r.Post("/arrays/{name}/expand", expandPoolHandler(p))
			r.Post("/arrays/{name}/snapshots/{snap}/clone", cloneSnapshotHandler(p))
			r.Get("/smb-connections", smbConnectionsHandler(p))
			r.Get("/journal/search", journalSearchHandler(p))
			r.Get("/arrays/{name}/pool-props", getPoolPropsHandler(p))
			r.Patch("/arrays/{name}/pool-props", setPoolPropsHandler(p))
			r.Post("/network/scan", scanServicesHandler(p))
			r.Get("/system/packages", pendingUpdatesHandler(p))
			r.Get("/system/users", systemUsersHandler(p))
			r.Post("/system/users", addSystemUserHandler(p))
			r.Delete("/system/users/{name}", deleteSystemUserHandler(p))
			r.Get("/system/crons", cronJobsHandler(p))
			r.Get("/system/cpu-freq", cpuFreqHandler(p))
			r.Get("/system/arp", arpTableHandler(p))
			r.Get("/system/firewall", firewallRulesHandler(p))
			r.Get("/system/share-stats", shareStatsHandler(p))
			r.Post("/disks/{name}/benchmark", benchmarkDiskHandler(p))
			r.Get("/system/dns", getDNSConfigHandler(p))
			r.Put("/system/dns", setDNSConfigHandler(p))
			r.Get("/system/hosts", getHostsHandler(p))
			r.Post("/system/hosts", addHostHandler(p))
			r.Delete("/system/hosts", deleteHostHandler(p))
			r.Get("/system/services", listServicesHandler(p))
			r.Post("/system/services/{name}/{action}", serviceActionHandler(p))
			r.Get("/system/mem", memDetailHandler(p))
			r.Get("/system/samba-global", getSambaGlobalHandler(p))
			r.Put("/system/samba-global", setSambaGlobalHandler(p))
			r.Get("/system/iface-stats", ifaceStatsHandler(p))
			r.Post("/system/tls-cert", tlsCertHandler(p))
			r.Get("/system/last-logins", lastLoginsHandler(p))
			r.Get("/system/scrub-schedules", scrubSchedulesHandler(p))
			r.Put("/system/scrub-schedules/{pool}", setScrubScheduleHandler(p))
			r.Post("/system/exec", execHandler(p))
			r.Post("/files/search", fileSearchHandler(p))
			r.Get("/arrays/{name}/snapshots/{snapA}/diff", snapshotDiffHandler(p))
			r.Post("/containers/{id}/exec", containerExecHandler(p, auditLog))
			r.Get("/system/smtp", getSMTPHandler(p))
			r.Put("/system/smtp", setSMTPHandler(p))
			r.Post("/system/smtp/test", testSMTPHandler(p))
			r.Get("/system/ups", upsStatusHandler(p))
			r.Put("/network/interfaces/{name}/state", setIfaceStateHandler(p))
			r.Get("/system/tailscale", tailscaleStatusHandler(p))
			r.Get("/system/bootlog", bootLogHandler())
			r.Patch("/containers/{id}/limits", updateContainerLimitsHandler(p))
			r.Patch("/shares/{name}/permissions", setSharePermsHandler(p))
			r.Get("/nfs/exports", nfsExportsHandler(p))
			r.Post("/nfs/exports", addNFSExportHandler(p))
			r.Post("/nfs/exports/delete", deleteNFSExportHandler(p))
			r.Get("/system/alert-rules", getAlertRulesHandler(p))
			r.Put("/system/alert-rules", setAlertRulesHandler(p))
			r.Get("/disks/{name}/smart-history", smartHistoryHandler(p))
			r.Get("/arrays/{name}/user-quotas", userQuotasHandler(p))
			r.Put("/arrays/{name}/user-quotas/{user}", setUserQuotaHandler(p))
			r.Post("/arrays/{name}/change-key", changeEncKeyHandler(p))
			r.Get("/system/journal/export", journalExportHandler(p))
			r.Get("/docker/daemon-config", dockerDaemonConfigHandler(p))
			r.Put("/docker/daemon-config", setDockerDaemonConfigHandler(p))
			r.Post("/processes/{pid}/kill", killProcessHandler(p))
			r.Get("/system/entropy", entropyHandler(p))
			r.Get("/disks/{name}/apm", getDiskAPMHandler(p))
			r.Put("/disks/{name}/apm", setDiskAPMHandler(p))
			r.Get("/network/resolve", resolveHostnameHandler(p))
			r.Get("/disks/{name}/spin-state", diskSpinStateHandler(p))
			r.Post("/network/ping", pingHostHandler(p))
			r.Get("/compose", composeProjectsHandler(p))
			r.Post("/compose/action", composeActionHandler(p))
			r.Get("/system/fans", fanSpeedsHandler(p))
			r.Get("/network/routes", routeTableHandler(p))
			r.Get("/system/time", timeStatusHandler(p))
			r.Put("/system/hostname", setHostnameHandler(p))
			r.Get("/system/hostname", getHostnameHandler(p))
			r.Get("/network/wireguard", wireguardStatusHandler(p))
			r.Get("/storage/mdraid", mdRaidStatusHandler(p))
			r.Get("/smb/sessions", smbSessionsHandler(p))
			r.Get("/system/temperatures", cpuTemperaturesHandler(p))
			r.Get("/system/iptables", ipTablesHandler(p))
			r.Post("/disks/{name}/smart-test", triggerSMARTTestHandler(p))
			r.Post("/docker/prune", dockerPruneHandler(p, auditLog))
			r.Get("/system/usb", usbDevicesHandler(p))
			r.Get("/system/pci", pciDevicesHandler(p))
			r.Get("/system/loadavg", loadAveragesHandler(p))
			r.Get("/system/swap", swapInfoHandler(p))
			r.Get("/system/connections", connectionSummaryHandler(p))
			r.Get("/containers/{id}/env", containerEnvHandler(p))
			r.Get("/storage/partitions", diskPartitionsHandler(p))
			r.Get("/system/sysctl", getSysctlHandler(p))
			r.Put("/system/sysctl", setSysctlHandler(p))
			r.Post("/arrays/{name}/trim", zfsPoolTrimHandler(p))
			r.Get("/system/who", whoLoggedInHandler(p))
			r.Get("/files/acl", getACLHandler(p))
			r.Put("/files/acl", setACLHandler(p))
			r.Patch("/containers/{id}/restart-policy", setRestartPolicyHandler(p))
			r.Get("/system/fail2ban", fail2banHandler(p))
			r.Get("/system/server-certificate", serverCertHandler(p))
			r.Post("/system/server-certificate/upload", uploadServerCertHandler(p, auditLog))
			r.Post("/system/server-certificate/generate", generateServerCertHandler(p, auditLog))
			r.Post("/arrays/{name}/datasets/{ds}/destroy", destroyDatasetHandler(p))
			r.Get("/system/motd", getMOTDHandler(p))
			r.Put("/system/motd", setMOTDHandler(p))
			r.Get("/system/crontab", getCronTabHandler(p))
			r.Put("/system/crontab", setCronTabHandler(p))
			r.Get("/network/netstat", netstatHandler(p))
			r.Post("/network/test-port", testPortHandler(p))
			r.Get("/zfs/snapshots/{name}/holds", zfsHoldsHandler(p))
			r.Post("/zfs/snapshots/{name}/holds", addZFSHoldHandler(p))
			r.Delete("/zfs/snapshots/{name}/holds/{tag}", releaseZFSHoldHandler(p))
			r.Get("/system/failed-units", failedUnitsHandler(p))
			r.Get("/storage/nfs-mounts", nfsMountsHandler(p))
			r.Get("/system/readonly-mounts", readonlyMountsHandler(p))
			r.Post("/zfs/rename", zfsRenameHandler(p))
			r.Get("/system/logrotate", logRotateHandler(p))
			r.Get("/containers/{id}/health", containerHealthHandler(p))
			r.Get("/network/mdns", mdnsServicesHandler(p))
			r.Get("/system/kernel-param", kernelParamHandler(p))
			r.Post("/containers/{id}/pause", pauseContainerHandler(p))
			r.Post("/containers/{id}/unpause", unpauseContainerHandler(p))
			r.Post("/containers/{id}/restart", restartContainerHandler(p, auditLog))
			r.Get("/zfs/bookmarks", zfsBookmarksHandler(p))
			r.Post("/zfs/bookmarks", createZFSBookmarkHandler(p))
			r.Get("/system/runlevel", runlevelHandler(p))
			r.Get("/system/uptime", uptimeHandler(p))
			r.Get("/network/netmasks", netmaskHandler(p))
			r.Get("/system/battery", batteryHandler(p))
			r.Get("/system/locale", localeHandler(p))
			r.Put("/system/timezone", setTimezoneHandler(p))
			r.Get("/system/timezones", listTimezonesHandler(p))
			r.Get("/system/os-release", osReleaseHandler(p))
			r.Get("/system/kernel-modules", kernelModulesHandler(p))
			r.Get("/network/ip-rules", ipRulesHandler(p))
			r.Get("/network/interfaces/{name}/stats", nicStatsHandler(p))
			r.Put("/network/interfaces/{name}/mtu", setMTUHandler(p))
			r.Get("/system/systemd-units/{name}", systemdUnitDetailHandler(p))
			r.Post("/system/systemd-units/{name}/start", startSystemdHandler(p))
			r.Post("/system/systemd-units/{name}/stop", stopSystemdHandler(p))
			r.Post("/system/systemd-units/{name}/enable", enableSystemdHandler(p))
			r.Post("/system/systemd-units/{name}/disable", disableSystemdHandler(p))
			r.Get("/system/host-info", hostHardwareHandler(p))
			r.Get("/system/journal-units", journalUnitsHandler(p))
			r.Get("/system/journal-units/{unit}", journalForUnitHandler(p))
			r.Get("/zfs/features", zfsFeaturesHandler(p))
			r.Get("/system/ip6tables", ip6tablesHandler(p))
			r.Get("/system/conntrack-count", conntrackCountHandler(p))
			r.Get("/system/dmesg", dmesgHandler(p))
			r.Get("/system/cmdline", cmdlineHandler(p))
			r.Get("/network/interfaces/{name}/offloads", nicOffloadsHandler(p))
			r.Get("/system/cpu-detail", cpuDetailHandler(p))
			r.Get("/system/mounts", listMountsHandler(p))
			r.Get("/system/conntrack", conntrackHandler(p))
			r.Get("/system/iowait", iowaitHandler(p))
			r.Get("/zfs/importable", zfsImportableHandler(p))
			r.Get("/system/installed-kernels", installedKernelsHandler(p))
			r.Get("/system/current-kernel", currentKernelHandler(p))
			r.Post("/network/speedtest", speedtestHandler(p))
			r.Get("/disks/temperatures", diskTempsHandler(p))
			r.Get("/system/build-info", buildInfoHandler(p))
			r.Get("/system/vms", vmsHandler(p))
			r.Get("/system/sudoers", sudoersHandler(p))
			r.Get("/system/sshd-config", sshdConfigHandler(p))
			r.Get("/system/recommendations", recommendationsHandler(p))
			r.Get("/system/max-open-files", maxOpenFilesHandler(p))
			r.Get("/network/tcp-congestion", tcpCongestionHandler(p))
			r.Get("/disks/{name}/serial", diskSerialHandler(p))
			r.Get("/network/interface-features", interfaceFeaturesHandler(p))
			r.Get("/zfs/datasets/property", getDatasetPropertyHandler(p))
			r.Put("/zfs/datasets/property", setDatasetPropertyHandler(p))
			r.Get("/system/open-ports", openPortsHandler(p))
			r.Get("/system/oom-events", oomEventsHandler(p))
			r.Get("/system/zram", zramHandler(p))
			r.Get("/system/ntp-servers", getNTPServersHandler(p))
			r.Put("/system/ntp-servers", setNTPServersHandler(p))
			r.Get("/system/time-sync", timeSyncStatusHandler(p))
			r.Get("/network/ipv6", ipv6StatusHandler(p))
			r.Get("/arrays/{name}/scrub-progress", scrubProgressHandler(p))
			r.Get("/system/last-logins", listLoginsHandler(p))
			r.Get("/system/timezone-offset", tzOffsetHandler(p))
			r.Get("/system/boots", systemBootsHandler(p))
			r.Get("/disks/{name}/smart-attributes", smartAttributesHandler(p))
			r.Get("/arrays/{name}/dedup-stats", dedupStatsHandler(p))
			r.Get("/disks/{name}/nvme-stats", nvmeStatsHandler(p))
			r.Get("/system/gpus", gpusHandler(p))
			r.Post("/network/arp-flush", arpFlushHandler(p))
			r.Get("/system/ecc-errors", eccErrorsHandler(p))
			r.Get("/system/mem-fragmentation", memFragHandler(p))
			r.Get("/network/top-bandwidth", topBandwidthHandler(p))
			r.Get("/system/swap-pressure", swapPressureHandler(p))

			// ── Backup & Cloud Sync (M301-M315) ─────────────────────────────
			r.Group(func(r chi.Router) {
				r.Use(requireFeature(kilaoslicense.FeatureBackup))
				r.Get("/backup/status", backupStatusHandler(backuper))
				r.Post("/backup/borg/init", borgInitHandler(backuper))
				r.Post("/backup/borg/create", borgCreateBackupHandler(backuper, nil))
				r.Get("/backup/borg/archives", borgListArchivesHandler(backuper))
				r.Delete("/backup/borg/archives/{repo}/{archive}", borgDeleteArchiveHandler(backuper))
				r.Post("/backup/borg/prune", borgPruneHandler(backuper))
				r.Post("/backup/borg/restore", borgRestoreHandler(backuper))
				r.Post("/backup/borg/verify", borgVerifyHandler(backuper))
				r.Post("/backup/restic/init", resticInitHandler(backuper))
				r.Post("/backup/restic/backup", resticCreateBackupHandler(backuper))
				r.Get("/backup/restic/snapshots", resticListSnapshotsHandler(backuper))
				r.Delete("/backup/restic/snapshots/{repo}/{snapshot}", resticDeleteSnapshotHandler(backuper))
				r.Post("/backup/restic/restore", resticRestoreHandler(backuper))
				r.Post("/backup/restic/verify", resticVerifyHandler(backuper))
				r.Post("/backup/rclone/remote", rcloneRemoteAddHandler(backuper))
				r.Delete("/backup/rclone/remote/{name}", rcloneRemoteRemoveHandler(backuper))
				r.Get("/backup/rclone/remotes", rcloneRemoteListHandler(backuper))
				r.Post("/backup/rclone/sync", rcloneSyncHandler(backuper))
				r.Get("/backup/jobs", backupJobsHandler(backuper))
				r.Post("/backup/jobs", createBackupJobHandler(backuper))
				r.Patch("/backup/jobs/{id}", updateBackupJobHandler(backuper))
				r.Delete("/backup/jobs/{id}", deleteBackupJobHandler(backuper))
				r.Post("/backup/jobs/{id}/run", runBackupJobHandler(backuper))
				r.Get("/backup/jobs/{id}/runs", backupJobRunsHandler(backuper))
				r.Get("/backup/jobs/{id}/runs/{runID}", backupJobRunHandler(backuper))
				r.Get("/backup/jobs/{id}/runs/{runID}/log", backupJobRunLogHandler(backuper))
				r.Get("/backup/restore-points", restorePointsHandler(backuper))
				r.Get("/backup/cloud-cost", cloudCostEstimateHandler(backuper))
			})

			// ╔══ BATCH ANCHOR ZONES (auth route group) ══╗
			// ║ Each batch appends ITS routes in its zone below. Do not interleave. ║
			// ╚══════════════════════════════════════════╝

			// ── BATCH-B (M316-M330): Monitoring & Alerting routes ──
			r.Get("/metrics/prom", prometheusMetricsHandler(p))
			r.Get("/healthchecks/ping", healthchecksPingHandler(p))
			r.Post("/notify", notifyHandler(p, auditLog))
			r.Get("/notification-channels", notificationChannelsHandler(p))
			r.Post("/notification-channels", createNotificationChannelHandler(p, auditLog))
			r.Put("/notification-channels/{name}", updateNotificationChannelHandler(p, auditLog))
			r.Delete("/notification-channels/{name}", deleteNotificationChannelHandler(p, auditLog))
			r.Get("/alert-rules", monitorAlertRulesHandler(p))
			r.Post("/alert-rules", createMonitorAlertRuleHandler(p, auditLog))
			r.Put("/alert-rules/{name}", updateMonitorAlertRuleHandler(p, auditLog))
			r.Delete("/alert-rules/{name}", deleteMonitorAlertRuleHandler(p, auditLog))
			r.Get("/alert-events", alertEventsHandler(p))
			r.Post("/alert-events/{id}/ack", acknowledgeAlertHandler(p))
			r.Post("/alert-rules/{name}/silence", silenceAlertHandler(p))
			r.Get("/anomaly", anomalyScoreHandler(p))
			r.Post("/notification-channels/{name}/test", testNotificationHandler(p))

			// ── BATCH-C (M331-M345): Reverse Proxy & Tunnels routes ──
			r.Get("/caddy/sites", caddySitesHandler(p))
			r.Post("/caddy/sites", caddySiteCreateHandler(p, auditLog))
			r.Put("/caddy/sites/{name}", caddySiteUpdateHandler(p, auditLog))
			r.Delete("/caddy/sites/{name}", caddySiteDeleteHandler(p, auditLog))
			r.Post("/caddy/reload", caddyReloadHandler(p, auditLog))
			r.Get("/cf-tunnel/status", cfTunnelStatusHandler(p))
			r.Post("/cf-tunnel/start", cfTunnelStartHandler(p, auditLog))
			r.Post("/cf-tunnel/stop", cfTunnelStopHandler(p, auditLog))
			r.Post("/tailscale/funnel", tailscaleFunnelHandler(p, auditLog))
			r.Get("/wireguard/peers", wgPeersHandler(p))
			r.Post("/wireguard/peers", wgAddPeerHandler(p, auditLog))
			r.Delete("/wireguard/peers/{pubkey}", wgRemovePeerHandler(p, auditLog))
			r.Get("/wireguard/config", wgConfigHandler(p))
			r.Get("/wireguard/peers/{pubkey}/config", wgClientConfigHandler(p))
			r.Get("/wireguard/peers/{pubkey}/qrcode", wgQRCodeHandler(p))
			r.Get("/upnp/status", upnpStatusHandler(p))
			r.Post("/upnp/forward", upnpForwardHandler(p, auditLog))
			r.Delete("/upnp/forward", upnpRemoveHandler(p, auditLog))
			r.Post("/ddns/update", ddnsUpdateHandler(p, auditLog))
			r.Get("/dnsmasq/config", dnsmasqConfigHandler(p))
			r.Put("/dnsmasq/config", dnsmasqConfigSetHandler(p, auditLog))
			r.Get("/dnsmasq/dhcp", dhcpConfigHandler(p))
			r.Put("/dnsmasq/dhcp", dhcpConfigSetHandler(p, auditLog))

			// ── BATCH-E (M361-M375): Storage Power-User routes ──
			r.Get("/storage/btrfs/subvolumes", btrfsSubvolumesHandler(p))
			r.Post("/storage/btrfs/subvolumes", createBtrfsSubvolHandler(p))
			r.Delete("/storage/btrfs/subvolumes", deleteBtrfsSubvolHandler(p))
			r.Get("/storage/btrfs/snapshots", btrfsSnapshotsHandler(p))
			r.Post("/storage/btrfs/snapshots", createBtrfsSnapshotHandler(p))
			r.Delete("/storage/btrfs/snapshots", deleteBtrfsSnapshotHandler(p))
			r.Post("/storage/btrfs/snapshots/restore", btrfsRestoreSnapshotHandler(p, auditLog))
			r.Post("/storage/btrfs/scrub", btrfsScrubHandler(p))
			r.Post("/storage/btrfs/balance", btrfsBalanceHandler(p))
			r.Get("/storage/zfs/l2arc", zfsL2ARCStatusHandler(p))
			r.Post("/storage/zfs/l2arc", zfsL2ARCAddHandler(p, auditLog))
			r.Delete("/storage/zfs/l2arc/{pool}", zfsL2ARCRemoveHandler(p, auditLog))
			r.Get("/storage/zfs/slog", zfsSLOGStatusHandler(p))
			r.Post("/storage/zfs/slog", zfsSLOGAddHandler(p, auditLog))
			r.Delete("/storage/zfs/slog/{pool}", zfsSLOGRemoveHandler(p, auditLog))
			r.Get("/storage/zfs/special-vdev", zfsSpecialVdevStatusHandler(p))
			r.Post("/storage/zfs/special-vdev", zfsSpecialVdevAddHandler(p, auditLog))
			r.Get("/storage/zfs/ddt", zfsDDTProjectionHandler(p))
			r.Get("/storage/zfs/ddt/status", ddtProjectionStatusHandler(p))
			r.Get("/storage/zfs/compression", zfsCompressionRatiosHandler(p))
			r.Get("/storage/lifecycle/policies", lifecyclePoliciesHandler(p))
			r.Put("/storage/lifecycle/policies", setLifecyclePolicyHandler(p))
			r.Delete("/storage/lifecycle/policies/{name}", deleteLifecyclePolicyHandler(p))
			r.Get("/storage/tier-policy", storageTierPolicyHandler(p))
			r.Put("/storage/tier-policy", setStorageTierPolicyHandler(p))
			r.Get("/storage/dedup/status", dedupScannerStatusHandler(p))
			r.Post("/storage/dedup/scan", startDedupScanHandler(p))
			r.Get("/storage/burnin/status", diskBurnInStatusHandler(p))
			r.Post("/storage/burnin/start", startDiskBurnInHandler(p, auditLog))
			r.Get("/storage/wizards/replacement/{id}", replacementWizardStateHandler(p))
			r.Post("/storage/wizards/replacement/{id}", replacementWizardStepHandler(p, auditLog))
			r.Get("/storage/wizards/expansion/{id}", poolExpansionWizardStateHandler(p))
			r.Post("/storage/wizards/expansion/{id}", poolExpansionStepHandler(p, auditLog))

			// ── BATCH-G (M391-M405): Web File Manager routes ──
			r.Get("/files/list", fileListHandler(p, auditLog))
			r.Get("/files/tree", fileTreeHandler(p, auditLog))
			r.Post("/files/upload", fileUploadHandler(p, auditLog))
			r.Post("/files/folder-zip", folderZipHandler(p, auditLog))
			r.Get("/files/download", fileDownloadHandler(p, auditLog))
			r.Get("/files/preview", filePreviewHandler(p, auditLog))
			r.Post("/files/rename", fileRenameHandler(p, auditLog))
			r.Post("/files/copy", fileCopyHandler(p, auditLog))
			r.Post("/files/delete", fileDeleteHandler(p, auditLog))
			r.Get("/files/read", fileReadHandler(p, auditLog))
			r.Get("/trash/list", trashListHandler(p, auditLog))
			r.Post("/trash/restore", trashRestoreHandler(p, auditLog))
			r.Post("/trash/empty", trashEmptyHandler(p, auditLog))
			r.Post("/files/chmod", fileChmodHandler(p, auditLog))
			r.Post("/files/chown", fileChownHandler(p, auditLog))
			r.Get("/share", listSharesHandler(p, auditLog))
			r.Post("/share", createShareLinkHandler(p, auditLog))
			r.Delete("/share/{id}", revokeShareHandler(p, auditLog))
			r.Get("/share/{id}", getShareHandler(p, auditLog))
			r.Post("/files/bulk-delete", bulkDeleteHandler(p, auditLog))
			r.Post("/files/bulk-move", bulkMoveHandler(p, auditLog))

			// ── BATCH-H (M406-M420): Mobile & UX Polish routes (minimal) ──

			// ── BATCH-I (M421-M435): Observability & Logs routes ──
			r.Get("/syslog-forwarding", syslogForwardingConfigHandler(p))
			r.Put("/syslog-forwarding", setSyslogForwardingHandler(p))
			r.Get("/audit/retention", auditRetentionHandler(p))
			r.Put("/audit/retention", setAuditRetentionHandler(p, auditLog))
			r.Post("/audit/rotate", rotateAuditLogsHandler(p))
			r.Post("/audit/search", searchAuditLogsHandler(p))
			r.Get("/logs/aggregate", aggregateSystemLogsHandler(p))
			r.Post("/logs/container/search", searchContainerLogsHandler(p))
			r.Get("/logs/download", logDownloadHandler(p))
			r.Get("/logs/alert-rules", logAlertRulesHandler(p))
			r.Post("/logs/alert-rules", createLogAlertRuleHandler(p))
			r.Delete("/logs/alert-rules/{name}", deleteLogAlertRuleHandler(p))
			r.Get("/logs/stats", logStatsHandler(p))
			r.Get("/logs/restart-loops", containerRestartLoopsHandler(p))
			r.Get("/loki/config", lokiConfigHandler(p))
			r.Put("/loki/config", setLokiConfigHandler(p))
			r.Post("/logs/export-s3", exportLogsToS3Handler(p))

			r.Get("/security/ssh/audit", sshKeyAuditHandler(p))
			r.Put("/security/ssh/audit/{fingerprint}", markSSHKeyUsedHandler(p))
			r.Get("/security/sudo/audit", sudoAuditHandler(p))
			r.Get("/security/failed-logins", failedLoginsHandler(p))
			r.Group(func(r chi.Router) {
				r.Use(requireFeature(kilaoslicense.FeatureTrivy))
				r.Post("/security/trivy/scan", trivyScanHandler(p))
				r.Get("/security/trivy/{image}/results", trivyResultsHandler(p))
			})
			r.Group(func(r chi.Router) {
				r.Use(requireFeature(kilaoslicense.FeatureLynis))
				r.Post("/security/lynis/run", runLynisHandler(p))
				r.Get("/security/lynis/status", lynisStatusHandler(p))
				r.Get("/security/lynis/report", lynisReportHandler(p))
			})
			r.Group(func(r chi.Router) {
				r.Use(requireFeature(kilaoslicense.FeatureAppArmor))
				r.Get("/security/apparmor", apparmorStatusHandler(p))
				r.Post("/security/apparmor/enforce", setAppArmorProfileHandler(p, auditLog))
			})
			r.Group(func(r chi.Router) {
				r.Use(requireFeature(kilaoslicense.FeatureSELinux))
				r.Get("/security/selinux", selinuxStatusHandler(p))
			})
			r.Group(func(r chi.Router) {
				r.Use(requireFeature(kilaoslicense.FeatureUSBAllow))
				r.Get("/security/usb/allowlist", usbAllowlistHandler(p))
				r.Put("/security/usb/allowlist", setUSBAllowlistHandler(p, auditLog))
				r.Post("/security/usb/block", blockUSBHandler(p))
			})
			r.Group(func(r chi.Router) {
				r.Use(requireFeature(kilaoslicense.FeatureCompliance))
				r.Get("/security/compliance/report", complianceReportHandler(cm))
			})
			r.Group(func(r chi.Router) {
				r.Use(requireFeature(kilaoslicense.FeatureGDPR))
				r.Get("/security/gdpr/export", gdprExportHandler(cm, auditLog))
				r.Delete("/security/gdpr/user/{username}", gdprDeleteHandler(cm, auditLog))
			})
			r.Group(func(r chi.Router) {
				r.Use(requireFeature(kilaoslicense.FeaturePrivacy))
				r.Get("/security/privacy", privacyModeHandler(cm))
				r.Put("/security/privacy", setPrivacyModeHandler(cm, auditLog))
			})
			r.Get("/security/integrity", integrityCheckHandler(p))
		})
	})

	return r
}

func authMiddleware(staticToken string, users *auth.UserStore, apiKeys *auth.APIKeyStore) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			// Also accept token via query param (for EventSource/SSE)
			if tok == "" {
				tok = r.URL.Query().Get("_token")
			}

			// No auth configured and no users: open access as admin
			if staticToken == "" && users.Count() == 0 {
				ctx := context.WithValue(r.Context(), ctxRole, auth.RoleAdmin)
				ctx = context.WithValue(ctx, ctxUsername, "admin")
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			// Legacy static token
			if staticToken != "" && tok == staticToken {
				ctx := context.WithValue(r.Context(), ctxRole, auth.RoleAdmin)
				ctx = context.WithValue(ctx, ctxUsername, "admin")
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			// UserStore session token
			if username, role, ok := users.ValidateToken(tok); ok {
				if role == auth.RoleReadonly &&
					r.Method != http.MethodGet &&
					r.Method != http.MethodHead &&
					r.Method != http.MethodOptions {
					writeJSON(w, http.StatusForbidden, map[string]string{"error": "read-only access"})
					return
				}
				ctx := context.WithValue(r.Context(), ctxRole, role)
				ctx = context.WithValue(ctx, ctxUsername, username)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			// M384: API key (looks like ID.SECRET, where ID is 8 hex chars)
			if apiKeys != nil && len(tok) > 16 && tok[8:9] == "." {
				if username, role, ok := apiKeys.Validate(tok); ok {
					if role == auth.RoleReadonly &&
						r.Method != http.MethodGet &&
						r.Method != http.MethodHead &&
						r.Method != http.MethodOptions {
						writeJSON(w, http.StatusForbidden, map[string]string{"error": "read-only access"})
						return
					}
					ctx := context.WithValue(r.Context(), ctxRole, role)
					ctx = context.WithValue(ctx, ctxUsername, username)
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
			}

			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		})
	}
}

func requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	role, _ := r.Context().Value(ctxRole).(string)
	if role != auth.RoleAdmin {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "admin required"})
		return false
	}
	return true
}

func authInfoHandler(users *auth.UserStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]bool{"setup_required": users.Count() == 0})
	}
}

func loginHandler(staticToken string, users *auth.UserStore, auditLog *audit.Logger, rl *loginRateLimiter, bf *auth.BruteForceTracker) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr
		if !rl.allow(ip) {
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many failed attempts — try again later"})
			return
		}
		// M386: brute-force ban check
		if bf != nil && bf.IsBanned(ip) {
			auditLog.LogEnriched(audit.Entry{Action: "login-blocked", Detail: "ip-banned", IP: ip, OK: false})
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "this IP is temporarily banned due to too many failures"})
			return
		}
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
			TOTPCode string `json:"totp_code"`
			Token    string `json:"token"` // legacy
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}

		// Legacy static token login
		if req.Token != "" {
			if staticToken == "" || req.Token != staticToken {
				auditLog.Log("admin", "login", "legacy token", ip, false)
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid token"})
				return
			}
			auditLog.Log("admin", "login", "legacy token", ip, true)
			writeJSON(w, http.StatusOK, map[string]interface{}{
				"token": req.Token, "username": "admin", "role": auth.RoleAdmin,
			})
			return
		}

		// No auth configured and no users
		if staticToken == "" && users.Count() == 0 {
			writeJSON(w, http.StatusOK, map[string]interface{}{
				"token": "", "username": "admin", "role": auth.RoleAdmin,
			})
			return
		}

		tok, role, requiresTOTP, err := users.Login(req.Username, req.Password, req.TOTPCode)
		if requiresTOTP {
			writeJSON(w, http.StatusOK, map[string]interface{}{"requires_totp": true})
			return
		}
		if err != nil {
			// M386: track failure, ban after threshold
			banned := false
			attemptsLeft := 5
			if bf != nil {
				banned, attemptsLeft = bf.RecordFailure(ip)
			}
			auditLog.LogEnriched(audit.Entry{User: req.Username, Action: "login", Detail: err.Error(), IP: ip, OK: false})
			if banned {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "too many failures — IP banned"})
				return
			}
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials", "attempts_left": fmt.Sprintf("%d", attemptsLeft)})
			return
		}
		rl.recordSuccess(ip)
		if bf != nil {
			bf.RecordSuccess(ip)
		}
		auditLog.Log(req.Username, "login", role, ip, true)
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"token": tok, "username": req.Username, "role": role,
		})
	}
}

func registerHandler(users *auth.UserStore, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if users.Count() > 0 {
			auditLog.Log("", "register", "already-setup", r.RemoteAddr, false)
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "setup already complete"})
			return
		}
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			auditLog.Log("", "register", "invalid-json:"+err.Error(), r.RemoteAddr, false)
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		if err := users.Register(req.Username, req.Password, auth.RoleAdmin); err != nil {
			auditLog.Log(req.Username, "register", "register-failed:"+err.Error(), r.RemoteAddr, false)
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		tok, role, _, _ := users.Login(req.Username, req.Password, "")
		auditLog.Log(req.Username, "register", "initial admin", r.RemoteAddr, true)
		writeJSON(w, http.StatusCreated, map[string]interface{}{
			"token": tok, "username": req.Username, "role": role,
		})
	}
}

func logoutHandler(users *auth.UserStore, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		username, _, _ := users.ValidateToken(tok)
		users.Logout(tok)
		auditLog.Log(username, "logout", "", r.RemoteAddr, true)
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func usersHandler(users *auth.UserStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		writeJSON(w, http.StatusOK, users.Users())
	}
}

func createUserHandler(users *auth.UserStore, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		caller, _ := r.Context().Value(ctxUsername).(string)
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
			Role     string `json:"role"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			auditLog.Log(caller, "user-create", "invalid-json:"+err.Error(), r.RemoteAddr, false)
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		if req.Role == "" {
			req.Role = auth.RoleReadonly
		}
		if err := users.Register(req.Username, req.Password, req.Role); err != nil {
			auditLog.Log(caller, "user-create", req.Username+":"+err.Error(), r.RemoteAddr, false)
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		auditLog.Log(caller, "user-create", req.Username+" role="+req.Role, r.RemoteAddr, true)
		writeJSON(w, http.StatusCreated, map[string]string{"username": req.Username, "role": req.Role})
	}
}

func deleteUserHandler(users *auth.UserStore, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		me, _ := r.Context().Value(ctxUsername).(string)
		target := chi.URLParam(r, "username")
		if target == me {
			auditLog.Log(me, "user-delete", "self-delete-blocked", r.RemoteAddr, false)
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "cannot delete yourself"})
			return
		}
		if err := users.DeleteUser(target); err != nil {
			auditLog.Log(me, "user-delete", target+":"+err.Error(), r.RemoteAddr, false)
			writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
			return
		}
		auditLog.Log(me, "user-delete", target, r.RemoteAddr, true)
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func setRoleHandler(users *auth.UserStore, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		actor, _ := r.Context().Value(ctxUsername).(string)
		var req struct {
			Role string `json:"role"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			auditLog.Log(actor, "role-change", "invalid-json:"+err.Error(), r.RemoteAddr, false)
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		target := chi.URLParam(r, "username")
		if err := users.SetRole(target, req.Role); err != nil {
			auditLog.Log(actor, "role-change", target+"→"+req.Role+":"+err.Error(), r.RemoteAddr, false)
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		auditLog.Log(actor, "role-change", target+"→"+req.Role, r.RemoteAddr, true)
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func uiHandler(w http.ResponseWriter, r *http.Request) {
	data, err := staticFS.ReadFile("static/index.html")
	if err != nil {
		http.Error(w, "UI not found", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(data) //nolint:errcheck
}

func healthzHandler(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok": true,
		"ts": time.Now().UTC().Format(time.RFC3339),
	})
}

func disksHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		disks, err := p.Disks(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, disks)
	}
}

func arraysHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		arrays, err := p.Arrays(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, arrays)
	}
}

func createArrayHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			storage.ArraySpec
			Force bool `json:"force"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON: " + err.Error()})
			return
		}
		if req.Name == "" || len(req.Devices) == 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name and devices are required"})
			return
		}
		if err := enforcePoolCount(p, r); err != nil {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": err.Error()})
			return
		}
		if err := enforceRawCapacity(p, r, req.Devices); err != nil {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": err.Error()})
			return
		}
		arr, err := p.CreateArray(r.Context(), req.ArraySpec, req.Force)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusCreated, arr)
	}
}

func startArrayHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		if err := p.StartArray(r.Context(), name); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func stopArrayHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		if err := p.StopArray(r.Context(), name); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func deleteArrayHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		if err := p.DeleteArray(r.Context(), name); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func importCandidatesHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		candidates, err := p.ImportCandidates(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, candidates)
	}
}

func importPoolHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Name string `json:"name"`
			GUID string `json:"guid"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		if body.Name == "" && body.GUID == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name or guid required"})
			return
		}
		if err := enforcePoolCount(p, r); err != nil {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": err.Error()})
			return
		}
		if err := p.ImportPool(r.Context(), body.Name, body.GUID); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func replaceDiskHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		pool := chi.URLParam(r, "name")
		var body struct {
			OldDisk string `json:"old_disk"`
			NewDisk string `json:"new_disk"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		if body.OldDisk == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "old_disk required"})
			return
		}
		if err := p.ReplaceDisk(r.Context(), pool, body.OldDisk, body.NewDisk); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func datasetsHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		pool := chi.URLParam(r, "name")
		datasets, err := p.Datasets(r.Context(), pool)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, datasets)
	}
}

func createDatasetHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		pool := chi.URLParam(r, "name")
		var body struct {
			Name       string `json:"name"`
			Encrypted  bool   `json:"encrypted"`
			Passphrase string `json:"passphrase"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		if body.Name == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name required"})
			return
		}
		var ds storage.Dataset
		var err error
		if body.Encrypted {
			if body.Passphrase == "" {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "passphrase required for encrypted dataset"})
				return
			}
			ds, err = p.CreateEncryptedDataset(r.Context(), pool, body.Name, body.Passphrase)
		} else {
			ds, err = p.CreateDataset(r.Context(), pool, body.Name)
		}
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusCreated, ds)
	}
}

func loadEncryptionKeyHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		pool := chi.URLParam(r, "name")
		dataset := chi.URLParam(r, "dataset")
		var body struct {
			Passphrase string `json:"passphrase"`
		}
		json.NewDecoder(r.Body).Decode(&body) //nolint:errcheck
		fullName := pool + "/" + dataset
		if err := p.LoadEncryptionKey(r.Context(), fullName, body.Passphrase); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func deleteDatasetHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		pool := chi.URLParam(r, "name")
		dataset := chi.URLParam(r, "dataset")
		if err := p.DeleteDataset(r.Context(), pool, dataset); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func sharesHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		shares, err := p.Shares(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, shares)
	}
}

func createShareHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var s storage.Share
		if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON: " + err.Error()})
			return
		}
		if s.Name == "" || s.Pool == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name and pool are required"})
			return
		}
		created, err := p.CreateShare(r.Context(), s)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusCreated, created)
	}
}

func deleteShareHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		if err := p.DeleteShare(r.Context(), name); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func updateShareHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		var s storage.Share
		if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		updated, err := p.UpdateShare(r.Context(), name, s)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, updated)
	}
}

func poolHealthHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		h, err := p.PoolHealth(r.Context(), name)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, h)
	}
}

func getQuotaHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		q, err := p.GetDatasetQuota(r.Context(), name)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, q)
	}
}

func setQuotaHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		name := chi.URLParam(r, "name")
		var u storage.QuotaUpdate
		if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		if err := p.SetDatasetQuota(r.Context(), name, u); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func startScrubHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		if err := p.StartScrub(r.Context(), name); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func containersHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		containers, err := p.Containers(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, containers)
	}
}

func startContainerHandler(p storage.Provider, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) { return }
		id := chi.URLParam(r, "id")
		caller, _ := r.Context().Value(ctxUsername).(string)
		if err := p.StartContainer(r.Context(), id); err != nil {
			auditLog.LogEnriched(audit.Entry{User: caller, Action: "container-start", Resource: id, Detail: err.Error(), IP: r.RemoteAddr, OK: false})
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		auditLog.LogEnriched(audit.Entry{User: caller, Action: "container-start", Resource: id, IP: r.RemoteAddr, OK: true})
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func stopContainerHandler(p storage.Provider, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) { return }
		id := chi.URLParam(r, "id")
		caller, _ := r.Context().Value(ctxUsername).(string)
		if err := p.StopContainer(r.Context(), id); err != nil {
			auditLog.LogEnriched(audit.Entry{User: caller, Action: "container-stop", Resource: id, Detail: err.Error(), IP: r.RemoteAddr, OK: false})
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		auditLog.LogEnriched(audit.Entry{User: caller, Action: "container-stop", Resource: id, IP: r.RemoteAddr, OK: true})
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func removeContainerHandler(p storage.Provider, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) { return }
		id := chi.URLParam(r, "id")
		caller, _ := r.Context().Value(ctxUsername).(string)
		if err := p.RemoveContainer(r.Context(), id); err != nil {
			auditLog.LogEnriched(audit.Entry{User: caller, Action: "container-remove", Resource: id, Detail: err.Error(), IP: r.RemoteAddr, OK: false})
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		auditLog.LogEnriched(audit.Entry{User: caller, Action: "container-remove", Resource: id, IP: r.RemoteAddr, OK: true})
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func containerLogsHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		tail := r.URL.Query().Get("lines")
		if tail == "" {
			tail = "100"
		}
		logs, err := p.ContainerLogs(r.Context(), id, tail)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"logs": logs})
	}
}

func containerStatsHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		stats, err := p.ContainerStats(r.Context(), id)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, stats)
	}
}

func metricsHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		m, err := p.Metrics(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, m)
	}
}

func snapshotsHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		snaps, err := p.Snapshots(r.Context(), chi.URLParam(r, "name"))
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, snaps)
	}
}

func createSnapshotHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		pool := chi.URLParam(r, "name")
		var req struct {
			Name string `json:"name"`
		}
		json.NewDecoder(r.Body).Decode(&req) //nolint:errcheck
		if req.Name == "" {
			req.Name = time.Now().UTC().Format("snap-20060102-150405")
		}
		snap, err := p.CreateSnapshot(r.Context(), pool, req.Name)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusCreated, snap)
	}
}

func deleteSnapshotHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := p.DeleteSnapshot(r.Context(), chi.URLParam(r, "name"), chi.URLParam(r, "snap")); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func rollbackSnapshotHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := p.RollbackSnapshot(r.Context(), chi.URLParam(r, "name"), chi.URLParam(r, "snap")); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func settingsHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s, err := p.GetSettings(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, s)
	}
}

func applySettingsHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var u storage.SettingsUpdate
		if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		if err := p.ApplySettings(r.Context(), u); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		s, err := p.GetSettings(r.Context())
		if err != nil {
			writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
			return
		}
		writeJSON(w, http.StatusOK, s)
	}
}

var allowedLogUnits = map[string]bool{"nasd": true, "smbd": true, "docker": true, "kernel": true, "nfs-server": true, "ssh": true, "cron": true}

func logsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		unit := r.URL.Query().Get("unit")
		if unit == "" {
			unit = "nasd"
		}
		if !allowedLogUnits[unit] {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid unit"})
			return
		}
		n, _ := strconv.Atoi(r.URL.Query().Get("n"))
		if n <= 0 {
			n = 100
		}
		if n > 1000 {
			n = 1000
		}

		var args []string
		if unit == "kernel" {
			args = []string{"-k", "-n", strconv.Itoa(n), "--no-pager", "--output=short-iso"}
		} else {
			args = []string{"-u", unit, "-n", strconv.Itoa(n), "--no-pager", "--output=short-iso"}
		}
		out, err := exec.CommandContext(r.Context(), "journalctl", args...).Output()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		if len(lines) == 1 && lines[0] == "" {
			lines = []string{}
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"unit": unit, "lines": lines})
	}
}

// ── SSE log streaming ─────────────────────────────────────────────────────────

func logsStreamHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		unit := r.URL.Query().Get("unit")
		if unit == "" {
			unit = "nasd"
		}
		if !allowedLogUnits[unit] {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid unit"})
			return
		}

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("X-Accel-Buffering", "no")

		var args []string
		if unit == "kernel" {
			args = []string{"-k", "-f", "-n", "50", "--no-pager", "--output=short-iso"}
		} else {
			args = []string{"-u", unit, "-f", "-n", "50", "--no-pager", "--output=short-iso"}
		}

		cmd := exec.CommandContext(r.Context(), "journalctl", args...)
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			return
		}
		if err := cmd.Start(); err != nil {
			return
		}
		defer cmd.Wait() //nolint:errcheck

		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			line := sc.Text()
			fmt.Fprintf(w, "data: %s\n\n", strings.ReplaceAll(line, "\n", " "))
			flusher.Flush()
		}
	}
}

// ── docker images ─────────────────────────────────────────────────────────────

func dockerImagesHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		imgs, err := p.DockerImages(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, imgs)
	}
}

func removeDockerImageHandler(p storage.Provider, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) { return }
		id := chi.URLParam(r, "id")
		caller, _ := r.Context().Value(ctxUsername).(string)
		if strings.ContainsAny(id, " /;|&$`\\\"'\n") {
			auditLog.LogEnriched(audit.Entry{User: caller, Action: "docker-image-remove", Detail: "invalid-id", IP: r.RemoteAddr, OK: false})
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid image id"})
			return
		}
		if err := p.RemoveDockerImage(r.Context(), id); err != nil {
			auditLog.LogEnriched(audit.Entry{User: caller, Action: "docker-image-remove", Resource: id, Detail: err.Error(), IP: r.RemoteAddr, OK: false})
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		auditLog.LogEnriched(audit.Entry{User: caller, Action: "docker-image-remove", Resource: id, IP: r.RemoteAddr, OK: true})
		w.WriteHeader(http.StatusNoContent)
	}
}

// ── file browser ─────────────────────────────────────────────────────────────

const poolMountDir = "/mnt"

type fileEntry struct {
	Name    string `json:"name"`
	IsDir   bool   `json:"is_dir"`
	Size    int64  `json:"size"`
	ModTime int64  `json:"mod_time"`
}

func resolvePoolPath(pool, rel string) (abs, base string, err error) {
	if pool == "" || strings.ContainsAny(pool, "/\\.") {
		return "", "", fmt.Errorf("invalid pool name")
	}
	base = filepath.Join(poolMountDir, pool)
	abs = filepath.Clean(filepath.Join(base, rel))
	if abs != base && !strings.HasPrefix(abs, base+"/") {
		return "", "", fmt.Errorf("path outside pool")
	}
	return abs, base, nil
}

func filesListHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		abs, _, err := resolvePoolPath(r.URL.Query().Get("pool"), r.URL.Query().Get("path"))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		entries, err := os.ReadDir(abs)
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
			return
		}
		out := make([]fileEntry, 0, len(entries))
		for _, e := range entries {
			info, _ := e.Info()
			size := int64(0)
			mod := int64(0)
			if info != nil {
				size = info.Size()
				mod = info.ModTime().Unix()
			}
			out = append(out, fileEntry{Name: e.Name(), IsDir: e.IsDir(), Size: size, ModTime: mod})
		}
		writeJSON(w, http.StatusOK, out)
	}
}

func filesDeleteHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		abs, base, err := resolvePoolPath(r.URL.Query().Get("pool"), r.URL.Query().Get("path"))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if abs == base {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "cannot delete pool root"})
			return
		}
		if err := os.RemoveAll(abs); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func filesMkdirHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		var req struct {
			Pool string `json:"pool"`
			Path string `json:"path"`
			Name string `json:"name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		abs, _, err := resolvePoolPath(req.Pool, req.Path+"/"+req.Name)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if err := os.Mkdir(abs, 0755); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func filesRenameHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		var req struct {
			Pool    string `json:"pool"`
			OldPath string `json:"old_path"`
			NewName string `json:"new_name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		if strings.ContainsAny(req.NewName, "/\\\x00") || req.NewName == "" || req.NewName == "." || req.NewName == ".." {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid name"})
			return
		}
		oldAbs, base, err := resolvePoolPath(req.Pool, req.OldPath)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		newAbs := filepath.Join(filepath.Dir(oldAbs), req.NewName)
		if !strings.HasPrefix(newAbs, base) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "path outside pool"})
			return
		}
		if err := os.Rename(oldAbs, newAbs); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func filesMoveHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		var req struct {
			Pool    string `json:"pool"`
			SrcPath string `json:"src_path"`
			DstPath string `json:"dst_path"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		srcAbs, _, err := resolvePoolPath(req.Pool, req.SrcPath)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		dstAbs, _, err := resolvePoolPath(req.Pool, req.DstPath)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if err := os.Rename(srcAbs, dstAbs); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func alertsHandler(mon *monitor.Monitor) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, mon.Alerts())
	}
}

func dismissAlertHandler(mon *monitor.Monitor) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		mon.Dismiss(chi.URLParam(r, "id"))
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

type backupDoc struct {
	Version    int                    `json:"version"`
	ExportedAt string                 `json:"exported_at"`
	Settings   storage.SystemSettings `json:"settings"`
	Arrays     []storage.Array        `json:"arrays"`
	Shares     []storage.Share        `json:"shares"`
}

func backupHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		settings, err := p.GetSettings(ctx)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		arrays, err := p.Arrays(ctx)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		shares, err := p.Shares(ctx)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		if arrays == nil {
			arrays = []storage.Array{}
		}
		if shares == nil {
			shares = []storage.Share{}
		}
		doc := backupDoc{
			Version:    1,
			ExportedAt: time.Now().UTC().Format(time.RFC3339),
			Settings:   settings,
			Arrays:     arrays,
			Shares:     shares,
		}
		fname := "kilasos-backup-" + time.Now().UTC().Format("20060102-150405") + ".json"
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", `attachment; filename="`+fname+`"`)
		w.WriteHeader(http.StatusOK)
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		enc.Encode(doc) //nolint:errcheck
	}
}

func restoreHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var doc backupDoc
		if err := json.NewDecoder(r.Body).Decode(&doc); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid backup JSON: " + err.Error()})
			return
		}
		ctx := r.Context()
		var errs []string

		u := storage.SettingsUpdate{
			Hostname: &doc.Settings.Hostname,
			Timezone: &doc.Settings.Timezone,
			NTP:      &doc.Settings.NTPEnabled,
		}
		if err := p.ApplySettings(ctx, u); err != nil {
			errs = append(errs, "settings: "+err.Error())
		}

		for _, s := range doc.Shares {
			if _, err := p.CreateShare(ctx, s); err != nil {
				errs = append(errs, "share "+s.Name+": "+err.Error())
			}
		}

		writeJSON(w, http.StatusOK, map[string]interface{}{
			"ok":      len(errs) == 0,
			"applied": map[string]int{"shares": len(doc.Shares)},
			"errors":  errs,
		})
	}
}

func schedulesHandler(sched *scheduler.Scheduler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, sched.Schedules())
	}
}

func createScheduleHandler(sched *scheduler.Scheduler, replicator zfssend.Replicator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Kind     string         `json:"kind"`
			Pool     string         `json:"pool"`
			Freq     scheduler.Freq `json:"freq"`
			Keep     int            `json:"keep"`
			RemoteID string         `json:"remote_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		if req.Kind == "scrub" {
			sc, err := sched.AddScrub(req.Pool, req.Freq)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, http.StatusCreated, sc)
			return
		}
		if req.RemoteID != "" || req.Kind == "replication" {
			remoteName := req.RemoteID
			for _, rem := range replicator.Remotes() {
				if rem.ID == req.RemoteID {
					remoteName = rem.Name
					break
				}
			}
			sc, err := sched.AddReplication(req.Pool, req.RemoteID, remoteName, req.Freq)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, http.StatusCreated, sc)
			return
		}
		sc, err := sched.Add(req.Pool, req.Freq, req.Keep)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusCreated, sc)
	}
}

func deleteScheduleHandler(sched *scheduler.Scheduler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := sched.Delete(chi.URLParam(r, "id")); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func patchScheduleHandler(sched *scheduler.Scheduler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Enabled *bool `json:"enabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		if req.Enabled == nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "enabled field required"})
			return
		}
		if err := sched.SetEnabled(chi.URLParam(r, "id"), *req.Enabled); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func remotesHandler(replicator zfssend.Replicator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, replicator.Remotes())
	}
}

func addRemoteHandler(replicator zfssend.Replicator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Name     string `json:"name"`
			Host     string `json:"host"`
			User     string `json:"user"`
			DestPool string `json:"dest_pool"`
			Port     int    `json:"port"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		remote, err := replicator.AddRemote(req.Name, req.Host, req.User, req.DestPool, req.Port)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusCreated, remote)
	}
}

func deleteRemoteHandler(replicator zfssend.Replicator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := replicator.DeleteRemote(chi.URLParam(r, "id")); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func startSendHandler(replicator zfssend.Replicator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		pool := chi.URLParam(r, "name")
		var req struct {
			RemoteID string `json:"remote_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		jobID, err := replicator.StartSend(pool, req.RemoteID)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]string{"job_id": jobID})
	}
}

func jobHandler(replicator zfssend.Replicator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		v, ok := replicator.GetJob(chi.URLParam(r, "id"))
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "job not found"})
			return
		}
		writeJSON(w, http.StatusOK, v)
	}
}

func powerStatusHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s, err := p.GetPowerStatus(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, s)
	}
}

func shutdownHandler(p storage.Provider, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		actor, _ := r.Context().Value(ctxUsername).(string)
		var req struct {
			DelayMinutes int `json:"delay_minutes"`
		}
		json.NewDecoder(r.Body).Decode(&req) //nolint:errcheck
		if err := p.Shutdown(r.Context(), req.DelayMinutes); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		auditLog.Log(actor, "shutdown", fmt.Sprintf("delay=%dm", req.DelayMinutes), r.RemoteAddr, true)
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func rebootHandler(p storage.Provider, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		actor, _ := r.Context().Value(ctxUsername).(string)
		var req struct {
			DelayMinutes int `json:"delay_minutes"`
		}
		json.NewDecoder(r.Body).Decode(&req) //nolint:errcheck
		if err := p.Reboot(r.Context(), req.DelayMinutes); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		auditLog.Log(actor, "reboot", fmt.Sprintf("delay=%dm", req.DelayMinutes), r.RemoteAddr, true)
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func cancelShutdownHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := p.CancelShutdown(r.Context()); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func spindownHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		if len(name) > 32 || strings.ContainsAny(name, " /;|&$`\\\"'") {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid disk name"})
			return
		}
		var req struct {
			Seconds int `json:"seconds"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		if err := p.SetDiskSpindown(r.Context(), "/dev/"+name, req.Seconds); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func getSmartTestStatusHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		if len(name) > 32 || strings.ContainsAny(name, " /;|&$`\\\"'") {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid disk name"})
			return
		}
		st, err := p.GetSmartTestStatus(r.Context(), "/dev/"+name)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, st)
	}
}

func wipeDiskHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		name := chi.URLParam(r, "name")
		if len(name) > 32 || strings.ContainsAny(name, " /;|&$`\\\"'") {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid disk name"})
			return
		}
		if err := p.WipeDisk(r.Context(), "/dev/"+name); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func pullImageHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		var req struct {
			Image string `json:"image"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Image == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "image is required"})
			return
		}
		output, err := p.PullImage(r.Context(), req.Image)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"output": output})
	}
}

func resilverHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		name := chi.URLParam(r, "name")
		if err := p.Resilver(r.Context(), name); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func expandPoolHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		name := chi.URLParam(r, "name")
		if err := enforcePoolCount(p, r); err != nil {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": err.Error()})
			return
		}
		if err := enforceRawCapacity(p, r, nil); err != nil {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": err.Error()})
			return
		}
		if err := p.ExpandPool(r.Context(), name); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func cloneSnapshotHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		pool := chi.URLParam(r, "name")
		snap := chi.URLParam(r, "snap")
		var req struct {
			CloneName string `json:"clone_name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.CloneName == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "clone_name required"})
			return
		}
		if strings.ContainsAny(req.CloneName, " /;|&$`\\\"'\n") {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid clone name"})
			return
		}
		if err := p.CloneSnapshot(r.Context(), pool, snap, req.CloneName); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func smbConnectionsHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		conns, err := p.SMBConnections(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, conns)
	}
}

func journalSearchHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query().Get("q")
		if query == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "q parameter required"})
			return
		}
		if len(query) > 200 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "query too long"})
			return
		}
		n, _ := strconv.Atoi(r.URL.Query().Get("n"))
		results, err := p.SearchJournal(r.Context(), query, n)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, results)
	}
}

func poolEventsHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		events, err := p.PoolEvents(r.Context(), name)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, events)
	}
}

func containerInspectHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		detail, err := p.InspectContainer(r.Context(), id)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, detail)
	}
}

func poolIOHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		stats, err := p.PoolIO(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, stats)
	}
}

func diskIOHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		stats, err := p.DiskIO(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, stats)
	}
}

func processesHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		procs, err := p.Processes(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, procs)
	}
}

func dockerVolumesHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vols, err := p.DockerVolumes(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, vols)
	}
}

func removeDockerVolumeHandler(p storage.Provider, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) { return }
		name := chi.URLParam(r, "name")
		caller, _ := r.Context().Value(ctxUsername).(string)
		if strings.ContainsAny(name, " /;|&$`\\\"'") {
			auditLog.LogEnriched(audit.Entry{User: caller, Action: "docker-volume-remove", Detail: "invalid-name", IP: r.RemoteAddr, OK: false})
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid volume name"})
			return
		}
		if err := p.RemoveDockerVolume(r.Context(), name); err != nil {
			auditLog.LogEnriched(audit.Entry{User: caller, Action: "docker-volume-remove", Resource: name, Detail: err.Error(), IP: r.RemoteAddr, OK: false})
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		auditLog.LogEnriched(audit.Entry{User: caller, Action: "docker-volume-remove", Resource: name, IP: r.RemoteAddr, OK: true})
		w.WriteHeader(http.StatusNoContent)
	}
}

func netDiagHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		var req struct {
			Type   string `json:"type"`
			Target string `json:"target"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Target == "" || req.Type == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "type and target are required"})
			return
		}
		// Validate type
		if req.Type != "ping" && req.Type != "dns" && req.Type != "traceroute" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "type must be ping, dns, or traceroute"})
			return
		}
		// Basic target validation — no shell metacharacters
		if strings.ContainsAny(req.Target, " ;|&$`\\\"'\n\r\t") {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid target"})
			return
		}
		result, err := p.NetDiag(r.Context(), req.Type, req.Target)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, result)
	}
}

func getDatasetPropsHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		pool := chi.URLParam(r, "name")
		ds := chi.URLParam(r, "dataset")
		full := pool + "/" + ds
		props, err := p.GetDatasetProps(r.Context(), full)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, props)
	}
}

func setDatasetPropsHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		pool := chi.URLParam(r, "name")
		ds := chi.URLParam(r, "dataset")
		full := pool + "/" + ds
		var u storage.DatasetPropsUpdate
		if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
			return
		}
		if err := p.SetDatasetProps(r.Context(), full, u); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func smartDetailHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		devPath := "/dev/" + name
		detail, err := p.SmartDetail(r.Context(), devPath)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, detail)
	}
}

func getIfaceConfigHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "iface")
		if len(name) > 16 || strings.ContainsAny(name, " /;|&$`\\\"'") {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid interface name"})
			return
		}
		cfg, err := p.GetIfaceConfig(r.Context(), name)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, cfg)
	}
}

func setIfaceConfigHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		name := chi.URLParam(r, "iface")
		if len(name) > 16 || strings.ContainsAny(name, " /;|&$`\\\"'") {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid interface name"})
			return
		}
		var cfg storage.IfaceConfig
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		if !cfg.DHCP {
			if cfg.Address == "" {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "address required for static config"})
				return
			}
			if _, _, err := net.ParseCIDR(cfg.Address); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "address must be CIDR (e.g. 10.0.0.1/24)"})
				return
			}
		}
		if err := p.SetIfaceConfig(r.Context(), name, cfg); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func wolListHandler(s *wol.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, s.List())
	}
}

func wolAddHandler(s *wol.Store, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		caller, _ := r.Context().Value(ctxUsername).(string)
		var req struct {
			Name string `json:"name"`
			MAC  string `json:"mac"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			auditLog.LogEnriched(audit.Entry{User: caller, Action: "wol-add", Detail: "invalid-json", IP: r.RemoteAddr, OK: false})
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		t, err := s.Add(req.Name, req.MAC)
		if err != nil {
			auditLog.LogEnriched(audit.Entry{User: caller, Action: "wol-add", Detail: err.Error(), IP: r.RemoteAddr, OK: false, Resource: req.Name})
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		auditLog.LogEnriched(audit.Entry{User: caller, Action: "wol-add", Resource: req.Name + " " + req.MAC, IP: r.RemoteAddr, OK: true})
		writeJSON(w, http.StatusCreated, t)
	}
}

func wolDeleteHandler(s *wol.Store, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		id := chi.URLParam(r, "id")
		caller, _ := r.Context().Value(ctxUsername).(string)
		if err := s.Delete(id); err != nil {
			auditLog.LogEnriched(audit.Entry{User: caller, Action: "wol-delete", Resource: id, Detail: err.Error(), IP: r.RemoteAddr, OK: false})
			writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
			return
		}
		auditLog.LogEnriched(audit.Entry{User: caller, Action: "wol-delete", Resource: id, IP: r.RemoteAddr, OK: true})
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func wolWakeHandler(s *wol.Store, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		id := chi.URLParam(r, "id")
		caller, _ := r.Context().Value(ctxUsername).(string)
		if err := s.Wake(id); err != nil {
			auditLog.LogEnriched(audit.Entry{User: caller, Action: "wol-wake", Resource: id, Detail: err.Error(), IP: r.RemoteAddr, OK: false})
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		auditLog.LogEnriched(audit.Entry{User: caller, Action: "wol-wake", Resource: id, IP: r.RemoteAddr, OK: true})
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func networkHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ifaces, err := p.NetInterfaces(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, ifaces)
	}
}

func setIfaceHandler(p storage.Provider, up bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "iface")
		// Validate name: only alnum, hyphens, dots, underscores, max 16 chars
		if len(name) > 16 || strings.ContainsAny(name, " /;|&$`\\\"'") {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid interface name"})
			return
		}
		if err := p.SetInterfaceState(r.Context(), name, up); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func catalogHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, appcatalog.AllCatalog())
	}
}

func appsHandler(apps *appcatalog.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, apps.Apps())
	}
}

func deployAppHandler(apps *appcatalog.Manager, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) { return }
		caller, _ := r.Context().Value(ctxUsername).(string)
		var req struct {
			TemplateID string `json:"template_id"`
			Compose    string `json:"compose,omitempty"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			auditLog.LogEnriched(audit.Entry{User: caller, Action: "app-deploy", Detail: "invalid-json", IP: r.RemoteAddr, OK: false})
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		jobID, err := apps.Deploy(req.TemplateID, req.Compose)
		if err != nil {
			auditLog.LogEnriched(audit.Entry{User: caller, Action: "app-deploy", Resource: req.TemplateID, Detail: err.Error(), IP: r.RemoteAddr, OK: false})
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		auditLog.LogEnriched(audit.Entry{User: caller, Action: "app-deploy", Resource: req.TemplateID, IP: r.RemoteAddr, OK: true})
		writeJSON(w, http.StatusAccepted, map[string]string{"job_id": jobID})
	}
}

func removeAppHandler(apps *appcatalog.Manager, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) { return }
		name := chi.URLParam(r, "name")
		caller, _ := r.Context().Value(ctxUsername).(string)
		out, err := apps.Remove(name)
		if err != nil {
			auditLog.LogEnriched(audit.Entry{User: caller, Action: "app-remove", Resource: name, Detail: err.Error(), IP: r.RemoteAddr, OK: false})
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		auditLog.LogEnriched(audit.Entry{User: caller, Action: "app-remove", Resource: name, IP: r.RemoteAddr, OK: true})
		writeJSON(w, http.StatusOK, map[string]string{"job_id": out})
	}
}

func appActionHandler(apps *appcatalog.Manager, action string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		var jobID string
		var err error
		switch action {
		case "start":
			jobID, err = apps.Start(name)
		case "stop":
			jobID, err = apps.Stop(name)
		}
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]string{"job_id": jobID})
	}
}

func appTemplateHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tmpl := appcatalog.GetTemplate(chi.URLParam(r, "id"))
		if tmpl == nil {
			writeJSON(w, 404, map[string]string{"error": "template not found"})
			return
		}
		writeJSON(w, 200, tmpl)
	}
}

func appJobHandler(apps *appcatalog.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		v, ok := apps.GetJob(chi.URLParam(r, "id"))
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "job not found"})
			return
		}
		writeJSON(w, http.StatusOK, v)
	}
}

func appStacksHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		stacks, err := p.AppStacks(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, stacks)
	}
}

func createAppStackHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) { return }
		var s storage.AppStack
		if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		stack, err := p.CreateAppStack(r.Context(), s)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, stack)
	}
}

func deleteAppStackHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) { return }
		name := chi.URLParam(r, "name")
		if err := p.DeleteAppStack(r.Context(), name); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"deleted": name})
	}
}

func appUpdateAvailableHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		info, err := p.AppUpdateAvailable(r.Context(), name)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, info)
	}
}

func appUpdateHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		var req struct {
			Backup bool `json:"backup"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		out, err := p.AppUpdate(r.Context(), name, req.Backup)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"output": out})
	}
}

func appRollbackHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		var req struct {
			BackupID string `json:"backup_id"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		out, err := p.AppRollback(r.Context(), name, req.BackupID)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"output": out})
	}
}

func appHealthStatusHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		info, err := p.AppHealthStatus(r.Context(), name)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, info)
	}
}

func appExportConfigHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		cfg, err := p.AppExportConfig(r.Context(), name)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, cfg)
	}
}

func appImportConfigHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		var cfg storage.AppConfigExport
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if err := p.AppImportConfig(r.Context(), name, cfg); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"imported": name})
	}
}

func appCustomTemplateHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ComposeYAML string `json:"compose_yaml"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		tmpl, err := p.AppCustomTemplate(r.Context(), req.ComposeYAML)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, tmpl)
	}
}

func appFavoritesHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		favs, err := p.AppFavorites(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, favs)
	}
}

func appSetFavoriteHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		var req struct {
			Favorite bool `json:"favorite"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		if err := p.AppSetFavorite(r.Context(), name, req.Favorite); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"name": name, "favorite": fmt.Sprintf("%v", req.Favorite)})
	}
}

func appSearchHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		cat := r.URL.Query().Get("category")
		results, err := p.AppSearch(r.Context(), q, cat)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, results)
	}
}

func rsyncJobsHandler(mgr *kilaosrsync.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, mgr.Jobs())
	}
}

func createRsyncJobHandler(mgr *kilaosrsync.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var j kilaosrsync.Job
		if err := json.NewDecoder(r.Body).Decode(&j); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		created, err := mgr.Add(j)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusCreated, created)
	}
}

func deleteRsyncJobHandler(mgr *kilaosrsync.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := mgr.Delete(chi.URLParam(r, "id")); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func patchRsyncJobHandler(mgr *kilaosrsync.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		var body struct {
			Enabled *bool `json:"enabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		if body.Enabled != nil {
			if err := mgr.SetEnabled(id, *body.Enabled); err != nil {
				writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
				return
			}
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func runRsyncJobHandler(mgr *kilaosrsync.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := mgr.RunNow(r.Context(), chi.URLParam(r, "id")); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func rsyncJobStatusHandler(mgr *kilaosrsync.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		st := mgr.Status(chi.URLParam(r, "id"))
		if st == nil {
			writeJSON(w, http.StatusOK, map[string]interface{}{"running": false, "done": false, "lines": []string{}})
			return
		}
		writeJSON(w, http.StatusOK, st)
	}
}

func getWebhookConfigHandler(mon *monitor.Monitor) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := mon.GetWebhook()
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"url":        cfg.URL,
			"has_secret": cfg.Secret != "",
		})
	}
}

func putWebhookConfigHandler(mon *monitor.Monitor, cfgPath string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		var req struct {
			URL    string `json:"url"`
			Secret string `json:"secret"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		mon.SetWebhook(req.URL, req.Secret)
		if err := saveWebhookCfg(cfgPath, req.URL, req.Secret); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func deleteWebhookConfigHandler(mon *monitor.Monitor, cfgPath string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		mon.SetWebhook("", "")
		os.Remove(cfgPath) //nolint:errcheck
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func testWebhookHandler(mon *monitor.Monitor) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		if err := mon.TestPing(); err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func monitorConfigHandler(mon *monitor.Monitor) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, mon.GetThresholds())
	}
}

func setMonitorConfigHandler(mon *monitor.Monitor, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		var cfg monitor.MonitorConfig
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid config"})
			return
		}
		caller, _ := r.Context().Value(ctxUsername).(string)
		mon.SetThresholds(cfg)
		auditLog.LogEnriched(audit.Entry{User: caller, Action: "monitor-config-update", IP: r.RemoteAddr, OK: true})
		writeJSON(w, http.StatusOK, mon.GetThresholds())
	}
}

func getSmtpConfigHandler(mon *monitor.Monitor) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ml := mon.GetMailer()
		if ml == nil {
			writeJSON(w, http.StatusOK, notify.SMTPConfig{})
			return
		}
		writeJSON(w, http.StatusOK, ml.Config())
	}
}

func putSmtpConfigHandler(mon *monitor.Monitor, cfgPath string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		var cfg notify.SMTPConfig
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		if cfg.Host == "" || cfg.Port == 0 || cfg.From == "" || cfg.To == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "host, port, from, and to are required"})
			return
		}
		if err := saveSmtpCfg(cfgPath, cfg); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		mon.SetMailer(notify.NewMailer(cfg))
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func deleteSmtpConfigHandler(mon *monitor.Monitor, cfgPath string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		os.Remove(cfgPath)
		mon.SetMailer(nil)
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func testSmtpHandler(mon *monitor.Monitor) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		if err := mon.TestEmail(); err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func saveSmtpCfg(path string, cfg notify.SMTPConfig) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func saveWebhookCfg(path, url, secret string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(map[string]string{"url": url, "secret": secret}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func updatesInfoHandler(u *sysupdate.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, u.Info())
	}
}

func startCheckHandler(u *sysupdate.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		jobID := u.StartCheck()
		writeJSON(w, http.StatusAccepted, map[string]string{"job_id": jobID})
	}
}

func startApplyHandler(u *sysupdate.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		jobID := u.StartApply()
		writeJSON(w, http.StatusAccepted, map[string]string{"job_id": jobID})
	}
}

func updateJobHandler(u *sysupdate.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		v, ok := u.GetJob(chi.URLParam(r, "id"))
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "job not found"})
			return
		}
		writeJSON(w, http.StatusOK, v)
	}
}

func sshKeysHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		keys, err := p.SSHKeys(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, keys)
	}
}

func addSSHKeyHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		var req struct {
			Pubkey string `json:"pubkey"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		key, err := p.AddSSHKey(r.Context(), strings.TrimSpace(req.Pubkey))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusCreated, key)
	}
}

func deleteSSHKeyHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		var req struct {
			Key string `json:"key"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		if err := p.DeleteSSHKey(r.Context(), req.Key); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func auditLogHandler(auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		n := 100
		if v := r.URL.Query().Get("n"); v != "" {
			if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 && parsed <= 1000 {
				n = parsed
			}
		}
		writeJSON(w, http.StatusOK, auditLog.Recent(n))
	}
}

func metricsHistoryHandler(hist *monitor.MetricsHistory) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, hist.Samples())
	}
}

func sysinfoHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		info, err := p.SystemInfo(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, info)
	}
}

func arcStatsHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		stats, err := p.ARCStats(r.Context())
		if err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "ZFS ARC stats unavailable"})
			return
		}
		writeJSON(w, http.StatusOK, stats)
	}
}

func prometheusHandler(p storage.Provider, hist *monitor.MetricsHistory) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		m, err := p.Metrics(r.Context())
		if err != nil {
			http.Error(w, "failed to collect metrics", http.StatusInternalServerError)
			return
		}
		var sb strings.Builder
		// CPU
		fmt.Fprintf(&sb, "# HELP kilasos_cpu_percent CPU utilization percent\n")
		fmt.Fprintf(&sb, "# TYPE kilasos_cpu_percent gauge\n")
		fmt.Fprintf(&sb, "kilasos_cpu_percent %.2f\n", m.CPUPercent)
		// Memory
		fmt.Fprintf(&sb, "# HELP kilasos_mem_total_bytes Total memory in bytes\n")
		fmt.Fprintf(&sb, "# TYPE kilasos_mem_total_bytes gauge\n")
		fmt.Fprintf(&sb, "kilasos_mem_total_bytes %d\n", m.MemTotal)
		fmt.Fprintf(&sb, "# HELP kilasos_mem_used_bytes Used memory in bytes\n")
		fmt.Fprintf(&sb, "# TYPE kilasos_mem_used_bytes gauge\n")
		fmt.Fprintf(&sb, "kilasos_mem_used_bytes %d\n", m.MemUsed)
		// Network
		fmt.Fprintf(&sb, "# HELP kilasos_net_rx_bytes_per_sec Network receive rate bytes/sec\n")
		fmt.Fprintf(&sb, "# TYPE kilasos_net_rx_bytes_per_sec gauge\n")
		fmt.Fprintf(&sb, "# HELP kilasos_net_tx_bytes_per_sec Network transmit rate bytes/sec\n")
		fmt.Fprintf(&sb, "# TYPE kilasos_net_tx_bytes_per_sec gauge\n")
		for _, iface := range m.NetInterfaces {
			fmt.Fprintf(&sb, "kilasos_net_rx_bytes_per_sec{iface=%q} %.2f\n", iface.Name, iface.RxBytesPerSec)
			fmt.Fprintf(&sb, "kilasos_net_tx_bytes_per_sec{iface=%q} %.2f\n", iface.Name, iface.TxBytesPerSec)
		}
		// Pool usage
		fmt.Fprintf(&sb, "# HELP kilasos_pool_total_bytes Pool total size in bytes\n")
		fmt.Fprintf(&sb, "# TYPE kilasos_pool_total_bytes gauge\n")
		fmt.Fprintf(&sb, "# HELP kilasos_pool_used_bytes Pool used space in bytes\n")
		fmt.Fprintf(&sb, "# TYPE kilasos_pool_used_bytes gauge\n")
		fmt.Fprintf(&sb, "# HELP kilasos_pool_free_bytes Pool free space in bytes\n")
		fmt.Fprintf(&sb, "# TYPE kilasos_pool_free_bytes gauge\n")
		for _, pool := range m.PoolUsage {
			fmt.Fprintf(&sb, "kilasos_pool_total_bytes{pool=%q} %d\n", pool.Name, pool.Total)
			fmt.Fprintf(&sb, "kilasos_pool_used_bytes{pool=%q} %d\n", pool.Name, pool.Used)
			fmt.Fprintf(&sb, "kilasos_pool_free_bytes{pool=%q} %d\n", pool.Name, pool.Free)
		}
		// History last sample
		samples := hist.Samples()
		if len(samples) > 0 {
			last := samples[len(samples)-1]
			fmt.Fprintf(&sb, "# HELP kilasos_net_rx_bps_total Aggregate network RX bytes/sec\n")
			fmt.Fprintf(&sb, "# TYPE kilasos_net_rx_bps_total gauge\n")
			fmt.Fprintf(&sb, "kilasos_net_rx_bps_total %.2f\n", last.RxBytesPerSec)
			fmt.Fprintf(&sb, "kilasos_net_tx_bps_total %.2f\n", last.TxBytesPerSec)
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(sb.String())) //nolint:errcheck
	}
}

func totpStatusHandler(users *auth.UserStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username, _ := r.Context().Value(ctxUsername).(string)
		writeJSON(w, http.StatusOK, map[string]bool{"enabled": users.TOTPStatus(username)})
	}
}

func totpEnrollHandler(users *auth.UserStore, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username, _ := r.Context().Value(ctxUsername).(string)
		secret, uri, err := users.EnrollTOTP(username)
		if err != nil {
			auditLog.Log(username, "totp-enroll", err.Error(), r.RemoteAddr, false)
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		auditLog.Log(username, "totp-enroll", "", r.RemoteAddr, true)
		writeJSON(w, http.StatusOK, map[string]string{"secret": secret, "uri": uri})
	}
}

func totpConfirmHandler(users *auth.UserStore, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username, _ := r.Context().Value(ctxUsername).(string)
		var req struct {
			Code string `json:"code"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			auditLog.Log(username, "totp-enabled", "invalid-json:"+err.Error(), r.RemoteAddr, false)
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		if err := users.ConfirmTOTP(username, req.Code); err != nil {
			auditLog.Log(username, "totp-enabled", err.Error(), r.RemoteAddr, false)
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		auditLog.Log(username, "totp-enabled", "", r.RemoteAddr, true)
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func totpDisableHandler(users *auth.UserStore, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username, _ := r.Context().Value(ctxUsername).(string)
		var req struct {
			Code string `json:"code"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			auditLog.Log(username, "totp-disabled", "invalid-json:"+err.Error(), r.RemoteAddr, false)
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		if err := users.DisableTOTP(username, req.Code); err != nil {
			auditLog.Log(username, "totp-disabled", err.Error(), r.RemoteAddr, false)
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		auditLog.Log(username, "totp-disabled", "", r.RemoteAddr, true)
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func getPoolPropsHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		pool := chi.URLParam(r, "name")
		props, err := p.GetPoolProps(r.Context(), pool)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, props)
	}
}

func setPoolPropsHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		pool := chi.URLParam(r, "name")
		var u storage.ZFSPoolPropsUpdate
		if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		if err := p.SetPoolProps(r.Context(), pool, u); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func scanServicesHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Host string `json:"host"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Host == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "host required"})
			return
		}
		results, err := p.ScanServices(r.Context(), req.Host)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, results)
	}
}

func pendingUpdatesHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		updates, err := p.PendingUpdates(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, updates)
	}
}

func systemUsersHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		users, err := p.SystemUsers(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, users)
	}
}

func addSystemUserHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Name     string `json:"name"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" || req.Password == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name and password required"})
			return
		}
		if err := p.AddSystemUser(r.Context(), req.Name, req.Password); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func deleteSystemUserHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		if err := p.DeleteSystemUser(r.Context(), name); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func cronJobsHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		jobs, err := p.CronJobs(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, jobs)
	}
}

func cpuFreqHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		info, err := p.CPUFreq(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, info)
	}
}

func benchmarkDiskHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		devPath := "/dev/" + name
		result, err := p.BenchmarkDisk(r.Context(), devPath)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, result)
	}
}

func shareStatsHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		stats, err := p.ShareStats(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, stats)
	}
}

func arpTableHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		entries, err := p.ARPTable(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, entries)
	}
}

func firewallRulesHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rules, err := p.FirewallRules(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"rules": rules})
	}
}

func getDNSConfigHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg, err := p.GetDNSConfig(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, cfg)
	}
}

func setDNSConfigHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var cfg storage.DNSConfig
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		if err := p.SetDNSConfig(r.Context(), cfg); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func getHostsHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hosts, err := p.GetHosts(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, hosts)
	}
}

func addHostHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var entry storage.HostEntry
		if err := json.NewDecoder(r.Body).Decode(&entry); err != nil || entry.IP == "" || entry.Hostname == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "ip and hostname required"})
			return
		}
		if err := p.AddHost(r.Context(), entry); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func deleteHostHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := r.URL.Query().Get("ip")
		hostname := r.URL.Query().Get("hostname")
		if ip == "" || hostname == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "ip and hostname required"})
			return
		}
		if err := p.DeleteHost(r.Context(), ip, hostname); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func listServicesHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		services, err := p.ListServices(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, services)
	}
}

func serviceActionHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		action := chi.URLParam(r, "action")
		if err := p.ServiceAction(r.Context(), name, action); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func memDetailHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		mem, err := p.MemDetail(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, mem)
	}
}

func getSambaGlobalHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg, err := p.GetSambaGlobal(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, cfg)
	}
}

func setSambaGlobalHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var cfg storage.SambaGlobal
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		if err := p.SetSambaGlobal(r.Context(), cfg); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func ifaceStatsHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		stats, err := p.NetIfaceStats(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, stats)
	}
}

func tlsCertHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Host string `json:"host"`
			Port int    `json:"port"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Host == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "host required"})
			return
		}
		if req.Port == 0 {
			req.Port = 443
		}
		info, err := p.TLSCert(r.Context(), req.Host, req.Port)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, info)
	}
}

func lastLoginsHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		n := 20
		if nStr := r.URL.Query().Get("n"); nStr != "" {
			if v, err := strconv.Atoi(nStr); err == nil && v > 0 {
				n = v
			}
		}
		logins, err := p.LastLogins(r.Context(), n)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, logins)
	}
}

func scrubSchedulesHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		schedules, err := p.ScrubSchedules(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, schedules)
	}
}

func setScrubScheduleHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		pool := chi.URLParam(r, "pool")
		var req struct {
			Schedule string `json:"schedule"`
			Enabled  bool   `json:"enabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		if err := p.SetScrubSchedule(r.Context(), pool, req.Schedule, req.Enabled); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func fileSearchHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Root    string `json:"root"`
			Pattern string `json:"pattern"`
			Max     int    `json:"max"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Pattern == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "pattern required"})
			return
		}
		results, err := p.SearchFiles(r.Context(), req.Root, req.Pattern, req.Max)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, results)
	}
}

func snapshotDiffHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		pool := chi.URLParam(r, "name")
		snapA := chi.URLParam(r, "snapA")
		snapB := r.URL.Query().Get("to")
		diffs, err := p.SnapshotDiff(r.Context(), pool, snapA, snapB)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, diffs)
	}
}

func containerExecHandler(p storage.Provider, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) { return }
		id := chi.URLParam(r, "id")
		caller, _ := r.Context().Value(ctxUsername).(string)
		var req struct {
			Command string `json:"command"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Command == "" {
			auditLog.LogEnriched(audit.Entry{User: caller, Action: "container-exec", Resource: id, Detail: "command-required", IP: r.RemoteAddr, OK: false})
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "command required"})
			return
		}
		_, err := p.ContainerExec(r.Context(), id, req.Command)
		if err != nil {
			auditLog.LogEnriched(audit.Entry{User: caller, Action: "container-exec", Resource: id, Detail: err.Error(), IP: r.RemoteAddr, OK: false})
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		auditLog.LogEnriched(audit.Entry{User: caller, Action: "container-exec", Resource: id, Detail: req.Command, IP: r.RemoteAddr, OK: true})
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func getSMTPHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg, err := p.GetSMTPConfig(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, cfg)
	}
}

func setSMTPHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var cfg storage.SMTPConfig
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		if err := p.SetSMTPConfig(r.Context(), cfg); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func testSMTPHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := p.SendTestEmail(r.Context()); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func execHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		role, _ := r.Context().Value(ctxRole).(string)
		if role != "admin" {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "admin only"})
			return
		}
		var req struct {
			Command string `json:"command"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Command == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "command required"})
			return
		}
		result, err := p.Exec(r.Context(), req.Command)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, result)
	}
}

func diskSpinStateHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		if strings.ContainsAny(name, " /;|&$`\\\"'") {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid disk name"})
			return
		}
		state, err := p.DiskSpinState(r.Context(), "/dev/"+name)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"state": state})
	}
}

func pingHostHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Host  string `json:"host"`
			Count int    `json:"count"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Host == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "host required"})
			return
		}
		if req.Count == 0 {
			req.Count = 4
		}
		result, err := p.PingHost(r.Context(), req.Host, req.Count)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, result)
	}
}

func getDiskAPMHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		if strings.ContainsAny(name, " /;|&$`\\\"'") {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid disk name"})
			return
		}
		level, err := p.GetDiskAPM(r.Context(), "/dev/"+name)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]int{"level": level})
	}
}

func setDiskAPMHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		if strings.ContainsAny(name, " /;|&$`\\\"'") {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid disk name"})
			return
		}
		var req struct {
			Level int `json:"level"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
			return
		}
		if err := p.SetDiskAPM(r.Context(), "/dev/"+name, req.Level); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func resolveHostnameHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := r.URL.Query().Get("ip")
		if ip == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "ip required"})
			return
		}
		hostname, err := p.ResolveHostname(r.Context(), ip)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"hostname": hostname})
	}
}

func killProcessHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		pidStr := chi.URLParam(r, "pid")
		pid, err := strconv.Atoi(pidStr)
		if err != nil || pid <= 1 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid pid"})
			return
		}
		var req struct {
			Signal int `json:"signal"`
		}
		json.NewDecoder(r.Body).Decode(&req) //nolint:errcheck
		if req.Signal == 0 {
			req.Signal = 15
		}
		if err := p.KillProcess(r.Context(), pid, req.Signal); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func entropyHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		entropy, err := p.SystemEntropy(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]int{"entropy": entropy})
	}
}

func changeEncKeyHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		var req struct {
			Passphrase string `json:"passphrase"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Passphrase == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "passphrase required"})
			return
		}
		if err := p.ChangeEncryptionKey(r.Context(), name, req.Passphrase); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func journalExportHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		text, err := p.JournalExport(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="kilasos-journal.log"`)
		w.Write([]byte(text)) //nolint:errcheck
	}
}

func dockerDaemonConfigHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg, err := p.DockerDaemonConfig(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, cfg)
	}
}

func setDockerDaemonConfigHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) { return }
		var cfg map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		if err := p.SetDockerDaemonConfig(r.Context(), cfg); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func smartHistoryHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		if strings.ContainsAny(name, " /;|&$`\\\"'") {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid disk name"})
			return
		}
		history, err := p.SmartTestHistory(r.Context(), "/dev/"+name)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, history)
	}
}

func userQuotasHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		dataset := chi.URLParam(r, "name")
		quotas, err := p.UserQuotas(r.Context(), dataset)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, quotas)
	}
}

func setUserQuotaHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		dataset := chi.URLParam(r, "name")
		user := chi.URLParam(r, "user")
		var req struct {
			QuotaBytes int64 `json:"quota_bytes"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
			return
		}
		if err := p.SetUserQuota(r.Context(), dataset, user, req.QuotaBytes); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func nfsExportsHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		exports, err := p.NFSExports(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, exports)
	}
}

func addNFSExportHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Path    string `json:"path"`
			Clients string `json:"clients"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Path == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "path required"})
			return
		}
		if req.Clients == "" {
			req.Clients = "*(rw,sync,no_subtree_check)"
		}
		if err := p.AddNFSExport(r.Context(), req.Path, req.Clients); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func deleteNFSExportHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Path string `json:"path"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Path == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "path required"})
			return
		}
		if err := p.DeleteNFSExport(r.Context(), req.Path); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func getAlertRulesHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rules, err := p.GetAlertRules(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, rules)
	}
}

func setAlertRulesHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var rules []storage.AlertRule
		if err := json.NewDecoder(r.Body).Decode(&rules); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
			return
		}
		if err := p.SetAlertRules(r.Context(), rules); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func updateContainerLimitsHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) { return }
		id := chi.URLParam(r, "id")
		var req struct {
			MemBytes   int64   `json:"mem_bytes"`
			CPUPercent float64 `json:"cpu_percent"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
			return
		}
		if err := p.UpdateContainerLimits(r.Context(), id, req.MemBytes, req.CPUPercent); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func setSharePermsHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		var req struct {
			Owner string `json:"owner"`
			Group string `json:"group"`
			Mode  uint32 `json:"mode"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
			return
		}
		if err := p.SetSharePerms(r.Context(), name, req.Owner, req.Group, req.Mode); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func auditLogExportHandler(auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		entries := auditLog.Recent(1000)
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="kilasos-audit.csv"`)
		fmt.Fprintf(w, "time,user,action,detail,ip,ok\n")
		for _, e := range entries {
			fmt.Fprintf(w, "%s,%s,%s,%s,%s,%v\n",
				e.Time.UTC().Format("2006-01-02T15:04:05Z"),
				csvEscape(e.User), csvEscape(e.Action), csvEscape(e.Detail), csvEscape(e.IP), e.OK)
		}
	}
}

func csvEscape(s string) string {
	if strings.ContainsAny(s, ",\"\n\r") {
		return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
	}
	return s
}

func bootLogHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		n := 200
		if v := r.URL.Query().Get("n"); v != "" {
			if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 && parsed <= 2000 {
				n = parsed
			}
		}
		out, err := exec.CommandContext(r.Context(), "journalctl", "-b", "-n", strconv.Itoa(n), "--no-pager", "-o", "short-precise").Output()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"log": string(out)})
	}
}

func allJobsHandler(replicator zfssend.Replicator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, replicator.AllJobs())
	}
}

func tailscaleStatusHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ts, err := p.TailscaleStatus(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, ts)
	}
}

func composeProjectsHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		projects, err := p.ComposeProjects(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, projects)
	}
}

func composeActionHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) { return }
		var req struct {
			Dir    string `json:"dir"`
			Action string `json:"action"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Dir == "" || req.Action == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "dir and action required"})
			return
		}
		if err := p.ComposeAction(r.Context(), req.Dir, req.Action); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func upsStatusHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		info, err := p.UPSStatus(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, info)
	}
}

func setIfaceStateHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		var req struct {
			Up bool `json:"up"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
			return
		}
		if err := p.SetInterfaceState(r.Context(), name, req.Up); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func fanSpeedsHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fans, err := p.FanSpeeds(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, fans)
	}
}

func routeTableHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		routes, err := p.RouteTable(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, routes)
	}
}

func timeStatusHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		info, err := p.TimeStatus(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, info)
	}
}

func getHostnameHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name, err := p.GetHostname(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"hostname": name})
	}
}

func setHostnameHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Hostname string `json:"hostname"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Hostname == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "hostname required"})
			return
		}
		if err := p.SetHostname(r.Context(), req.Hostname); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func wireguardStatusHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ifaces, err := p.WireguardStatus(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, ifaces)
	}
}

func mdRaidStatusHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		status, err := p.MDRaidStatus(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": status})
	}
}

func smbSessionsHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sessions, err := p.SMBSessions(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, sessions)
	}
}

func cpuTemperaturesHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		temps, err := p.CPUTemperatures(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, temps)
	}
}

func ipTablesHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rules, err := p.IPTablesRules(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"rules": rules})
	}
}

func triggerSMARTTestHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		var req struct {
			TestType string `json:"test_type"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.TestType == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "test_type required"})
			return
		}
		if err := p.TriggerSMARTTest(r.Context(), name, req.TestType); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func dockerPruneHandler(p storage.Provider, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) { return }
		caller, _ := r.Context().Value(ctxUsername).(string)
		var req struct {
			Volumes bool `json:"volumes"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		out, err := p.DockerPrune(r.Context(), req.Volumes)
		if err != nil {
			auditLog.LogEnriched(audit.Entry{User: caller, Action: "docker-prune", Detail: err.Error(), IP: r.RemoteAddr, OK: false})
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		auditLog.LogEnriched(audit.Entry{User: caller, Action: "docker-prune", Detail: fmt.Sprintf("volumes=%v", req.Volumes), IP: r.RemoteAddr, OK: true})
		writeJSON(w, http.StatusOK, map[string]string{"output": out})
	}
}

func usbDevicesHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		devices, err := p.USBDevices(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, devices)
	}
}

func pciDevicesHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		devices, err := p.PCIDevices(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, devices)
	}
}

func loadAveragesHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		la, err := p.LoadAverages(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, la)
	}
}

func swapInfoHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		entries, err := p.SwapInfo(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, entries)
	}
}

func connectionSummaryHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s, err := p.ConnectionSummary(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"summary": s})
	}
}

func containerEnvHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		env, err := p.ContainerEnv(r.Context(), id)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, env)
	}
}

func diskPartitionsHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		entries, err := p.DiskPartitions(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, entries)
	}
}

func getSysctlHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key := r.URL.Query().Get("key")
		if key == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "key required"})
			return
		}
		val, err := p.GetSysctl(r.Context(), key)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"key": key, "value": val})
	}
}

func setSysctlHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Key   string `json:"key"`
			Value string `json:"value"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Key == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "key and value required"})
			return
		}
		if err := p.SetSysctl(r.Context(), req.Key, req.Value); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func zfsPoolTrimHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		if err := p.ZFSPoolTrim(r.Context(), name); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func whoLoggedInHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		out, err := p.WhoLoggedIn(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"output": out})
	}
}

func getACLHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Query().Get("path")
		if path == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "path required"})
			return
		}
		out, err := p.GetACL(r.Context(), path)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"acl": out})
	}
}

func setACLHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Path string `json:"path"`
			Spec string `json:"spec"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Path == "" || req.Spec == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "path and spec required"})
			return
		}
		if err := p.SetACL(r.Context(), req.Path, req.Spec); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func setRestartPolicyHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) { return }
		id := chi.URLParam(r, "id")
		var req struct {
			Policy string `json:"policy"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Policy == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "policy required"})
			return
		}
		if err := p.SetContainerRestartPolicy(r.Context(), id, req.Policy); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func fail2banHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		info, err := p.Fail2BanStatus(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, info)
	}
}

func serverCertHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		info, err := p.GetServerCertificate(r.Context())
		if err != nil {
			status := http.StatusInternalServerError
			if strings.Contains(err.Error(), "no server certificate found") {
				status = http.StatusNotFound
			}
			writeJSON(w, status, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, info)
	}
}

func destroyDatasetHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		pool := chi.URLParam(r, "name")
		ds := chi.URLParam(r, "ds")
		var req struct {
			Recursive bool `json:"recursive"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		if err := p.DestroyDatasetRecursive(r.Context(), pool, ds, req.Recursive); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func getMOTDHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		content, err := p.GetMOTD(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"content": content})
	}
}

func setMOTDHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Content string `json:"content"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "content required"})
			return
		}
		if err := p.SetMOTD(r.Context(), req.Content); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func getCronTabHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.URL.Query().Get("user")
		content, err := p.GetCronTab(r.Context(), user)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"content": content, "user": user})
	}
}

func setCronTabHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			User    string `json:"user"`
			Content string `json:"content"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "content required"})
			return
		}
		if err := p.SetCronTab(r.Context(), req.User, req.Content); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func netstatHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		entries, err := p.NetstatActive(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, entries)
	}
}

func testPortHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Host string `json:"host"`
			Port int    `json:"port"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Host == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "host and port required"})
			return
		}
		open, err := p.TestPort(r.Context(), req.Host, req.Port)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"open": open})
	}
}

func zfsHoldsHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		tags, err := p.ZFSHolds(r.Context(), name)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, tags)
	}
}

func addZFSHoldHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		var req struct {
			Tag string `json:"tag"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Tag == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "tag required"})
			return
		}
		if err := p.ZFSAddHold(r.Context(), name, req.Tag); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func releaseZFSHoldHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		tag := chi.URLParam(r, "tag")
		if err := p.ZFSReleaseHold(r.Context(), name, tag); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func failedUnitsHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		units, err := p.FailedSystemdUnits(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, units)
	}
}

func nfsMountsHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		mounts, err := p.NFSActiveMounts(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, mounts)
	}
}

func readonlyMountsHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		mounts, err := p.GetReadOnlyMounts(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, mounts)
	}
}

func zfsRenameHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			OldName string `json:"old_name"`
			NewName string `json:"new_name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.OldName == "" || req.NewName == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "old_name and new_name required"})
			return
		}
		if err := p.ZFSRenameDataset(r.Context(), req.OldName, req.NewName); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func logRotateHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		out, err := p.LogRotateStatus(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": out})
	}
}

func containerHealthHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		info, err := p.GetContainerHealth(r.Context(), id)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, info)
	}
}

func mdnsServicesHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		svcs, err := p.MDNSServices(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, svcs)
	}
}

func kernelParamHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key := r.URL.Query().Get("key")
		if key == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "key required"})
			return
		}
		val, err := p.GetKernelParam(r.Context(), key)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"key": key, "value": val})
	}
}

func pauseContainerHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) { return }
		id := chi.URLParam(r, "id")
		if err := p.PauseContainer(r.Context(), id); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func unpauseContainerHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) { return }
		id := chi.URLParam(r, "id")
		if err := p.UnpauseContainer(r.Context(), id); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func restartContainerHandler(p storage.Provider, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) { return }
		id := chi.URLParam(r, "id")
		caller, _ := r.Context().Value(ctxUsername).(string)
		if err := p.RestartContainer(r.Context(), id); err != nil {
			auditLog.LogEnriched(audit.Entry{User: caller, Action: "container-restart", Resource: id, Detail: err.Error(), IP: r.RemoteAddr, OK: false})
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		auditLog.LogEnriched(audit.Entry{User: caller, Action: "container-restart", Resource: id, IP: r.RemoteAddr, OK: true})
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func zfsBookmarksHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		dataset := r.URL.Query().Get("dataset")
		if dataset == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "dataset required"})
			return
		}
		bms, err := p.ZFSBookmarks(r.Context(), dataset)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, bms)
	}
}

func createZFSBookmarkHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Snapshot string `json:"snapshot"`
			Bookmark string `json:"bookmark"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Snapshot == "" || req.Bookmark == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "snapshot and bookmark required"})
			return
		}
		if err := p.CreateZFSBookmark(r.Context(), req.Snapshot, req.Bookmark); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func runlevelHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rl, err := p.GetCurrentRunlevel(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"runlevel": rl})
	}
}

func uptimeHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		up, err := p.GetUptime(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, up)
	}
}

func netmaskHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		entries, err := p.NetMaskInfo(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, entries)
	}
}

func batteryHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		info, err := p.BatteryStatus(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, info)
	}
}

func localeHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		info, err := p.GetSystemLocale(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, info)
	}
}

func setTimezoneHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Timezone string `json:"timezone"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Timezone == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "timezone required"})
			return
		}
		if err := p.SetTimezone(r.Context(), req.Timezone); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func listTimezonesHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		zones, err := p.ListTimezones(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, zones)
	}
}

func osReleaseHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		info, err := p.OSRelease(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, info)
	}
}

func kernelModulesHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		mods, err := p.KernelModules(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, mods)
	}
}

func ipRulesHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		out, err := p.IPRules(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"rules": out})
	}
}

func nicStatsHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		stats, err := p.NICStats(r.Context(), name)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, stats)
	}
}

func setMTUHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		var req struct {
			MTU int `json:"mtu"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.MTU == 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "mtu required"})
			return
		}
		if err := p.SetMTU(r.Context(), name, req.MTU); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func systemdUnitDetailHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		d, err := p.SystemdUnitDetail(r.Context(), name)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, d)
	}
}

func startSystemdHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		if err := p.StartSystemdUnit(r.Context(), name); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func stopSystemdHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		if err := p.StopSystemdUnit(r.Context(), name); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func enableSystemdHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		if err := p.EnableSystemdUnit(r.Context(), name); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func disableSystemdHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		if err := p.DisableSystemdUnit(r.Context(), name); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func hostHardwareHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		info, err := p.GetSysHostInfo(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, info)
	}
}

func journalUnitsHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		units, err := p.JournalUnits(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, units)
	}
}

func journalForUnitHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		unit := chi.URLParam(r, "unit")
		lines, _ := strconv.Atoi(r.URL.Query().Get("lines"))
		out, err := p.GetJournalForUnit(r.Context(), unit, lines)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"output": out})
	}
}

func zfsFeaturesHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		pool := r.URL.Query().Get("pool")
		if pool == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "pool required"})
			return
		}
		f, err := p.ZFSFeatures(r.Context(), pool)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, f)
	}
}

func ip6tablesHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		out, err := p.IP6Tables(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"rules": out})
	}
}

func conntrackCountHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := p.ConntrackCount(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]int{"count": c})
	}
}

func dmesgHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		lines, _ := strconv.Atoi(r.URL.Query().Get("lines"))
		out, err := p.Dmesg(r.Context(), lines)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"output": out})
	}
}

func cmdlineHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		out, err := p.KernelCmdline(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"cmdline": out})
	}
}

func nicOffloadsHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		offloads, err := p.NICOffloads(r.Context(), name)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, offloads)
	}
}

func cpuDetailHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		d, err := p.GetCPUInfoDetailed(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, d)
	}
}

func listMountsHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		mounts, err := p.ListMounts(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, mounts)
	}
}

func conntrackHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		max, _ := strconv.Atoi(r.URL.Query().Get("max"))
		entries, err := p.NetlinkConntrack(r.Context(), max)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, entries)
	}
}

func iowaitHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		v, err := p.IOWait(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]float64{"iowait_pct": v})
	}
}

func zfsImportableHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		pools, err := p.ZFSPoolImportable(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, pools)
	}
}

func installedKernelsHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		k, err := p.ListInstalledKernels(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, k)
	}
}

func currentKernelHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		k, err := p.GetCurrentKernel(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"kernel": k})
	}
}

func speedtestHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Server string `json:"server"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		res, err := p.NetworkSpeedTest(r.Context(), req.Server)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, res)
	}
}

func diskTempsHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		t, err := p.GetDiskTemperatures(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, t)
	}
}

func buildInfoHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		info, err := p.SystemBuildInfo(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, info)
	}
}

func vmsHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		v, err := p.GetVMSizes(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, v)
	}
}

func sudoersHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s, err := p.GetSudoers(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"content": s})
	}
}

func sshdConfigHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s, err := p.GetSSHDConfig(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"content": s})
	}
}

func recommendationsHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		recs, err := p.SystemRecommendations(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, recs)
	}
}

func maxOpenFilesHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		v, err := p.GetMaxOpenFiles(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]int{"max_open_files": v})
	}
}

func tcpCongestionHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		algo, err := p.GetTCPCongestionAlgo(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"algorithm": algo})
	}
}

func diskSerialHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		serial, err := p.GetDiskSerial(r.Context(), name)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"serial": serial})
	}
}

func interfaceFeaturesHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		f, err := p.NetworkInterfaceFeatures(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, f)
	}
}

func getDatasetPropertyHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		dataset := r.URL.Query().Get("dataset")
		prop := r.URL.Query().Get("prop")
		if dataset == "" || prop == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "dataset and prop required"})
			return
		}
		v, err := p.GetZFSDatasetProperty(r.Context(), dataset, prop)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"value": v})
	}
}

func setDatasetPropertyHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Dataset string `json:"dataset"`
			Prop    string `json:"prop"`
			Value   string `json:"value"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Dataset == "" || req.Prop == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "dataset, prop, value required"})
			return
		}
		if err := p.SetZFSDatasetProperty(r.Context(), req.Dataset, req.Prop, req.Value); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func openPortsHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ports, err := p.OpenPortsAudit(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, ports)
	}
}

func oomEventsHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		lines, _ := strconv.Atoi(r.URL.Query().Get("lines"))
		events, err := p.OOMKillerLog(r.Context(), lines)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, events)
	}
}

func zramHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		devs, err := p.ZRAMInfo(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, devs)
	}
}

func getNTPServersHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s, err := p.GetNTPServers(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, s)
	}
}

func setNTPServersHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Servers []string `json:"servers"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.Servers) == 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "servers required"})
			return
		}
		if err := p.SetNTPServers(r.Context(), req.Servers); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func timeSyncStatusHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s, err := p.GetTimeSyncStatus(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, s)
	}
}

func ipv6StatusHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s, err := p.GetIPv6Status(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, s)
	}
}

func scrubProgressHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		pool := chi.URLParam(r, "name")
		prog, err := p.ZFSScrubProgress(r.Context(), pool)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, prog)
	}
}

func listLoginsHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		count, _ := strconv.Atoi(r.URL.Query().Get("count"))
		logins, err := p.ListLogins(r.Context(), count)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, logins)
	}
}

func tzOffsetHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		off, err := p.GetCurrentTimezoneOffset(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"offset": off})
	}
}

func systemBootsHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		boots, err := p.GetSystemBoots(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, boots)
	}
}

func smartAttributesHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		attrs, err := p.GetSMARTAttributes(r.Context(), name)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, attrs)
	}
}

func dedupStatsHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		pool := chi.URLParam(r, "name")
		stats, err := p.GetZFSDedupStats(r.Context(), pool)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, stats)
	}
}

func nvmeStatsHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		info, err := p.GetNVMeStats(r.Context(), name)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, info)
	}
}

func gpusHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		gpus, err := p.GetGPUInfo(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, gpus)
	}
}

func arpFlushHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := p.FlushARPCache(r.Context()); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func eccErrorsHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		events, err := p.GetECCErrors(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, events)
	}
}

func memFragHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		info, err := p.GetMemFragmentation(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, info)
	}
}

func topBandwidthHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		max, _ := strconv.Atoi(r.URL.Query().Get("max"))
		ips, err := p.GetTopBandwidthIPs(r.Context(), max)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, ips)
	}
}

func swapPressureHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		info, err := p.GetSwapPressure(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, info)
	}
}

// ─── M376-M379: OIDC handlers ────────────────────────────────────────────────

func oidcLoginHandler(m auth.OIDCAuthenticator, rl *loginRateLimiter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip, _, _ := net.SplitHostPort(r.RemoteAddr)
		if !rl.allow(ip) {
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many requests"})
			return
		}
		m.BeginLogin(w, r)
	}
}

func oidcCallbackHandler(m auth.OIDCAuthenticator, rl *loginRateLimiter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip, _, _ := net.SplitHostPort(r.RemoteAddr)
		if !rl.allow(ip) {
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many requests"})
			return
		}
		m.HandleCallback(w, r)
	}
}

func getOIDCConfigHandler(m auth.OIDCAuthenticator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		writeJSON(w, http.StatusOK, m.GetConfig())
	}
}

func setOIDCConfigHandler(m auth.OIDCAuthenticator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		var cfg auth.OIDCConfig
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid config"})
			return
		}
		if err := m.SetConfig(cfg); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

// ─── M380-M381: LDAP handlers ────────────────────────────────────────────────

func ldapLoginHandler(m auth.LDAPAuthenticator, users *auth.UserStore, auditLog *audit.Logger, rl *loginRateLimiter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rip, _, _ := net.SplitHostPort(r.RemoteAddr)
		if !rl.allow(rip) {
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many requests"})
			return
		}
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Username == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "username/password required"})
			return
		}
		if !m.Enabled() {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "LDAP not configured"})
			return
		}
		ip := r.RemoteAddr
		role, err := m.Authenticate(req.Username, req.Password)
		if err != nil {
			auditLog.Log(req.Username, "ldap-login", err.Error(), ip, false)
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
			return
		}
		token, err := users.IssueTokenWithMeta(req.Username, "ldap", ip, r.Header.Get("User-Agent"))
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		auditLog.Log(req.Username, "ldap-login", "success", ip, true)
		writeJSON(w, http.StatusOK, map[string]string{"token": token, "username": req.Username, "role": role})
	}
}

func getLDAPConfigHandler(m auth.LDAPAuthenticator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		writeJSON(w, http.StatusOK, m.GetConfig())
	}
}

func setLDAPConfigHandler(m auth.LDAPAuthenticator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		var cfg auth.LDAPConfig
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid config"})
			return
		}
		if err := m.SetConfig(cfg); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func ldapTestHandler(m auth.LDAPAuthenticator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		if err := m.TestConnection(); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func ldapSyncHandler(m auth.LDAPAuthenticator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		provisioned, updated, err := m.SyncUsers()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]int{"provisioned": provisioned, "updated": updated})
	}
}

// ─── M382: SMB AD Join handlers ──────────────────────────────────────────────

func smbADStatusHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		st, err := p.SMBADStatus(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, st)
	}
}

func smbADJoinHandler(p storage.Provider, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Realm    string `json:"realm"`
			Admin    string `json:"admin"`
			Password string `json:"password"`
			OUPath   string `json:"ou_path"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Realm == "" || req.Admin == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "realm and admin required"})
			return
		}
		username, _ := r.Context().Value(ctxUsername).(string)
		if err := p.SMBADJoin(r.Context(), req.Realm, req.Admin, req.Password, req.OUPath); err != nil {
			auditLog.LogEnriched(audit.Entry{User: username, Action: "smb-ad-join", Detail: err.Error(), IP: r.RemoteAddr, OK: false, Resource: req.Realm})
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		auditLog.LogEnriched(audit.Entry{User: username, Action: "smb-ad-join", Detail: "joined " + req.Realm, IP: r.RemoteAddr, OK: true, Resource: req.Realm})
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func smbADLeaveHandler(p storage.Provider, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Admin    string `json:"admin"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Admin == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "admin required"})
			return
		}
		username, _ := r.Context().Value(ctxUsername).(string)
		if err := p.SMBADLeave(r.Context(), req.Admin, req.Password); err != nil {
			auditLog.LogEnriched(audit.Entry{User: username, Action: "smb-ad-leave", Detail: err.Error(), IP: r.RemoteAddr, OK: false})
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		auditLog.LogEnriched(audit.Entry{User: username, Action: "smb-ad-leave", Detail: "left domain", IP: r.RemoteAddr, OK: true})
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

// ─── M383: Session management handlers ───────────────────────────────────────

func listSessionsHandler(users *auth.UserStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		role, _ := r.Context().Value(ctxRole).(string)
		caller, _ := r.Context().Value(ctxUsername).(string)
		all := users.ListSessions()
		// Non-admin: only see own sessions
		if role != auth.RoleAdmin {
			filtered := all[:0]
			for _, s := range all {
				if s.Username == caller {
					filtered = append(filtered, s)
				}
			}
			all = filtered
		}
		writeJSON(w, http.StatusOK, all)
	}
}

func revokeSessionHandler(users *auth.UserStore, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := chi.URLParam(r, "token")
		username, _ := r.Context().Value(ctxUsername).(string)
		if err := users.RevokeSessionByPrefix(token); err != nil {
			auditLog.LogEnriched(audit.Entry{User: username, Action: "session-revoke", Detail: err.Error(), IP: r.RemoteAddr, OK: false})
			writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
			return
		}
		auditLog.LogEnriched(audit.Entry{User: username, Action: "session-revoke", Detail: "prefix=" + token, IP: r.RemoteAddr, OK: true})
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func revokeAllSessionsHandler(users *auth.UserStore, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Username string `json:"username"`
		}
		json.NewDecoder(r.Body).Decode(&req) //nolint:errcheck
		caller, _ := r.Context().Value(ctxUsername).(string)
		role, _ := r.Context().Value(ctxRole).(string)
		target := req.Username
		if target == "" {
			target = caller
		}
		if target != caller && role != auth.RoleAdmin {
			auditLog.LogEnriched(audit.Entry{User: caller, Action: "session-revoke-all", Detail: "forbidden target=" + target, IP: r.RemoteAddr, OK: false})
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "admin required to revoke other users"})
			return
		}
		count := users.RevokeAllSessionsForUser(target)
		auditLog.LogEnriched(audit.Entry{User: caller, Action: "session-revoke-all", Detail: fmt.Sprintf("target=%s count=%d", target, count), IP: r.RemoteAddr, OK: true})
		writeJSON(w, http.StatusOK, map[string]int{"revoked": count})
	}
}

// ─── M384: API key handlers ──────────────────────────────────────────────────

func listAPIKeysHandler(apiKeys *auth.APIKeyStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		role, _ := r.Context().Value(ctxRole).(string)
		caller, _ := r.Context().Value(ctxUsername).(string)
		// Admins see all; users see own
		username := caller
		if role == auth.RoleAdmin {
			username = r.URL.Query().Get("user") // empty = all
		}
		writeJSON(w, http.StatusOK, apiKeys.List(username))
	}
}

func createAPIKeyHandler(apiKeys *auth.APIKeyStore, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Username string `json:"username"`
			Label    string `json:"label"`
			TTLDays  int    `json:"ttl_days"`
		}
		json.NewDecoder(r.Body).Decode(&req) //nolint:errcheck
		caller, _ := r.Context().Value(ctxUsername).(string)
		role, _ := r.Context().Value(ctxRole).(string)
		target := req.Username
		if target == "" {
			target = caller
		}
		if target != caller && role != auth.RoleAdmin {
			auditLog.LogEnriched(audit.Entry{User: caller, Action: "apikey-create", Detail: "forbidden for=" + target, IP: r.RemoteAddr, OK: false})
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "admin required to create keys for other users"})
			return
		}
		if req.Label == "" {
			req.Label = "API key"
		}
		var ttl time.Duration
		if req.TTLDays > 0 {
			ttl = time.Duration(req.TTLDays) * 24 * time.Hour
		}
		id, fullKey, err := apiKeys.Create(target, req.Label, ttl)
		if err != nil {
			auditLog.LogEnriched(audit.Entry{User: caller, Action: "apikey-create", Detail: err.Error(), IP: r.RemoteAddr, OK: false})
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		auditLog.LogEnriched(audit.Entry{User: caller, Action: "apikey-create", Detail: "for=" + target + " label=" + req.Label, IP: r.RemoteAddr, OK: true, Resource: id})
		writeJSON(w, http.StatusOK, map[string]string{"id": id, "key": fullKey, "label": req.Label})
	}
}

func deleteAPIKeyHandler(apiKeys *auth.APIKeyStore, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		caller, _ := r.Context().Value(ctxUsername).(string)
		// Anyone may revoke a key whose ID they know — no leakage since IDs aren't enumerable for non-admins.
		if err := apiKeys.Delete(id); err != nil {
			auditLog.LogEnriched(audit.Entry{User: caller, Action: "apikey-delete", Detail: err.Error(), IP: r.RemoteAddr, OK: false, Resource: id})
			writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
			return
		}
		auditLog.LogEnriched(audit.Entry{User: caller, Action: "apikey-delete", IP: r.RemoteAddr, OK: true, Resource: id})
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

// ─── M386: Brute-force handlers ──────────────────────────────────────────────

func bruteForceStatsHandler(bf *auth.BruteForceTracker) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		max, win, ban := bf.GetThresholds()
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"stats":          bf.Stats(),
			"max_attempts":   max,
			"window_minutes": win,
			"ban_minutes":    ban,
		})
	}
}

func bruteForceUnbanHandler(bf *auth.BruteForceTracker, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		var req struct {
			IP string `json:"ip"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.IP == "" {
			caller, _ := r.Context().Value(ctxUsername).(string)
			auditLog.LogEnriched(audit.Entry{User: caller, Action: "bf-unban", Detail: "ip required", IP: r.RemoteAddr, OK: false})
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "ip required"})
			return
		}
		bf.UnbanIP(req.IP)
		caller, _ := r.Context().Value(ctxUsername).(string)
		auditLog.LogEnriched(audit.Entry{User: caller, Action: "bf-unban", Resource: req.IP, IP: r.RemoteAddr, OK: true})
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func bruteForceThresholdsHandler(bf *auth.BruteForceTracker, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		var req struct {
			MaxAttempts   int `json:"max_attempts"`
			WindowMinutes int `json:"window_minutes"`
			BanMinutes    int `json:"ban_minutes"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			caller, _ := r.Context().Value(ctxUsername).(string)
			auditLog.LogEnriched(audit.Entry{User: caller, Action: "bf-thresholds-update", Detail: err.Error(), IP: r.RemoteAddr, OK: false})
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		bf.SetThresholds(req.MaxAttempts, req.WindowMinutes, req.BanMinutes)
		caller, _ := r.Context().Value(ctxUsername).(string)
		auditLog.LogEnriched(audit.Entry{User: caller, Action: "bf-thresholds-update", IP: r.RemoteAddr, OK: true})
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

// ─── M387: Password policy handlers ──────────────────────────────────────────

func getPasswordPolicyHandler(p *auth.PasswordPolicy) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, p.Get())
	}
}

func setPasswordPolicyHandler(p *auth.PasswordPolicy, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		caller, _ := r.Context().Value(ctxUsername).(string)
		var cfg auth.PasswordPolicyConfig
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			auditLog.LogEnriched(audit.Entry{User: caller, Action: "password-policy-update", Detail: err.Error(), IP: r.RemoteAddr, OK: false})
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		if err := p.Set(cfg); err != nil {
			auditLog.LogEnriched(audit.Entry{User: caller, Action: "password-policy-update", Detail: err.Error(), IP: r.RemoteAddr, OK: false})
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		auditLog.LogEnriched(audit.Entry{User: caller, Action: "password-policy-update", IP: r.RemoteAddr, OK: true})
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func changePasswordHandler(users *auth.UserStore, policy *auth.PasswordPolicy, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			OldPassword string `json:"old_password"`
			NewPassword string `json:"new_password"`
		}
		caller, _ := r.Context().Value(ctxUsername).(string)
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			auditLog.LogEnriched(audit.Entry{User: caller, Action: "password-change", Detail: err.Error(), IP: r.RemoteAddr, OK: false})
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		if err := policy.Validate(req.NewPassword); err != nil {
			auditLog.LogEnriched(audit.Entry{User: caller, Action: "password-change", Detail: "policy:" + err.Error(), IP: r.RemoteAddr, OK: false})
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if err := users.ChangePassword(caller, req.OldPassword, req.NewPassword); err != nil {
			auditLog.LogEnriched(audit.Entry{User: caller, Action: "password-change", Detail: err.Error(), IP: r.RemoteAddr, OK: false})
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		auditLog.LogEnriched(audit.Entry{User: caller, Action: "password-change", IP: r.RemoteAddr, OK: true})
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

// ─── M388: TOTP backup code handlers ─────────────────────────────────────────

func generateBackupCodesHandler(users *auth.UserStore, policy *auth.PasswordPolicy, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		caller, _ := r.Context().Value(ctxUsername).(string)
		codes, err := policy.GenerateBackupCodes()
		if err != nil {
			auditLog.LogEnriched(audit.Entry{User: caller, Action: "totp-backup-codes-generate", Detail: err.Error(), IP: r.RemoteAddr, OK: false})
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		if err := users.SetBackupCodes(caller, codes); err != nil {
			auditLog.LogEnriched(audit.Entry{User: caller, Action: "totp-backup-codes-generate", Detail: err.Error(), IP: r.RemoteAddr, OK: false})
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		auditLog.LogEnriched(audit.Entry{User: caller, Action: "totp-backup-codes-generate", IP: r.RemoteAddr, OK: true})
		writeJSON(w, http.StatusOK, map[string]interface{}{"codes": codes})
	}
}

func backupCodeCountHandler(users *auth.UserStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		caller, _ := r.Context().Value(ctxUsername).(string)
		writeJSON(w, http.StatusOK, map[string]int{"count": users.BackupCodeCount(caller)})
	}
}

// ─── M389: WebAuthn handlers ─────────────────────────────────────────────────

func waBeginRegisterHandler(m *auth.WebAuthnManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if m == nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "WebAuthn not configured"})
			return
		}
		caller, _ := r.Context().Value(ctxUsername).(string)
		opts, sessionID, err := m.BeginRegistration(caller)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"options": opts, "session_id": sessionID})
	}
}

func waFinishRegisterHandler(m *auth.WebAuthnManager, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if m == nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "WebAuthn not configured"})
			return
		}
		caller, _ := r.Context().Value(ctxUsername).(string)
		sessionID := r.URL.Query().Get("session_id")
		label := r.URL.Query().Get("label")
		if label == "" {
			label = "passkey"
		}
		if err := m.FinishRegistration(caller, sessionID, label, r); err != nil {
			auditLog.LogEnriched(audit.Entry{User: caller, Action: "webauthn-register", Detail: err.Error(), IP: r.RemoteAddr, OK: false})
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		auditLog.LogEnriched(audit.Entry{User: caller, Action: "webauthn-register", Detail: label, IP: r.RemoteAddr, OK: true})
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func waBeginLoginHandler(m *auth.WebAuthnManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if m == nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "WebAuthn not configured"})
			return
		}
		var req struct {
			Username string `json:"username"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Username == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "username required"})
			return
		}
		opts, sessionID, err := m.BeginLogin(req.Username)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"options": opts, "session_id": sessionID})
	}
}

func waFinishLoginHandler(m *auth.WebAuthnManager, users *auth.UserStore, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if m == nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "WebAuthn not configured"})
			return
		}
		username := r.URL.Query().Get("username")
		sessionID := r.URL.Query().Get("session_id")
		if err := m.FinishLogin(username, sessionID, r); err != nil {
			auditLog.LogEnriched(audit.Entry{User: username, Action: "webauthn-login", Detail: err.Error(), IP: r.RemoteAddr, OK: false})
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
			return
		}
		token, err := users.IssueTokenWithMeta(username, "webauthn", r.RemoteAddr, r.Header.Get("User-Agent"))
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		u, _ := users.GetUser(username)
		auditLog.LogEnriched(audit.Entry{User: username, Action: "webauthn-login", IP: r.RemoteAddr, OK: true})
		writeJSON(w, http.StatusOK, map[string]string{"token": token, "username": username, "role": u.Role})
	}
}

func waListCredsHandler(m *auth.WebAuthnManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if m == nil {
			writeJSON(w, http.StatusOK, []auth.WebAuthnCred{})
			return
		}
		caller, _ := r.Context().Value(ctxUsername).(string)
		writeJSON(w, http.StatusOK, m.ListCredentials(caller))
	}
}

func waDeleteCredHandler(m *auth.WebAuthnManager, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if m == nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "WebAuthn not configured"})
			return
		}
		caller, _ := r.Context().Value(ctxUsername).(string)
		credID := chi.URLParam(r, "id")
		if err := m.DeleteCredential(caller, credID); err != nil {
			auditLog.LogEnriched(audit.Entry{User: caller, Action: "webauthn-delete-cred", Detail: err.Error(), Resource: credID, IP: r.RemoteAddr, OK: false})
			writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
			return
		}
		auditLog.LogEnriched(audit.Entry{User: caller, Action: "webauthn-delete-cred", Resource: credID, IP: r.RemoteAddr, OK: true})
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

// ─── M390: Login customization handlers ──────────────────────────────────────

func loginCustomizationHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, auth.GetLoginCustomization())
	}
}

func setLoginCustomizationHandler(auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		caller, _ := r.Context().Value(ctxUsername).(string)
		var c auth.LoginCustomization
		if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
			auditLog.LogEnriched(audit.Entry{User: caller, Action: "login-customization-update", Detail: err.Error(), IP: r.RemoteAddr, OK: false})
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		if err := auth.SetLoginCustomization(c); err != nil {
			auditLog.LogEnriched(audit.Entry{User: caller, Action: "login-customization-update", Detail: err.Error(), IP: r.RemoteAddr, OK: false})
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		auditLog.LogEnriched(audit.Entry{User: caller, Action: "login-customization-update", IP: r.RemoteAddr, OK: true})
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}


// ╔═══════════════════════════════════════════════════════════════════════════╗
// ║ ── BATCH ANCHOR ZONES (handler functions) ──                              ║
// ║ Each batch appends ITS handler funcs in its own zone below.               ║
// ║ Routes go in the auth-group anchors above; handlers go here.              ║
// ╚═══════════════════════════════════════════════════════════════════════════╝

// ── BATCH-B (M316-M330): Monitoring & Alerting handlers ──

func prometheusMetricsHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		metrics, err := p.PrometheusMetrics(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte(metrics))
	}
}

func healthchecksPingHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		url := r.URL.Query().Get("url")
		if err := p.HealthchecksPing(r.Context(), url); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}

func notifyHandler(p storage.Provider, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		caller, _ := r.Context().Value(ctxUsername).(string)
		var req struct {
			Channel  string `json:"channel"`
			Event    string `json:"event"`
			Severity string `json:"severity"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			auditLog.LogEnriched(audit.Entry{User: caller, Action: "notify-send", Detail: "invalid-json", IP: r.RemoteAddr, OK: false})
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if err := p.Notify(r.Context(), req.Channel, req.Event, req.Severity); err != nil {
			auditLog.LogEnriched(audit.Entry{User: caller, Action: "notify-send", Resource: req.Channel, Detail: err.Error(), IP: r.RemoteAddr, OK: false})
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		auditLog.LogEnriched(audit.Entry{User: caller, Action: "notify-send", Resource: req.Channel, IP: r.RemoteAddr, OK: true})
	}
}

func notificationChannelsHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		chs, err := p.NotificationChannels(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, chs)
	}
}

func createNotificationChannelHandler(p storage.Provider, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		var ch storage.NotificationChannel
		if err := json.NewDecoder(r.Body).Decode(&ch); err != nil || ch.Name == "" {
			caller, _ := r.Context().Value(ctxUsername).(string)
			auditLog.LogEnriched(audit.Entry{User: caller, Action: "notification-channel-create", Detail: "name-required", IP: r.RemoteAddr, OK: false})
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name required"})
			return
		}
		_, err := p.CreateNotificationChannel(r.Context(), ch)
		if err != nil {
			caller, _ := r.Context().Value(ctxUsername).(string)
			auditLog.LogEnriched(audit.Entry{User: caller, Action: "notification-channel-create", Resource: ch.Name, Detail: err.Error(), IP: r.RemoteAddr, OK: false})
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		caller, _ := r.Context().Value(ctxUsername).(string)
		auditLog.LogEnriched(audit.Entry{User: caller, Action: "notification-channel-create", Resource: ch.Name + " " + ch.Type, IP: r.RemoteAddr, OK: true})
	}
}

func updateNotificationChannelHandler(p storage.Provider, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		name := chi.URLParam(r, "name")
		var ch storage.NotificationChannel
		if err := json.NewDecoder(r.Body).Decode(&ch); err != nil {
			caller, _ := r.Context().Value(ctxUsername).(string)
			auditLog.LogEnriched(audit.Entry{User: caller, Action: "notification-channel-update", Resource: name, Detail: "invalid-json", IP: r.RemoteAddr, OK: false})
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		_, err := p.UpdateNotificationChannel(r.Context(), name, ch)
		if err != nil {
			caller, _ := r.Context().Value(ctxUsername).(string)
			auditLog.LogEnriched(audit.Entry{User: caller, Action: "notification-channel-update", Resource: name, Detail: err.Error(), IP: r.RemoteAddr, OK: false})
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		caller, _ := r.Context().Value(ctxUsername).(string)
		auditLog.LogEnriched(audit.Entry{User: caller, Action: "notification-channel-update", Resource: name, IP: r.RemoteAddr, OK: true})
	}
}

func deleteNotificationChannelHandler(p storage.Provider, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		name := chi.URLParam(r, "name")
		if err := p.DeleteNotificationChannel(r.Context(), name); err != nil {
			caller, _ := r.Context().Value(ctxUsername).(string)
			auditLog.LogEnriched(audit.Entry{User: caller, Action: "notification-channel-delete", Resource: name, Detail: err.Error(), IP: r.RemoteAddr, OK: false})
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		caller, _ := r.Context().Value(ctxUsername).(string)
		auditLog.LogEnriched(audit.Entry{User: caller, Action: "notification-channel-delete", Resource: name, IP: r.RemoteAddr, OK: true})
	}
}

func monitorAlertRulesHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rules, err := p.MonitorAlertRules(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, rules)
	}
}

func createMonitorAlertRuleHandler(p storage.Provider, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		var rule storage.MonitorAlertRule
		if err := json.NewDecoder(r.Body).Decode(&rule); err != nil || rule.Name == "" {
			caller, _ := r.Context().Value(ctxUsername).(string)
			auditLog.LogEnriched(audit.Entry{User: caller, Action: "alert-rule-create", Detail: "name-required", IP: r.RemoteAddr, OK: false})
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name required"})
			return
		}
		_, err := p.CreateMonitorAlertRule(r.Context(), rule)
		if err != nil {
			caller, _ := r.Context().Value(ctxUsername).(string)
			auditLog.LogEnriched(audit.Entry{User: caller, Action: "alert-rule-create", Resource: rule.Name, Detail: err.Error(), IP: r.RemoteAddr, OK: false})
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		caller, _ := r.Context().Value(ctxUsername).(string)
		auditLog.LogEnriched(audit.Entry{User: caller, Action: "alert-rule-create", Resource: rule.Name + " " + rule.Metric, IP: r.RemoteAddr, OK: true})
	}
}

func updateMonitorAlertRuleHandler(p storage.Provider, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		name := chi.URLParam(r, "name")
		var rule storage.MonitorAlertRule
		if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
			caller, _ := r.Context().Value(ctxUsername).(string)
			auditLog.LogEnriched(audit.Entry{User: caller, Action: "alert-rule-update", Resource: name, Detail: "invalid-json", IP: r.RemoteAddr, OK: false})
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		_, err := p.UpdateMonitorAlertRule(r.Context(), name, rule)
		if err != nil {
			caller, _ := r.Context().Value(ctxUsername).(string)
			auditLog.LogEnriched(audit.Entry{User: caller, Action: "alert-rule-update", Resource: name, Detail: err.Error(), IP: r.RemoteAddr, OK: false})
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		caller, _ := r.Context().Value(ctxUsername).(string)
		auditLog.LogEnriched(audit.Entry{User: caller, Action: "alert-rule-update", Resource: name, IP: r.RemoteAddr, OK: true})
	}
}

func deleteMonitorAlertRuleHandler(p storage.Provider, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		name := chi.URLParam(r, "name")
		if err := p.DeleteMonitorAlertRule(r.Context(), name); err != nil {
			caller, _ := r.Context().Value(ctxUsername).(string)
			auditLog.LogEnriched(audit.Entry{User: caller, Action: "alert-rule-delete", Resource: name, Detail: err.Error(), IP: r.RemoteAddr, OK: false})
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		caller, _ := r.Context().Value(ctxUsername).(string)
		auditLog.LogEnriched(audit.Entry{User: caller, Action: "alert-rule-delete", Resource: name, IP: r.RemoteAddr, OK: true})
	}
}

func alertEventsHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		if limit <= 0 {
			limit = 100
		}
		events, err := p.AlertEvents(r.Context(), limit)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, events)
	}
}

func acknowledgeAlertHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		id := chi.URLParam(r, "id")
		if err := p.AcknowledgeAlert(r.Context(), id); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"acked": id})
	}
}

func silenceAlertHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		name := chi.URLParam(r, "name")
		hours, _ := strconv.Atoi(r.URL.Query().Get("hours"))
		if hours <= 0 {
			hours = 24
		}
		if err := p.SilenceAlert(r.Context(), name, hours); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"silenced": name, "hours": strconv.Itoa(hours)})
	}
}

func anomalyScoreHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		metric := r.URL.Query().Get("metric")
		window, _ := strconv.Atoi(r.URL.Query().Get("window"))
		if metric == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "metric required"})
			return
		}
		result, err := p.AnomalyScore(r.Context(), metric, window)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, result)
	}
}

func testNotificationHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		name := chi.URLParam(r, "name")
		if err := p.TestNotification(r.Context(), name); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"tested": name})
	}
}

// ── BATCH-C (M331-M345): Reverse Proxy & Tunnels handlers ──

// M331-M335: Caddy
func caddySitesHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sites, err := p.CaddySites(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, sites)
	}
}

func caddySiteCreateHandler(p storage.Provider, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		var s storage.CaddySite
		if err := json.NewDecoder(r.Body).Decode(&s); err != nil || s.Name == "" || s.Domain == "" {
			caller, _ := r.Context().Value(ctxUsername).(string)
			auditLog.LogEnriched(audit.Entry{User: caller, Action: "caddy-site-create", Detail: "invalid-request", IP: r.RemoteAddr, OK: false})
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name and domain required"})
			return
		}
		out, err := p.CreateCaddySite(r.Context(), s)
		if err != nil {
			caller, _ := r.Context().Value(ctxUsername).(string)
			auditLog.LogEnriched(audit.Entry{User: caller, Action: "caddy-site-create", Resource: s.Name, Detail: err.Error(), IP: r.RemoteAddr, OK: false})
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		caller, _ := r.Context().Value(ctxUsername).(string)
		auditLog.LogEnriched(audit.Entry{User: caller, Action: "caddy-site-create", Resource: s.Name, IP: r.RemoteAddr, OK: true})
		writeJSON(w, http.StatusOK, out)
	}
}

func caddySiteUpdateHandler(p storage.Provider, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		name := chi.URLParam(r, "name")
		var s storage.CaddySite
		if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
			caller, _ := r.Context().Value(ctxUsername).(string)
			auditLog.LogEnriched(audit.Entry{User: caller, Action: "caddy-site-update", Resource: name, Detail: "invalid-json", IP: r.RemoteAddr, OK: false})
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		out, err := p.UpdateCaddySite(r.Context(), name, s)
		if err != nil {
			caller, _ := r.Context().Value(ctxUsername).(string)
			auditLog.LogEnriched(audit.Entry{User: caller, Action: "caddy-site-update", Resource: name, Detail: err.Error(), IP: r.RemoteAddr, OK: false})
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		caller, _ := r.Context().Value(ctxUsername).(string)
		auditLog.LogEnriched(audit.Entry{User: caller, Action: "caddy-site-update", Resource: name, IP: r.RemoteAddr, OK: true})
		writeJSON(w, http.StatusOK, out)
	}
}

func caddySiteDeleteHandler(p storage.Provider, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		name := chi.URLParam(r, "name")
		if err := p.DeleteCaddySite(r.Context(), name); err != nil {
			caller, _ := r.Context().Value(ctxUsername).(string)
			auditLog.LogEnriched(audit.Entry{User: caller, Action: "caddy-site-delete", Resource: name, Detail: err.Error(), IP: r.RemoteAddr, OK: false})
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		caller, _ := r.Context().Value(ctxUsername).(string)
		auditLog.LogEnriched(audit.Entry{User: caller, Action: "caddy-site-delete", Resource: name, IP: r.RemoteAddr, OK: true})
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func caddyReloadHandler(p storage.Provider, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		if err := p.CaddyReload(r.Context()); err != nil {
			caller, _ := r.Context().Value(ctxUsername).(string)
			auditLog.LogEnriched(audit.Entry{User: caller, Action: "caddy-reload", Detail: err.Error(), IP: r.RemoteAddr, OK: false})
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		caller, _ := r.Context().Value(ctxUsername).(string)
		auditLog.LogEnriched(audit.Entry{User: caller, Action: "caddy-reload", IP: r.RemoteAddr, OK: true})
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

// M336-M337: Cloudflare Tunnel
func cfTunnelStatusHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		info, _ := p.TunnelStatus(r.Context())
		writeJSON(w, http.StatusOK, info)
	}
}

func cfTunnelStartHandler(p storage.Provider, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		var req struct {
			Name   string `json:"name"`
			Config string `json:"config"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
			caller, _ := r.Context().Value(ctxUsername).(string)
			auditLog.LogEnriched(audit.Entry{User: caller, Action: "cf-tunnel-start", Detail: "name-required", IP: r.RemoteAddr, OK: false})
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name required"})
			return
		}
		if err := p.TunnelStart(r.Context(), req.Name, req.Config); err != nil {
			caller, _ := r.Context().Value(ctxUsername).(string)
			auditLog.LogEnriched(audit.Entry{User: caller, Action: "cf-tunnel-start", Resource: req.Name, Detail: err.Error(), IP: r.RemoteAddr, OK: false})
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		caller, _ := r.Context().Value(ctxUsername).(string)
		auditLog.LogEnriched(audit.Entry{User: caller, Action: "cf-tunnel-start", Resource: req.Name, IP: r.RemoteAddr, OK: true})
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func cfTunnelStopHandler(p storage.Provider, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		var req struct {
			Name string `json:"name"`
		}
		json.NewDecoder(r.Body).Decode(&req) //nolint:errcheck
		if req.Name == "" {
			req.Name = "default"
		}
		if err := p.TunnelStop(r.Context(), req.Name); err != nil {
			caller, _ := r.Context().Value(ctxUsername).(string)
			auditLog.LogEnriched(audit.Entry{User: caller, Action: "cf-tunnel-stop", Resource: req.Name, Detail: err.Error(), IP: r.RemoteAddr, OK: false})
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		caller, _ := r.Context().Value(ctxUsername).(string)
		auditLog.LogEnriched(audit.Entry{User: caller, Action: "cf-tunnel-stop", Resource: req.Name, IP: r.RemoteAddr, OK: true})
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

// M338: Tailscale Funnel
func tailscaleFunnelHandler(p storage.Provider, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		var req struct {
			Port    int  `json:"port"`
			Enabled bool `json:"enabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			caller, _ := r.Context().Value(ctxUsername).(string)
			auditLog.LogEnriched(audit.Entry{User: caller, Action: "tailscale-funnel", Detail: "invalid-json", IP: r.RemoteAddr, OK: false})
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		if err := p.TailscaleFunnel(r.Context(), req.Port, req.Enabled); err != nil {
			caller, _ := r.Context().Value(ctxUsername).(string)
			auditLog.LogEnriched(audit.Entry{User: caller, Action: "tailscale-funnel", Detail: err.Error(), IP: r.RemoteAddr, OK: false})
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		caller, _ := r.Context().Value(ctxUsername).(string)
		action := "tailscale-funnel-disable"
		if req.Enabled {
			action = "tailscale-funnel-enable"
		}
		auditLog.LogEnriched(audit.Entry{User: caller, Action: action, IP: r.RemoteAddr, OK: true})
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

// M339-M340: WireGuard
func wgPeersHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		peers, err := p.WireGuardPeers(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, peers)
	}
}

func wgAddPeerHandler(p storage.Provider, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		var req struct {
			PublicKey string `json:"public_key"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.PublicKey == "" {
			caller, _ := r.Context().Value(ctxUsername).(string)
			auditLog.LogEnriched(audit.Entry{User: caller, Action: "wg-peer-add", Detail: "public_key-required", IP: r.RemoteAddr, OK: false})
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "public_key required"})
			return
		}
		peer, err := p.WireGuardAddPeer(r.Context(), req.PublicKey)
		if err != nil {
			caller, _ := r.Context().Value(ctxUsername).(string)
			auditLog.LogEnriched(audit.Entry{User: caller, Action: "wg-peer-add", Detail: err.Error(), IP: r.RemoteAddr, OK: false})
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		caller, _ := r.Context().Value(ctxUsername).(string)
		auditLog.LogEnriched(audit.Entry{User: caller, Action: "wg-peer-add", Resource: req.PublicKey[:12], IP: r.RemoteAddr, OK: true})
		writeJSON(w, http.StatusOK, peer)
	}
}

func wgRemovePeerHandler(p storage.Provider, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		pubkey := chi.URLParam(r, "pubkey")
		if err := p.WireGuardRemovePeer(r.Context(), pubkey); err != nil {
			caller, _ := r.Context().Value(ctxUsername).(string)
			auditLog.LogEnriched(audit.Entry{User: caller, Action: "wg-peer-remove", Detail: err.Error(), IP: r.RemoteAddr, OK: false})
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		caller, _ := r.Context().Value(ctxUsername).(string)
		auditLog.LogEnriched(audit.Entry{User: caller, Action: "wg-peer-remove", Resource: pubkey[:12], IP: r.RemoteAddr, OK: true})
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func wgConfigHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg, err := p.WireGuardConfig(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		// Strip private key from response to non-admins
		role, _ := r.Context().Value(ctxRole).(string)
		if role != auth.RoleAdmin {
			cfg.PrivateKey = ""
		}
		writeJSON(w, http.StatusOK, cfg)
	}
}

// wgClientConfigHandler returns a downloadable wg-quick .conf for a peer.
func wgClientConfigHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		pubkey := chi.URLParam(r, "pubkey")
		cfg, err := p.WireGuardConfig(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		var peer *storage.WireGuardPeer
		for i := range cfg.Peers {
			if cfg.Peers[i].PublicKey == pubkey {
				peer = &cfg.Peers[i]
				break
			}
		}
		if peer == nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "peer not found"})
			return
		}
		// Render a wg-quick template. The peer's actual private key is NOT stored
		// on the server; this template uses placeholders the client must fill in.
		body := fmt.Sprintf(`[Interface]
# Replace with the private key generated on the client (wg genkey)
PrivateKey = <CLIENT_PRIVATE_KEY>
Address = %s
DNS = 1.1.1.1

[Peer]
PublicKey = %s
AllowedIPs = %s
Endpoint = <SERVER_PUBLIC_HOST>:%d
PersistentKeepalive = 25
`, peer.AllowedIPs, pubkey, peer.AllowedIPs, cfg.ListenPort)
		w.Header().Set("Content-Type", "application/x-wireguard-config")
		w.Header().Set("Content-Disposition", `attachment; filename="kilasos-wg.conf"`)
		w.Write([]byte(body)) //nolint:errcheck
	}
}

// wgQRCodeHandler returns an SVG QR code of the client config (M341).
func wgQRCodeHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		pubkey := chi.URLParam(r, "pubkey")
		cfg, err := p.WireGuardConfig(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		var peer *storage.WireGuardPeer
		for i := range cfg.Peers {
			if cfg.Peers[i].PublicKey == pubkey {
				peer = &cfg.Peers[i]
				break
			}
		}
		if peer == nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "peer not found"})
			return
		}
		conf := fmt.Sprintf("[Interface]\nPrivateKey = <CLIENT_PRIVATE_KEY>\nAddress = %s\nDNS = 1.1.1.1\n\n[Peer]\nPublicKey = %s\nAllowedIPs = %s\nEndpoint = <SERVER_PUBLIC_HOST>:%d\nPersistentKeepalive = 25\n",
			peer.AllowedIPs, pubkey, peer.AllowedIPs, cfg.ListenPort)
		// Try qrencode (most common); fall back to plain text if not installed
		cmd := exec.Command("qrencode", "-t", "SVG", "-o", "-")
		cmd.Stdin = strings.NewReader(conf)
		out, err := cmd.Output()
		if err != nil {
			w.Header().Set("Content-Type", "text/plain")
			w.Write([]byte("# qrencode not installed; install with: apt install qrencode\n# Config:\n" + conf)) //nolint:errcheck
			return
		}
		w.Header().Set("Content-Type", "image/svg+xml")
		w.Write(out) //nolint:errcheck
	}
}

// M342: UPnP
func upnpStatusHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		st, _ := p.UPnPStatus(r.Context())
		writeJSON(w, http.StatusOK, st)
	}
}

func upnpForwardHandler(p storage.Provider, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		var req struct {
			InternalPort int    `json:"internal_port"`
			Protocol     string `json:"protocol"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.InternalPort == 0 {
			caller, _ := r.Context().Value(ctxUsername).(string)
			auditLog.LogEnriched(audit.Entry{User: caller, Action: "upnp-forward", Detail: "invalid-request", IP: r.RemoteAddr, OK: false})
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "internal_port required"})
			return
		}
		ext, err := p.UPnPForwardPort(r.Context(), req.InternalPort, req.Protocol)
		if err != nil {
			caller, _ := r.Context().Value(ctxUsername).(string)
			auditLog.LogEnriched(audit.Entry{User: caller, Action: "upnp-forward", Detail: err.Error(), IP: r.RemoteAddr, OK: false})
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		caller, _ := r.Context().Value(ctxUsername).(string)
		auditLog.LogEnriched(audit.Entry{User: caller, Action: "upnp-forward", Detail: fmt.Sprintf("%d/%s", req.InternalPort, req.Protocol), IP: r.RemoteAddr, OK: true})
		writeJSON(w, http.StatusOK, map[string]int{"external_port": ext})
	}
}

func upnpRemoveHandler(p storage.Provider, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		var req struct {
			InternalPort int    `json:"internal_port"`
			Protocol     string `json:"protocol"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.InternalPort == 0 {
			caller, _ := r.Context().Value(ctxUsername).(string)
			auditLog.LogEnriched(audit.Entry{User: caller, Action: "upnp-remove", Detail: "invalid-request", IP: r.RemoteAddr, OK: false})
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "internal_port required"})
			return
		}
		if err := p.UPnPRemovePort(r.Context(), req.InternalPort, req.Protocol); err != nil {
			caller, _ := r.Context().Value(ctxUsername).(string)
			auditLog.LogEnriched(audit.Entry{User: caller, Action: "upnp-remove", Detail: err.Error(), IP: r.RemoteAddr, OK: false})
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		caller, _ := r.Context().Value(ctxUsername).(string)
		auditLog.LogEnriched(audit.Entry{User: caller, Action: "upnp-remove", Detail: fmt.Sprintf("%d/%s", req.InternalPort, req.Protocol), IP: r.RemoteAddr, OK: true})
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

// M343: DDNS
func ddnsUpdateHandler(p storage.Provider, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		var req struct {
			Provider string `json:"provider"`
			Domain   string `json:"domain"`
			Token    string `json:"token"`
			IP       string `json:"ip"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Provider == "" || req.Domain == "" {
			caller, _ := r.Context().Value(ctxUsername).(string)
			auditLog.LogEnriched(audit.Entry{User: caller, Action: "ddns-update", Detail: "invalid-request", IP: r.RemoteAddr, OK: false})
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "provider and domain required"})
			return
		}
		if err := p.DDNSUpdate(r.Context(), req.Provider, req.Domain, req.Token, req.IP); err != nil {
			caller, _ := r.Context().Value(ctxUsername).(string)
			auditLog.LogEnriched(audit.Entry{User: caller, Action: "ddns-update", Detail: err.Error(), IP: r.RemoteAddr, OK: false})
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		caller, _ := r.Context().Value(ctxUsername).(string)
		auditLog.LogEnriched(audit.Entry{User: caller, Action: "ddns-update", Detail: req.Provider + " " + req.Domain, IP: r.RemoteAddr, OK: true})
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

// M344: dnsmasq DNS
func dnsmasqConfigHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg, err := p.DNSmasqConfig(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"config": cfg})
	}
}

func dnsmasqConfigSetHandler(p storage.Provider, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		var req struct {
			Config string `json:"config"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			caller, _ := r.Context().Value(ctxUsername).(string)
			auditLog.LogEnriched(audit.Entry{User: caller, Action: "dnsmasq-config-update", Detail: "invalid-json", IP: r.RemoteAddr, OK: false})
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		if err := p.SetDNSmasqConfig(r.Context(), req.Config); err != nil {
			caller, _ := r.Context().Value(ctxUsername).(string)
			auditLog.LogEnriched(audit.Entry{User: caller, Action: "dnsmasq-config-update", Detail: err.Error(), IP: r.RemoteAddr, OK: false})
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		caller, _ := r.Context().Value(ctxUsername).(string)
		auditLog.LogEnriched(audit.Entry{User: caller, Action: "dnsmasq-config-update", IP: r.RemoteAddr, OK: true})
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

// M345: DHCP
func dhcpConfigHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg, err := p.DHCPConfig(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, cfg)
	}
}

func dhcpConfigSetHandler(p storage.Provider, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		var cfg storage.DHCPConfig
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			caller, _ := r.Context().Value(ctxUsername).(string)
			auditLog.LogEnriched(audit.Entry{User: caller, Action: "dhcp-config-update", Detail: "invalid-json", IP: r.RemoteAddr, OK: false})
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		if err := p.SetDHCPConfig(r.Context(), cfg); err != nil {
			caller, _ := r.Context().Value(ctxUsername).(string)
			auditLog.LogEnriched(audit.Entry{User: caller, Action: "dhcp-config-update", Detail: err.Error(), IP: r.RemoteAddr, OK: false})
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		caller, _ := r.Context().Value(ctxUsername).(string)
		auditLog.LogEnriched(audit.Entry{User: caller, Action: "dhcp-config-update", IP: r.RemoteAddr, OK: true})
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

// ── BATCH-E (M361-M375): Storage Power-User handlers ──
func btrfsSubvolumesHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		subvols, err := p.BtrfsSubvolumes(r.Context())
		if err != nil { writeJSON(w, 500, map[string]string{"error": err.Error()}); return }
		writeJSON(w, 200, subvols)
	}
}
func createBtrfsSubvolHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct{ Path string }
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil { writeJSON(w, 400, map[string]string{"error": err.Error()}); return }
		sv, err := p.CreateBtrfsSubvol(r.Context(), req.Path)
		if err != nil { writeJSON(w, 500, map[string]string{"error": err.Error()}); return }
		writeJSON(w, 200, sv)
	}
}
func deleteBtrfsSubvolHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Query().Get("path")
		if path == "" { writeJSON(w, 400, map[string]string{"error": "path required"}); return }
		if err := p.DeleteBtrfsSubvol(r.Context(), path); err != nil { writeJSON(w, 500, map[string]string{"error": err.Error()}); return }
		writeJSON(w, 200, map[string]string{"status": "deleted"})
	}
}
func btrfsSnapshotsHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		snaps, err := p.BtrfsSnapshots(r.Context())
		if err != nil { writeJSON(w, 500, map[string]string{"error": err.Error()}); return }
		writeJSON(w, 200, snaps)
	}
}
func createBtrfsSnapshotHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct{ Source, Target string }
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil { writeJSON(w, 400, map[string]string{"error": err.Error()}); return }
		snap, err := p.CreateBtrfsSnapshot(r.Context(), req.Source, req.Target)
		if err != nil { writeJSON(w, 500, map[string]string{"error": err.Error()}); return }
		writeJSON(w, 200, snap)
	}
}
func deleteBtrfsSnapshotHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Query().Get("path")
		if path == "" { writeJSON(w, 400, map[string]string{"error": "path required"}); return }
		if err := p.DeleteBtrfsSnapshot(r.Context(), path); err != nil { writeJSON(w, 500, map[string]string{"error": err.Error()}); return }
		writeJSON(w, 200, map[string]string{"status": "deleted"})
	}
}
func btrfsRestoreSnapshotHandler(p storage.Provider, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct{ Path, Snapshot string }
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil { writeJSON(w, 400, map[string]string{"error": err.Error()}); return }
		if req.Path == "" || req.Snapshot == "" { writeJSON(w, 400, map[string]string{"error": "path and snapshot required"}); return }
		caller, _ := r.Context().Value(ctxUsername).(string)
		if err := p.RestoreBtrfsSnapshot(r.Context(), req.Path, req.Snapshot); err != nil {
			auditLog.LogEnriched(audit.Entry{User: caller, Action: "btrfs-snapshot-restore", Resource: req.Path, Detail: req.Snapshot, IP: r.RemoteAddr, OK: false})
			writeJSON(w, 500, map[string]string{"error": err.Error()}); return
		}
		auditLog.LogEnriched(audit.Entry{User: caller, Action: "btrfs-snapshot-restore", Resource: req.Path, Detail: req.Snapshot, IP: r.RemoteAddr, OK: true})
		writeJSON(w, 200, map[string]string{"status": "restored"})
	}
}
func btrfsScrubHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct{ Path string }
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil { writeJSON(w, 400, map[string]string{"error": err.Error()}); return }
		if err := p.BtrfsScrub(r.Context(), req.Path); err != nil { writeJSON(w, 500, map[string]string{"error": err.Error()}); return }
		writeJSON(w, 200, map[string]string{"status": "scrub started"})
	}
}
func btrfsBalanceHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct{ Path string }
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil { writeJSON(w, 400, map[string]string{"error": err.Error()}); return }
		if err := p.BtrfsBalance(r.Context(), req.Path); err != nil { writeJSON(w, 500, map[string]string{"error": err.Error()}); return }
		writeJSON(w, 200, map[string]string{"status": "balance started"})
	}
}
func zfsL2ARCStatusHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		devices, err := p.ZFSL2ARCStatus(r.Context())
		if err != nil { writeJSON(w, 500, map[string]string{"error": err.Error()}); return }
		writeJSON(w, 200, devices)
	}
}
func zfsL2ARCAddHandler(p storage.Provider, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct{ Pool, Device string }
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil { writeJSON(w, 400, map[string]string{"error": err.Error()}); return }
		caller, _ := r.Context().Value(ctxUsername).(string)
		if err := p.ZFSL2ARCAdd(r.Context(), req.Pool, req.Device); err != nil {
			auditLog.LogEnriched(audit.Entry{User: caller, Action: "zfs-l2arc-add", Resource: req.Pool, Detail: req.Device, IP: r.RemoteAddr, OK: false})
			writeJSON(w, 500, map[string]string{"error": err.Error()}); return
		}
		auditLog.LogEnriched(audit.Entry{User: caller, Action: "zfs-l2arc-add", Resource: req.Pool, Detail: req.Device, IP: r.RemoteAddr, OK: true})
		writeJSON(w, 200, map[string]string{"status": "L2ARC added"})
	}
}
func zfsL2ARCRemoveHandler(p storage.Provider, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		pool := chi.URLParam(r, "pool")
		caller, _ := r.Context().Value(ctxUsername).(string)
		if err := p.ZFSL2ARCRemove(r.Context(), pool); err != nil {
			auditLog.LogEnriched(audit.Entry{User: caller, Action: "zfs-l2arc-remove", Resource: pool, IP: r.RemoteAddr, OK: false})
			writeJSON(w, 500, map[string]string{"error": err.Error()}); return
		}
		auditLog.LogEnriched(audit.Entry{User: caller, Action: "zfs-l2arc-remove", Resource: pool, IP: r.RemoteAddr, OK: true})
		writeJSON(w, 200, map[string]string{"status": "L2ARC removed"})
	}
}
func zfsSLOGStatusHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		devices, err := p.ZFSSLOGStatus(r.Context())
		if err != nil { writeJSON(w, 500, map[string]string{"error": err.Error()}); return }
		writeJSON(w, 200, devices)
	}
}
func zfsSLOGAddHandler(p storage.Provider, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct{ Pool, Device string }
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil { writeJSON(w, 400, map[string]string{"error": err.Error()}); return }
		caller, _ := r.Context().Value(ctxUsername).(string)
		if err := p.ZFSSLOGAdd(r.Context(), req.Pool, req.Device); err != nil {
			auditLog.LogEnriched(audit.Entry{User: caller, Action: "zfs-slog-add", Resource: req.Pool, Detail: req.Device, IP: r.RemoteAddr, OK: false})
			writeJSON(w, 500, map[string]string{"error": err.Error()}); return
		}
		auditLog.LogEnriched(audit.Entry{User: caller, Action: "zfs-slog-add", Resource: req.Pool, Detail: req.Device, IP: r.RemoteAddr, OK: true})
		writeJSON(w, 200, map[string]string{"status": "SLOG added"})
	}
}
func zfsSLOGRemoveHandler(p storage.Provider, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		pool := chi.URLParam(r, "pool")
		caller, _ := r.Context().Value(ctxUsername).(string)
		if err := p.ZFSSLOGRemove(r.Context(), pool); err != nil {
			auditLog.LogEnriched(audit.Entry{User: caller, Action: "zfs-slog-remove", Resource: pool, IP: r.RemoteAddr, OK: false})
			writeJSON(w, 500, map[string]string{"error": err.Error()}); return
		}
		auditLog.LogEnriched(audit.Entry{User: caller, Action: "zfs-slog-remove", Resource: pool, IP: r.RemoteAddr, OK: true})
		writeJSON(w, 200, map[string]string{"status": "SLOG removed"})
	}
}
func zfsSpecialVdevStatusHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vdevs, err := p.ZFSSpecialVdevStatus(r.Context())
		if err != nil { writeJSON(w, 500, map[string]string{"error": err.Error()}); return }
		writeJSON(w, 200, vdevs)
	}
}
func zfsSpecialVdevAddHandler(p storage.Provider, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct{ Pool, Device string }
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil { writeJSON(w, 400, map[string]string{"error": err.Error()}); return }
		caller, _ := r.Context().Value(ctxUsername).(string)
		if err := p.ZFSSpecialVdevAdd(r.Context(), req.Pool, req.Device); err != nil {
			auditLog.LogEnriched(audit.Entry{User: caller, Action: "zfs-specialvdev-add", Resource: req.Pool, Detail: req.Device, IP: r.RemoteAddr, OK: false})
			writeJSON(w, 500, map[string]string{"error": err.Error()}); return
		}
		auditLog.LogEnriched(audit.Entry{User: caller, Action: "zfs-specialvdev-add", Resource: req.Pool, Detail: req.Device, IP: r.RemoteAddr, OK: true})
		writeJSON(w, 200, map[string]string{"status": "special vdev added"})
	}
}
func zfsDDTProjectionHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		proj, err := p.ZFSDDTProjection(r.Context())
		if err != nil { writeJSON(w, 500, map[string]string{"error": err.Error()}); return }
		writeJSON(w, 200, proj)
	}
}
func ddtProjectionStatusHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		proj, err := p.DDTProjectionStatus(r.Context())
		if err != nil { writeJSON(w, 500, map[string]string{"error": err.Error()}); return }
		writeJSON(w, 200, proj)
	}
}
func zfsCompressionRatiosHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ratios, err := p.ZFSCompressionRatios(r.Context())
		if err != nil { writeJSON(w, 500, map[string]string{"error": err.Error()}); return }
		writeJSON(w, 200, ratios)
	}
}
func lifecyclePoliciesHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		policies, err := p.LifecyclePolicies(r.Context())
		if err != nil { writeJSON(w, 500, map[string]string{"error": err.Error()}); return }
		writeJSON(w, 200, policies)
	}
}
func setLifecyclePolicyHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var pol storage.LifecyclePolicy
		if err := json.NewDecoder(r.Body).Decode(&pol); err != nil { writeJSON(w, 400, map[string]string{"error": err.Error()}); return }
		if err := p.SetLifecyclePolicy(r.Context(), pol); err != nil { writeJSON(w, 500, map[string]string{"error": err.Error()}); return }
		writeJSON(w, 200, pol)
	}
}
func deleteLifecyclePolicyHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		if err := p.DeleteLifecyclePolicy(r.Context(), name); err != nil { writeJSON(w, 500, map[string]string{"error": err.Error()}); return }
		writeJSON(w, 200, map[string]string{"status": "deleted"})
	}
}
func storageTierPolicyHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		pol, err := p.StorageTierPolicy(r.Context())
		if err != nil { writeJSON(w, 500, map[string]string{"error": err.Error()}); return }
		writeJSON(w, 200, pol)
	}
}
func setStorageTierPolicyHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var pol storage.TierPolicy
		if err := json.NewDecoder(r.Body).Decode(&pol); err != nil { writeJSON(w, 400, map[string]string{"error": err.Error()}); return }
		if err := p.SetStorageTierPolicy(r.Context(), pol); err != nil { writeJSON(w, 500, map[string]string{"error": err.Error()}); return }
		writeJSON(w, 200, pol)
	}
}
func dedupScannerStatusHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		res, err := p.DedupScannerStatus(r.Context())
		if err != nil { writeJSON(w, 500, map[string]string{"error": err.Error()}); return }
		writeJSON(w, 200, res)
	}
}
func startDedupScanHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct{ Path string }
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil { writeJSON(w, 400, map[string]string{"error": err.Error()}); return }
		if err := p.StartDedupScan(r.Context(), req.Path); err != nil { writeJSON(w, 500, map[string]string{"error": err.Error()}); return }
		writeJSON(w, 200, map[string]string{"status": "dedup scan started"})
	}
}
func diskBurnInStatusHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		status, err := p.DiskBurnInStatus(r.Context())
		if err != nil { writeJSON(w, 500, map[string]string{"error": err.Error()}); return }
		writeJSON(w, 200, status)
	}
}
func startDiskBurnInHandler(p storage.Provider, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct{ Disk string }
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil { writeJSON(w, 400, map[string]string{"error": err.Error()}); return }
		caller, _ := r.Context().Value(ctxUsername).(string)
		// Burn-in is DESTRUCTIVE — wipes the disk. Always audit-log.
		if err := p.StartDiskBurnIn(r.Context(), req.Disk); err != nil {
			auditLog.LogEnriched(audit.Entry{User: caller, Action: "disk-burnin-start", Resource: req.Disk, IP: r.RemoteAddr, OK: false, Detail: err.Error()})
			writeJSON(w, 500, map[string]string{"error": err.Error()}); return
		}
		auditLog.LogEnriched(audit.Entry{User: caller, Action: "disk-burnin-start", Resource: req.Disk, IP: r.RemoteAddr, OK: true})
		writeJSON(w, 200, map[string]string{"status": "burn-in started"})
	}
}
func replacementWizardStateHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		state, err := p.ReplacementWizardState(r.Context(), id)
		if err != nil { writeJSON(w, 500, map[string]string{"error": err.Error()}); return }
		writeJSON(w, 200, state)
	}
}
func replacementWizardStepHandler(p storage.Provider, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		var req struct{ Action string; Data map[string]string }
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil { writeJSON(w, 400, map[string]string{"error": err.Error()}); return }
		caller, _ := r.Context().Value(ctxUsername).(string)
		state, err := p.ReplacementWizardStep(r.Context(), id, req.Action, req.Data)
		if err != nil {
			auditLog.LogEnriched(audit.Entry{User: caller, Action: "replacement-wizard-step", Resource: id, Detail: req.Action, IP: r.RemoteAddr, OK: false})
			writeJSON(w, 500, map[string]string{"error": err.Error()}); return
		}
		auditLog.LogEnriched(audit.Entry{User: caller, Action: "replacement-wizard-step", Resource: id, Detail: req.Action, IP: r.RemoteAddr, OK: true})
		writeJSON(w, 200, state)
	}
}
func poolExpansionWizardStateHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		state, err := p.PoolExpansionWizardState(r.Context(), id)
		if err != nil { writeJSON(w, 500, map[string]string{"error": err.Error()}); return }
		writeJSON(w, 200, state)
	}
}
func poolExpansionStepHandler(p storage.Provider, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		var req struct{ Action string; Data map[string]string }
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil { writeJSON(w, 400, map[string]string{"error": err.Error()}); return }
		caller, _ := r.Context().Value(ctxUsername).(string)
		state, err := p.PoolExpansionStep(r.Context(), id, req.Action, req.Data)
		if err != nil {
			auditLog.LogEnriched(audit.Entry{User: caller, Action: "pool-expansion-step", Resource: id, Detail: req.Action, IP: r.RemoteAddr, OK: false})
			writeJSON(w, 500, map[string]string{"error": err.Error()}); return
		}
		auditLog.LogEnriched(audit.Entry{User: caller, Action: "pool-expansion-step", Resource: id, Detail: req.Action, IP: r.RemoteAddr, OK: true})
		writeJSON(w, 200, state)
	}
}

// ── BATCH-G (M391-M405): Web File Manager handlers ──

// ── BATCH-H (M406-M420): Mobile & UX Polish handlers (minimal) ──
func pwaManifestHandler(w http.ResponseWriter, r *http.Request) {
	data, err := staticFS.ReadFile("static/manifest.json")
	if err != nil {
		http.Error(w, "manifest not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Write(data) //nolint:errcheck
}

func pwaServiceWorkerHandler(w http.ResponseWriter, r *http.Request) {
	data, err := staticFS.ReadFile("static/sw.js")
	if err != nil {
		http.Error(w, "service worker not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Write(data) //nolint:errcheck
}

// ── BATCH-I (M421-M435): Observability & Logs handlers ──
func syslogForwardingConfigHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg, err := p.SyslogForwardingConfig(r.Context())
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, cfg)
	}
}

func setSyslogForwardingHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var cfg storage.SyslogConfig
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		if err := p.SetSyslogForwarding(r.Context(), cfg); err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, cfg)
	}
}

func auditRetentionHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) { return }
		pol, err := p.AuditRetentionPolicy(r.Context())
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, pol)
	}
}

func setAuditRetentionHandler(p storage.Provider, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) { return }
		var pol storage.AuditRetention
		if err := json.NewDecoder(r.Body).Decode(&pol); err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		if err := p.SetAuditRetentionPolicy(r.Context(), pol); err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		auditLog.SetRetentionDays(pol.MaxAgeDays)
		caller, _ := r.Context().Value(ctxUsername).(string)
		auditLog.LogEnriched(audit.Entry{User: caller, Action: "audit-retention-update", IP: r.RemoteAddr, OK: true})
		writeJSON(w, 200, pol)
	}
}

func rotateAuditLogsHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) { return }
		if err := p.RotateAuditLogs(r.Context()); err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]string{"status": "rotated"})
	}
}

func searchAuditLogsHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) { return }
		var q storage.AuditLogQuery
		if err := json.NewDecoder(r.Body).Decode(&q); err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		entries, err := p.SearchAuditLogs(r.Context(), q)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, entries)
	}
}

func aggregateSystemLogsHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sinceHours := 24
		if h := r.URL.Query().Get("hours"); h != "" {
			if v, err := strconv.Atoi(h); err == nil {
				sinceHours = v
			}
		}
		summaries, err := p.AggregateSystemLogs(r.Context(), sinceHours)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, summaries)
	}
}

func searchContainerLogsHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var q storage.ContainerLogQuery
		if err := json.NewDecoder(r.Body).Decode(&q); err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		entries, err := p.SearchContainerLogs(r.Context(), q)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, entries)
	}
}

func logDownloadHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		unitsStr := r.URL.Query().Get("units")
		sinceHours := 24
		if h := r.URL.Query().Get("hours"); h != "" {
			if v, err := strconv.Atoi(h); err == nil {
				sinceHours = v
			}
		}
		units := strings.Split(unitsStr, ",")
		if unitsStr == "" {
			units = []string{"nasd.service"}
		}
		path, err := p.LogDownload(r.Context(), units, sinceHours)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		w.Header().Set("Content-Type", "application/x-gzip")
		http.ServeFile(w, r, path)
	}
}

func logAlertRulesHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rules, err := p.LogAlertRules(r.Context())
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, rules)
	}
}

func createLogAlertRuleHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var rule storage.LogAlertRule
		if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		saved, err := p.CreateLogAlertRule(r.Context(), rule)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, saved)
	}
}

func deleteLogAlertRuleHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		if err := p.DeleteLogAlertRule(r.Context(), name); err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]string{"status": "deleted"})
	}
}

func logStatsHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		stats, err := p.LogStats(r.Context())
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, stats)
	}
}

func containerRestartLoopsHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		events, err := p.ContainerRestartLoops(r.Context())
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, events)
	}
}

func lokiConfigHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg, err := p.LokiConfig(r.Context())
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, cfg)
	}
}

func setLokiConfigHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var cfg storage.LokiConfig
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		if err := p.SetLokiConfig(r.Context(), cfg); err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, cfg)
	}
}

func exportLogsToS3Handler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		unitsStr := r.URL.Query().Get("units")
		sinceHours := 24
		if h := r.URL.Query().Get("hours"); h != "" {
			if v, err := strconv.Atoi(h); err == nil {
				sinceHours = v
			}
		}
		units := strings.Split(unitsStr, ",")
		if unitsStr == "" {
			units = []string{"nasd.service"}
		}
		path, err := p.ExportLogsToS3(r.Context(), units, sinceHours)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]string{"archive": path, "status": "exported to s3 if configured"})
	}
}

// ── BATCH-J (M436-M450): Security & Compliance handlers ──

func sshKeyAuditHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) { return }
		entries, err := p.SSHKeyAudit(r.Context())
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, entries)
	}
}

func markSSHKeyUsedHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) { return }
		fp := chi.URLParam(r, "fingerprint")
		if err := p.MarkSSHKeyUsed(r.Context(), fp); err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]string{"status": "marked"})
	}
}

func sudoAuditHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		days := 7
		if d := r.URL.Query().Get("days"); d != "" {
			if v, err := strconv.Atoi(d); err == nil {
				days = v
			}
		}
		events, err := p.SudoAudit(r.Context(), days)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, events)
	}
}

func failedLoginsHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		days := 7
		if d := r.URL.Query().Get("days"); d != "" {
			if v, err := strconv.Atoi(d); err == nil {
				days = v
			}
		}
		logins, err := p.FailedLogins(r.Context(), days)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, logins)
	}
}

func integrityCheckHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		findings, err := p.IntegrityCheck(r.Context())
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, findings)
	}
}

// publicShareHandler — M403. Unauthenticated (token in URL is the credential).
// Rate-limits per IP, resolves token, validates server-side, streams file.
// Audit-logs every access including failures (with token+IP for forensics).
func publicShareHandler(p storage.Provider, auditLog *audit.Logger, rl *loginRateLimiter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clientIP := r.RemoteAddr
		if i := strings.LastIndex(clientIP, ":"); i > 0 {
			clientIP = clientIP[:i]
		}
		if !rl.allow(clientIP) {
			auditLog.Log("share-public", "rate-limited", clientIP, r.RemoteAddr, false)
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many requests"})
			return
		}
		token := chi.URLParam(r, "token")
		// Token shape sanity: 64 hex chars (32 bytes). Reject obvious malformed input
		// before hitting the store to limit timing-oracle exposure.
		if len(token) < 16 || strings.ContainsAny(token, "/.\\") {
			auditLog.Log("share-public", "malformed-token", token, r.RemoteAddr, false)
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
			return
		}
		link, err := p.ResolveShareToken(r.Context(), token)
		if err != nil {
			// Don't leak whether the token didn't exist vs expired vs maxed out.
			auditLog.Log("share-public", "denied", token+" "+err.Error(), r.RemoteAddr, false)
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
			return
		}
		// Defense-in-depth: refuse paths that shouldn't have been allowed at create time.
		clean := filepath.Clean(link.Path)
		if strings.Contains(clean, "..") || !strings.HasPrefix(clean, "/mnt") {
			auditLog.Log("share-public", "unsafe-path", link.ID+" "+link.Path, r.RemoteAddr, false)
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "invalid path"})
			return
		}
		f, err := os.Open(clean)
		if err != nil {
			auditLog.Log("share-public", "open-failed", link.ID+" "+err.Error(), r.RemoteAddr, false)
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
			return
		}
		defer f.Close()
		info, err := f.Stat()
		if err != nil || info.IsDir() {
			auditLog.Log("share-public", "not-a-file", link.ID, r.RemoteAddr, false)
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "not a file"})
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", "attachment; filename=\""+filepath.Base(clean)+"\"")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", info.Size()))
	auditLog.Log("share-public", "served", link.ID+" "+filepath.Base(clean), r.RemoteAddr, true)
	}
}

func uploadServerCertHandler(p storage.Provider, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) { return }
		caller, _ := r.Context().Value(ctxUsername).(string)
		if err := r.ParseMultipartForm(32 << 20); err != nil {
			writeJSON(w, 400, map[string]string{"error": "multipart form required"})
			return
		}
		certFile, _, err := r.FormFile("cert")
		if err != nil {
			auditLog.LogEnriched(audit.Entry{User: caller, Action: "cert-upload", Detail: "cert missing", IP: r.RemoteAddr, OK: false})
			writeJSON(w, 400, map[string]string{"error": "cert file required"})
			return
		}
		keyFile, _, err := r.FormFile("key")
		if err != nil {
			auditLog.LogEnriched(audit.Entry{User: caller, Action: "cert-upload", Detail: "key missing", IP: r.RemoteAddr, OK: false})
			writeJSON(w, 400, map[string]string{"error": "key file required"})
			return
		}
		certPEM, _ := io.ReadAll(certFile)
		keyPEM, _ := io.ReadAll(keyFile)
		if err := p.UploadServerCertificate(r.Context(), certPEM, keyPEM); err != nil {
			auditLog.LogEnriched(audit.Entry{User: caller, Action: "cert-upload", Detail: err.Error(), IP: r.RemoteAddr, OK: false})
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		auditLog.LogEnriched(audit.Entry{User: caller, Action: "cert-upload", IP: r.RemoteAddr, OK: true})
		writeJSON(w, 200, map[string]bool{"ok": true})
	}
}

func generateServerCertHandler(p storage.Provider, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) { return }
		var req struct{ CommonName string }
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.CommonName == "" {
			writeJSON(w, 400, map[string]string{"error": "common_name required"})
			return
		}
		caller, _ := r.Context().Value(ctxUsername).(string)
		msg, err := p.GenerateServerCertificate(r.Context(), req.CommonName)
		if err != nil {
			auditLog.LogEnriched(audit.Entry{User: caller, Action: "cert-generate", Detail: err.Error(), IP: r.RemoteAddr, OK: false})
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		auditLog.LogEnriched(audit.Entry{User: caller, Action: "cert-generate", Resource: req.CommonName, IP: r.RemoteAddr, OK: true})
		writeJSON(w, 200, map[string]string{"message": msg})
	}
}

func enforcePoolCount(p storage.Provider, r *http.Request) error {
	lic := licenseFromContext(r.Context())
	if lic != nil && lic.Tier == kilaoslicense.TierPro && !lic.IsExpired() {
		return nil
	}
	pools, err := p.Arrays(r.Context())
	if err != nil {
		return fmt.Errorf("failed to check pool count: %w", err)
	}
	if len(pools) >= 1 {
		return fmt.Errorf("Home tier supports 1 pool; %d pools exist. Upgrade to Pro for unlimited pools.", len(pools))
	}
	return nil
}

func enforceRawCapacity(p storage.Provider, r *http.Request, newDevices []string) error {
	lic := licenseFromContext(r.Context())
	if lic != nil && lic.Tier == kilaoslicense.TierPro && !lic.IsExpired() {
		return nil
	}
	disks, err := p.Disks(r.Context())
	if err != nil {
		return fmt.Errorf("failed to get disks: %w", err)
	}
	pools, err := p.Arrays(r.Context())
	if err != nil {
		return fmt.Errorf("failed to get arrays: %w", err)
	}
	poolDevices := make(map[string]bool)
	for _, pool := range pools {
		for _, d := range pool.Devices {
			poolDevices[d] = true
		}
	}
	newDeviceSet := make(map[string]bool)
	for _, d := range newDevices {
		newDeviceSet[d] = true
	}
	var totalBytes int64
	for _, disk := range disks {
		if poolDevices[disk.Name] || newDeviceSet[disk.Name] {
			totalBytes += disk.SizeBytes
		}
	}
	totalTB := float64(totalBytes) / 1e12
	if totalTB > 25 {
		return fmt.Errorf("Home tier supports 25 TB raw; current total would be %.1f TB. Upgrade to Pro for 500 TB.", totalTB)
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v) //nolint:errcheck
}
