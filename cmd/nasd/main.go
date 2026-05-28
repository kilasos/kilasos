package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"github.com/kilasos/kilasos/internal/api"
	"github.com/kilasos/kilasos/internal/appcatalog"
	"github.com/kilasos/kilasos/internal/audit"
	"github.com/kilasos/kilasos/internal/auth"
	kilaoslicense "github.com/kilasos/kilasos/internal/license"
	"github.com/kilasos/kilasos/internal/monitor"
	"github.com/kilasos/kilasos/internal/notify"
	"github.com/kilasos/kilasos/internal/rsync"
	"github.com/kilasos/kilasos/internal/scheduler"
	"github.com/kilasos/kilasos/internal/storage"
	"github.com/kilasos/kilasos/internal/sysupdate"
	"github.com/kilasos/kilasos/internal/wol"
)

// Build-time variables, overridden via -ldflags by scripts/build.sh.
var (
	Version   = "dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)

func main() {
	showVersion := flag.Bool("version", false, "print version and exit")
	addr    := flag.String("addr", "0.0.0.0:8080", "listen address")
	dev     := flag.Bool("dev", false, "use mock storage provider")
	token   := flag.String("token", "", "legacy static bearer token (or KILASOS_TOKEN env var)")
	webhook    := flag.String("webhook",     "", "fallback webhook URL (or KILASOS_WEBHOOK env var)")
	webhookCfg := flag.String("webhook-cfg", "/var/lib/kilasos/webhook.json", "path to webhook config file")
	smtpCfg    := flag.String("smtp-cfg",    "/var/lib/kilasos/smtp.json",    "path to SMTP config file")
	wolDB       := flag.String("wol-db",      "/var/lib/kilasos/wol.json",      "path to Wake-on-LAN targets file")
	usersDB     := flag.String("users-db",     "/var/lib/kilasos/users.json",     "path to users file")
	sessionsDB  := flag.String("sessions-db",  "/var/lib/kilasos/sessions.json",  "path to sessions file")
	auditDB     := flag.String("audit-db",     "/var/lib/kilasos/audit.json",     "path to audit log file")
	schedulesDB := flag.String("schedules-db", "/var/lib/kilasos/schedules.json", "path to schedules file")
	remotesDB   := flag.String("remotes-db",   "/var/lib/kilasos/remotes.json",   "path to ZFS send remotes file")
	appsDB      := flag.String("apps-db",      "/var/lib/kilasos/apps.json",      "path to deployed apps file")
	rsyncDB     := flag.String("rsync-db",     "/var/lib/kilasos/rsync.json",     "path to rsync jobs file")
	appsDir     := flag.String("apps-dir",     "/opt/kilasos-apps",               "directory for app compose files")
	flag.Parse()

	if *showVersion {
		fmt.Printf("nasd %s (commit %s, built %s)\n", Version, Commit, BuildDate)
		os.Exit(0)
	}

	if *token == "" {
		*token = os.Getenv("KILASOS_TOKEN")
	}
	if *webhook == "" {
		*webhook = os.Getenv("KILASOS_WEBHOOK")
	}

	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	// License loading — degraded to Home mode on any failure (per §f)
	var lic *kilaoslicense.License
	pubKey, err := kilaoslicense.EmbeddedPublicKey()
	if err != nil {
		log.Warn("license embedded public key unavailable", "err", err)
	} else {
		data, err := os.ReadFile("/etc/kilasos/license.key")
		if err != nil {
			log.Info("no license key found, running in Home tier (free, 25 TB / 1 pool / 1 node cap)")
		} else {
			lic, err = kilaoslicense.Verify(data, pubKey)
			if err != nil {
				if errors.Is(err, kilaoslicense.ErrExpired) {
					log.Warn("license expired", "err", err)
				} else {
					log.Error("license verification failed", "err", err)
				}
			}
		}
	}
	if lic == nil || lic.Tier == kilaoslicense.TierHome {
		log.Info("running in Home tier (1 node, 1 pool, 25 TB raw cap)")
	} else {
		log.Info("running in Pro tier", "customer", lic.CustomerID, "nodes", lic.NodeCount)
	}

	var provider storage.Provider
	devMode := *dev || runtime.GOOS != "linux"
	if devMode {
		provider = storage.NewMock()
		log.Info("using mock storage provider")
	} else {
		provider = storage.NewLinux()
		log.Info("using linux storage provider")
	}

	// Build the tool registry in linux mode only.  Mock provider has no
	// shell-out tools to probe and would force startup-fail on a dev box.
	var tools *storage.ToolRegistry
	if !devMode {
		t, err := storage.NewToolRegistry(context.Background())
		if err != nil {
			log.Error("tool registry init failed", "err", err)
			os.Exit(1)
		}
		tools = t
		log.Info("tool registry ready")
	}

	usersPath      := *usersDB
	sessionsPath   := *sessionsDB
	auditPath      := *auditDB
	schedPath      := *schedulesDB
	remotesPath    := *remotesDB
	appsPath       := *appsDB
	appsDirPath    := *appsDir
	rsyncPath      := *rsyncDB
	webhookCfgPath := *webhookCfg
	smtpCfgPath    := *smtpCfg
	wolPath         := *wolDB
	if devMode {
		usersPath      = "./users.json"
		sessionsPath   = "./sessions.json"
		auditPath      = "./audit.json"
		rsyncPath      = "./rsync.json"
		schedPath      = "./schedules.json"
		remotesPath    = "./remotes.json"
		appsPath       = "./apps.json"
		appsDirPath    = "./kilasos-apps"
		webhookCfgPath = "./webhook.json"
		smtpCfgPath    = "./smtp.json"
		wolPath         = "./wol.json"
	}

	sessionDur := 24 * time.Hour
	if v := os.Getenv("SESSION_TTL_HOURS"); v != "" {
		if h, err := strconv.Atoi(v); err == nil && h > 0 {
			sessionDur = time.Duration(h) * time.Hour
		}
	}
	users, err := auth.NewUserStore(usersPath, sessionsPath, sessionDur)
	if err != nil {
		log.Error("failed to load user store", "err", err)
		os.Exit(1)
	}
	log.Info("user store loaded", "count", users.Count(), "path", usersPath)

	auditLog, err := audit.New(auditPath)
	if err != nil {
		log.Error("failed to load audit log", "err", err)
		os.Exit(1)
	}

	sched, err := scheduler.New(schedPath, provider)
	if err != nil {
		log.Error("failed to load scheduler", "err", err)
		os.Exit(1)
	}
	sched.SetLogger(auditLog)
	log.Info("scheduler loaded", "path", schedPath)

	replicator, err := wireReplicator(remotesPath)
	if err != nil {
		log.Error("failed to load zfssend replicator", "err", err)
		os.Exit(1)
	}
	log.Info("remotes loaded", "path", remotesPath)

	apps, err := appcatalog.NewManager(appsPath, appsDirPath)
	if err != nil {
		log.Error("failed to load app catalog", "err", err)
		os.Exit(1)
	}
	log.Info("app catalog loaded", "path", appsPath)

	rsyncMgr, err := rsync.NewManager(rsyncPath)
	if err != nil {
		log.Error("failed to load rsync jobs", "err", err)
		os.Exit(1)
	}
	log.Info("rsync jobs loaded", "path", rsyncPath)

	updater := sysupdate.NewManager()

	// Load webhook config from file; fall back to --webhook flag
	webhookURL, webhookSecret := *webhook, ""
	if data, err := os.ReadFile(webhookCfgPath); err == nil {
		var cfg struct {
			URL    string `json:"url"`
			Secret string `json:"secret"`
		}
		if json.Unmarshal(data, &cfg) == nil && cfg.URL != "" {
			webhookURL = cfg.URL
			webhookSecret = cfg.Secret
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	sched.SetSender(replicator)

	wolStore, err := wol.NewStore(wolPath)
	if err != nil {
		log.Error("failed to load wol targets", "err", err)
		os.Exit(1)
	}

	mon := monitor.New(provider, webhookURL, webhookSecret)
	if data, err := os.ReadFile(smtpCfgPath); err == nil {
		var cfg notify.SMTPConfig
		if json.Unmarshal(data, &cfg) == nil && cfg.Host != "" {
			mon.SetMailer(notify.NewMailer(cfg))
			log.Info("smtp mailer loaded", "host", cfg.Host)
		}
	}
	mon.Start(ctx)
	sched.Start(ctx)
	rsyncMgr.Start(ctx)
	go func() {
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				users.PruneExpiredSessions()
			}
		}
	}()

	hist := monitor.NewMetricsHistory()
	hist.Start(ctx, provider)

	oidcMgr := wireOIDC(users, auditLog)
	ldapMgr := wireLDAP(users, auditLog)
	backuper := wireBackup(provider)
	cm := wireCompliance(provider)
	router := api.NewRouter(provider, *token, mon, hist, auditLog, users, sched, replicator, apps, updater, webhookCfgPath, smtpCfgPath, wolStore, rsyncMgr, tools, lic, oidcMgr, ldapMgr, backuper, cm)
	srv := &http.Server{
		Addr:    *addr,
		Handler: router,
	}

	go func() {
		log.Info("nasd starting", "addr", *addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("server error", "err", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	log.Info("shutting down")

	shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutCtx); err != nil {
		log.Error("shutdown error", "err", err)
	}
}
