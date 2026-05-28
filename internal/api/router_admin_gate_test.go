package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/kilasos/kilasos/internal/appcatalog"
	"github.com/kilasos/kilasos/internal/auth"
	"github.com/kilasos/kilasos/internal/audit"
	"github.com/kilasos/kilasos/internal/monitor"
	"github.com/kilasos/kilasos/internal/rsync"
	"github.com/kilasos/kilasos/internal/scheduler"
	"github.com/kilasos/kilasos/internal/storage"
	"github.com/kilasos/kilasos/internal/sysupdate"
	"github.com/kilasos/kilasos/internal/wol"
	"github.com/kilasos/kilasos/internal/zfssend"
)

func buildTestRouter(t *testing.T) (http.Handler, string, func()) {
	dir := t.TempDir()

	provider := storage.NewMock()

	usersPath := dir + "/users.json"
	sessionsPath := dir + "/sessions.json"
	users, err := auth.NewUserStore(usersPath, sessionsPath, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	auditPath := dir + "/audit.json"
	auditLog, err := audit.New(auditPath)
	if err != nil {
		t.Fatal(err)
	}

	sched, err := scheduler.New(dir+"/schedules.json", provider)
	if err != nil {
		t.Fatal(err)
	}

	remotes, err := zfssend.NewManager(dir + "/remotes.json")
	if err != nil {
		t.Fatal(err)
	}

	appsDir := dir + "/apps"
	os.MkdirAll(appsDir, 0755)
	apps, err := appcatalog.NewManager(dir+"/apps.json", appsDir)
	if err != nil {
		t.Fatal(err)
	}

	rsyncMgr, err := rsync.NewManager(dir + "/rsync.json")
	if err != nil {
		t.Fatal(err)
	}

	updater := sysupdate.NewManager()

	wolStore, err := wol.NewStore(dir + "/wol.json")
	if err != nil {
		t.Fatal(err)
	}

	mon := monitor.New(provider, "", "")
	hist := monitor.NewMetricsHistory()

	if err := users.Register("testuser", "testpass123", "user"); err != nil {
		t.Fatal(err)
	}

	token, err := users.IssueToken("testuser", "local")
	if err != nil {
		t.Fatal(err)
	}

	router := NewRouter(provider, "", mon, hist, auditLog, users, sched, remotes, apps, updater, dir+"/webhook.json", dir+"/smtp.json", wolStore, rsyncMgr, nil, nil, auth.NewHomeOIDC(nil, nil), auth.NewHomeLDAP(nil), provider, provider)

	cleanup := func() {
		os.RemoveAll(dir)
	}

	return router, token, cleanup
}

func TestAdminGating(t *testing.T) {
	router, nonAdminToken, cleanup := buildTestRouter(t)
	defer cleanup()

	adminGated := []struct {
		method, path, body string
	}{
		{"GET", "/api/v1/users", ""},
		{"POST", "/api/v1/users", `{"username":"new","password":"pass123","role":"user"}`},
		{"DELETE", "/api/v1/users/testuser", ""},
		{"PATCH", "/api/v1/users/testuser/role", `{"role":"admin"}`},
		{"PUT", "/api/v1/arrays/abc/quota", `{"quota":"10G"}`},
		{"POST", "/api/v1/containers/abc/start", ""},
		{"POST", "/api/v1/containers/abc/stop", ""},
		{"POST", "/api/v1/containers/abc/restart", ""},
		{"POST", "/api/v1/containers/abc/exec", `{"command":"ls"}`},
		{"POST", "/api/v1/disks/sda/wipe", ""},
		{"GET", "/api/v1/audit/retention", ""},
	}
	for _, route := range adminGated {
		t.Run(route.method+" "+route.path, func(t *testing.T) {
			body := strings.NewReader(route.body)
			req := httptest.NewRequest(route.method, route.path, body)
			if route.body != "" {
				req.Header.Set("Content-Type", "application/json")
			}
			req.Header.Set("Authorization", "Bearer "+nonAdminToken)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			if w.Code != 403 {
				t.Errorf("expected 403 for non-admin on %s %s, got %d (body: %s)", route.method, route.path, w.Code, w.Body.String())
			}
		})
	}

	// Pro-gated security routes: requireFeature runs before requireAdmin,
	// so non-admin+nolicens users get 402, not 403.
	proGatedSecurity := []struct {
		method, path, body string
	}{
		{"POST", "/api/v1/security/trivy/scan", ""},
		{"POST", "/api/v1/security/lynis/run", ""},
		{"GET", "/api/v1/security/apparmor", ""},
		{"GET", "/api/v1/security/selinux", ""},
		{"GET", "/api/v1/security/usb/allowlist", ""},
	}
	for _, route := range proGatedSecurity {
		t.Run(route.method+" "+route.path+" (pro-gate)", func(t *testing.T) {
			body := strings.NewReader(route.body)
			req := httptest.NewRequest(route.method, route.path, body)
			if route.body != "" {
				req.Header.Set("Content-Type", "application/json")
			}
			req.Header.Set("Authorization", "Bearer "+nonAdminToken)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			if w.Code != http.StatusPaymentRequired {
				t.Errorf("expected 402 for pro-gated %s %s, got %d (body: %s)", route.method, route.path, w.Code, w.Body.String())
			}
		})
	}

	publicOrReadOnly := []struct {
		method, path string
	}{
		{"GET", "/api/v1/disks"},
		{"GET", "/api/v1/files/list?path=/mnt"},
		{"GET", "/api/v1/files/tree?path=/mnt"},
		{"GET", "/api/v1/auth/sessions"},
		{"GET", "/api/v1/auth/api-keys"},
		{"GET", "/api/v1/shares"},
		{"GET", "/api/v1/containers"},
		{"GET", "/api/v1/alerts"},
		{"GET", "/api/v1/metrics"},
		{"GET", "/api/v1/network/interfaces"},
		{"GET", "/api/v1/apps"},
		{"GET", "/api/v1/app-stacks"},
		{"GET", "/api/v1/auth/info"},
		{"GET", "/api/v1/trash/list"},
		{"GET", "/api/v1/notification-channels"},
		{"GET", "/api/v1/alert-rules"},
		{"GET", "/api/v1/syslog-forwarding"},
	}
	for _, route := range publicOrReadOnly {
		t.Run(route.method+" "+route.path+" (allowed)", func(t *testing.T) {
			req := httptest.NewRequest(route.method, route.path, nil)
			req.Header.Set("Authorization", "Bearer "+nonAdminToken)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			if w.Code == 403 {
				t.Errorf("expected allowed (non-403) for non-admin on %s %s, got 403 (body: %s)", route.method, route.path, w.Body.String())
			}
		})
	}
}
