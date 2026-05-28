package api

import (
	"net/http"
	"net/http/httptest"
	"os"
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

func TestRequireFeature(t *testing.T) {
	router, token, cleanup := buildTestRouterForGate(t)
	defer cleanup()

	tests := []struct {
		method      string
		path        string
		feature     string
		wantStatus  int
	}{
		{"GET", "/api/v1/backup/jobs", "backup", http.StatusPaymentRequired},
		{"GET", "/api/v1/remotes", "zfssend", http.StatusPaymentRequired},
		{"GET", "/api/v1/security/gdpr/export", "gdpr", http.StatusPaymentRequired},
		{"GET", "/api/v1/security/compliance/report", "compliance", http.StatusPaymentRequired},
		{"GET", "/api/v1/security/privacy", "privacy", http.StatusPaymentRequired},
	}

	for _, tc := range tests {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			req.Header.Set("Authorization", "Bearer "+token)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			if w.Code != tc.wantStatus {
				t.Errorf("expected %d for %s %s (feature=%s), got %d (body: %s)",
					tc.wantStatus, tc.method, tc.path, tc.feature, w.Code, w.Body.String())
			}
		})
	}
}

func buildTestRouterForGate(t *testing.T) (http.Handler, string, func()) {
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
	_ = os.MkdirAll(appsDir, 0755)
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

