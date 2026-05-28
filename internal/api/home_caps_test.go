package api

import (
	"context"
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
	kilaoslicense "github.com/kilasos/kilasos/internal/license"
	"github.com/kilasos/kilasos/internal/zfssend"
)

func TestEnforcePoolCountHelper(t *testing.T) {
	provider := storage.NewMock()

	homeLic := &kilaoslicense.License{Tier: kilaoslicense.TierHome, NodeCount: 1}
	proLic := &kilaoslicense.License{Tier: kilaoslicense.TierPro, NodeCount: 4}
	expiredProLic := &kilaoslicense.License{Tier: kilaoslicense.TierPro, NodeCount: 4}
	expiredProLic.NotAfter = time.Now().Add(-1 * time.Hour)

	proCtx := context.WithValue(context.Background(), ctxLicense, proLic)
	homeCtx := context.WithValue(context.Background(), ctxLicense, homeLic)
	expiredCtx := context.WithValue(context.Background(), ctxLicense, expiredProLic)
	nilCtx := context.Background()

	type poolCase struct {
		name       string
		ctx        context.Context
		wantErr    bool
		errContain string
	}

	cases := []poolCase{
		{"Home nil license", nilCtx, false, ""},
		{"Home license", homeCtx, false, ""},
		{"Pro license → bypass", proCtx, false, ""},
		{"Expired Pro → treated as Home", expiredCtx, false, ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil).WithContext(tc.ctx)
			err := enforcePoolCount(provider, req)
			if tc.wantErr {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tc.errContain)
				} else if !strings.Contains(err.Error(), tc.errContain) {
					t.Errorf("expected error containing %q, got %q", tc.errContain, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("expected no error, got %q", err.Error())
				}
			}
		})
	}
}

func TestEnforceRawCapacityHelper(t *testing.T) {
	provider := storage.NewMock()

	homeLic := &kilaoslicense.License{Tier: kilaoslicense.TierHome, NodeCount: 1}
	proLic := &kilaoslicense.License{Tier: kilaoslicense.TierPro, NodeCount: 4}

	proCtx := context.WithValue(context.Background(), ctxLicense, proLic)
	homeCtx := context.WithValue(context.Background(), ctxLicense, homeLic)

	type capCase struct {
		name        string
		ctx         context.Context
		newDevices  []string
		wantErr     bool
		errContain  string
	}

	cases := []capCase{
		{"Home nil newDevices", homeCtx, nil, false, ""},
		{"Home with newDevices", homeCtx, []string{}, false, ""},
		{"Pro bypass", proCtx, nil, false, ""},
		{"Pro with newDevices", proCtx, []string{}, false, ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil).WithContext(tc.ctx)
			err := enforceRawCapacity(provider, req, tc.newDevices)
			if tc.wantErr {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tc.errContain)
				} else if !strings.Contains(err.Error(), tc.errContain) {
					t.Errorf("expected error containing %q, got %q", tc.errContain, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("expected no error, got %q", err.Error())
				}
			}
		})
	}
}

func buildCapsTestRouter(t *testing.T, lic *kilaoslicense.License) (http.Handler, string, func()) {
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
	router := NewRouter(provider, "", mon, hist, auditLog, users, sched, remotes, apps, updater, dir+"/webhook.json", dir+"/smtp.json", wolStore, rsyncMgr, nil, lic, auth.NewHomeOIDC(nil, nil), auth.NewHomeLDAP(nil), provider, provider)
	cleanup := func() {
		os.RemoveAll(dir)
	}
	return router, token, cleanup
}

func TestEnforcePoolCountViaHTTP(t *testing.T) {
	homeLic := &kilaoslicense.License{Tier: kilaoslicense.TierHome, NodeCount: 1}
	proLic := &kilaoslicense.License{Tier: kilaoslicense.TierPro, NodeCount: 4}
	expiredProLic := &kilaoslicense.License{Tier: kilaoslicense.TierPro, NodeCount: 4, NotAfter: time.Now().Add(-1 * time.Hour)}

	for licName, lic := range map[string]*kilaoslicense.License{"Home": homeLic, "Pro": proLic, "ExpiredPro": expiredProLic} {
		router, token, cleanup := buildCapsTestRouter(t, lic)
		defer cleanup()

		t.Run(licName+": POST /arrays without body", func(t *testing.T) {
			req := httptest.NewRequest("POST", "/api/v1/arrays", strings.NewReader(`{"name":"test","type":"zfs","devices":["sda"]}`))
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			if licName == "Home" || licName == "ExpiredPro" {
				if w.Code == http.StatusForbidden && strings.Contains(w.Body.String(), "1 pool") {
					t.Logf("%s: pool cap enforced: %s", licName, w.Body.String())
				}
			}
			if licName == "Pro" {
				if w.Code == http.StatusForbidden && strings.Contains(w.Body.String(), "1 pool") {
					t.Errorf("Pro should bypass pool cap, got: %s", w.Body.String())
				}
			}
		})
	}
}
