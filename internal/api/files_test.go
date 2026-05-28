package api

import (
	"bytes"
	"net/http/httptest"
	"testing"

	"github.com/kilasos/kilasos/internal/storage"
)

func TestFileDeleteHandler(t *testing.T) {
	mock := storage.NewMock()
	auditLog := newTestAuditLogger(t)

	cases := []struct {
		name, method, body string
		wantCode           int
	}{
		{"happy path", "POST", `{"path":"/mnt/pool1/foo.txt"}`, 200},
		{"wrong method", "GET", "", 405},
		{"bad json", "POST", "not json", 400},
		{"path traversal", "POST", `{"path":"/etc/passwd"}`, 403},
		{"empty path", "POST", `{"path":""}`, 403},
		{"mid-path traversal", "POST", `{"path":"/mnt/pool1/../../etc/passwd"}`, 403},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "/files/delete",
				bytes.NewBufferString(tc.body))
			req.Header.Set("Content-Type", "application/json")
			req = newAdminCtx(req)
			w := httptest.NewRecorder()
			fileDeleteHandler(mock, auditLog)(w, req)
			if w.Code != tc.wantCode {
				t.Errorf("got %d, want %d (body: %s)", w.Code, tc.wantCode, w.Body.String())
			}
		})
	}
}

func TestFolderZipHandler(t *testing.T) {
	mock := storage.NewMock()
	auditLog := newTestAuditLogger(t)

	cases := []struct {
		name, method, body string
		wantCode           int
	}{
		{"wrong method", "GET", "", 405},
		{"bad json", "POST", "not json", 400},
		{"path traversal", "POST", `{"path":"/etc/passwd"}`, 403},
		{"empty path", "POST", `{"path":""}`, 403},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "/files/folder-zip",
				bytes.NewBufferString(tc.body))
			req.Header.Set("Content-Type", "application/json")
			req = newAdminCtx(req)
			w := httptest.NewRecorder()
			folderZipHandler(mock, auditLog)(w, req)
			if w.Code != tc.wantCode {
				t.Errorf("got %d, want %d (body: %s)", w.Code, tc.wantCode, w.Body.String())
			}
		})
	}
}

func TestTrashListHandler(t *testing.T) {
	mock := storage.NewMock()
	auditLog := newTestAuditLogger(t)

	req := httptest.NewRequest("GET", "/trash/list", nil)
	req = newAdminCtx(req)
	w := httptest.NewRecorder()
	trashListHandler(mock, auditLog)(w, req)
	if w.Code != 200 {
		t.Errorf("got %d, want 200", w.Code)
	}

	req2 := httptest.NewRequest("POST", "/trash/list", nil)
	req2 = newAdminCtx(req2)
	w2 := httptest.NewRecorder()
	trashListHandler(mock, auditLog)(w2, req2)
	if w2.Code != 405 {
		t.Errorf("got %d, want 405 (wrong method)", w2.Code)
	}
}

func TestTrashRestoreHandler(t *testing.T) {
	mock := storage.NewMock()
	auditLog := newTestAuditLogger(t)

	cases := []struct {
		name, method, body string
		wantCode           int
	}{
		{"happy path", "POST", `{"trash_path":"/mnt/.trash/pool1/foo.txt"}`, 200},
		{"wrong method", "GET", "", 405},
		{"bad json", "POST", "not json", 400},
		{"path traversal", "POST", `{"trash_path":"/etc/passwd"}`, 403},
		{"empty path", "POST", `{"trash_path":""}`, 403},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "/trash/restore",
				bytes.NewBufferString(tc.body))
			req.Header.Set("Content-Type", "application/json")
			req = newAdminCtx(req)
			w := httptest.NewRecorder()
			trashRestoreHandler(mock, auditLog)(w, req)
			if w.Code != tc.wantCode {
				t.Errorf("got %d, want %d (body: %s)", w.Code, tc.wantCode, w.Body.String())
			}
		})
	}
}

func TestTrashEmptyHandler(t *testing.T) {
	mock := storage.NewMock()
	auditLog := newTestAuditLogger(t)

	req := httptest.NewRequest("POST", "/trash/empty", nil)
	req = newAdminCtx(req)
	w := httptest.NewRecorder()
	trashEmptyHandler(mock, auditLog)(w, req)
	if w.Code != 200 {
		t.Errorf("got %d, want 200", w.Code)
	}

	req2 := httptest.NewRequest("GET", "/trash/empty", nil)
	req2 = newAdminCtx(req2)
	w2 := httptest.NewRecorder()
	trashEmptyHandler(mock, auditLog)(w2, req2)
	if w2.Code != 405 {
		t.Errorf("got %d, want 405 (wrong method)", w2.Code)
	}
}
