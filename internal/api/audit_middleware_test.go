package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

type stubLogger struct {
	entries []AuditEntry
}

func (s *stubLogger) LogEnriched(e AuditEntry) {
	s.entries = append(s.entries, e)
}

func TestAuditMiddleware_LogsPOST(t *testing.T) {
	logger := &stubLogger{}
	mw := AuditMiddlewareWith(logger, func(*http.Request) string { return "alice" })
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(204)
	}))
	req := httptest.NewRequest("POST", "/arrays/foo", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	h.ServeHTTP(httptest.NewRecorder(), req)

	if len(logger.entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(logger.entries))
	}
	e := logger.entries[0]
	if e.User != "alice" {
		t.Errorf("expected User='alice', got '%s'", e.User)
	}
	if e.Action != "POST /arrays/foo" {
		t.Errorf("expected Action='POST /arrays/foo', got '%s'", e.Action)
	}
	if e.IP != "10.0.0.1:1234" {
		t.Errorf("expected IP='10.0.0.1:1234', got '%s'", e.IP)
	}
	if !e.OK {
		t.Errorf("expected OK=true, got false")
	}
}

func TestAuditMiddleware_SkipsGET(t *testing.T) {
	logger := &stubLogger{}
	mw := AuditMiddlewareWith(logger, func(*http.Request) string { return "bob" })
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest("GET", "/", nil)
	h.ServeHTTP(httptest.NewRecorder(), req)

	if len(logger.entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(logger.entries))
	}
}

func TestAuditMiddleware_ForwardedFor(t *testing.T) {
	logger := &stubLogger{}
	mw := AuditMiddlewareWith(logger, func(*http.Request) string { return "alice" })
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest("POST", "/arrays/foo", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "203.0.113.5, 10.0.0.1")
	h.ServeHTTP(httptest.NewRecorder(), req)

	if len(logger.entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(logger.entries))
	}
	e := logger.entries[0]
	if e.IP != "203.0.113.5" {
		t.Errorf("expected IP='203.0.113.5', got '%s'", e.IP)
	}
}

func TestAuditMiddleware_4xxIsNotOK(t *testing.T) {
	logger := &stubLogger{}
	mw := AuditMiddlewareWith(logger, func(*http.Request) string { return "alice" })
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	req := httptest.NewRequest("POST", "/arrays/foo", nil)
	h.ServeHTTP(httptest.NewRecorder(), req)

	if len(logger.entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(logger.entries))
	}
	e := logger.entries[0]
	if e.OK {
		t.Errorf("expected OK=false for 4xx response, got true")
	}
}
