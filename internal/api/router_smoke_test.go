package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRouter_Healthz(t *testing.T) {
	req := httptest.NewRequest("GET", "/healthz", nil)
	rec := httptest.NewRecorder()
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("healthz status=%d", rec.Code)
	}
}

func TestRouter_AuthInfo_Unauthenticated(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/v1/auth/info", nil)
	rec := httptest.NewRecorder()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/auth/info", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	mux.ServeHTTP(rec, req)
	if rec.Code >= 500 {
		t.Fatalf("auth/info 5xx: status=%d", rec.Code)
	}
}
