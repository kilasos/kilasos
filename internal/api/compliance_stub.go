package api

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/kilasos/kilasos/internal/audit"
	"github.com/kilasos/kilasos/internal/storage"
)

func complianceReportHandler(cm storage.ComplianceManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		format := r.URL.Query().Get("format")
		if format == "" {
			format = "md"
		}
		report, err := cm.GenerateComplianceReport(r.Context(), format)
		if err != nil {
			if handleLicenseErr(w, err) {
				return
			}
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte(report))
	}
}

func gdprExportHandler(cm storage.ComplianceManager, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		username := r.URL.Query().Get("username")
		path, err := cm.GDPRExport(r.Context(), username)
		if err != nil {
			if handleLicenseErr(w, err) {
				return
			}
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"path": path})
	}
}

func gdprDeleteHandler(cm storage.ComplianceManager, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		username := chi.URLParam(r, "username")
		if err := cm.GDPRDelete(r.Context(), username); err != nil {
			if handleLicenseErr(w, err) {
				return
			}
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func privacyModeHandler(cm storage.ComplianceManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg, err := cm.PrivacyMode(r.Context())
		if err != nil {
			if handleLicenseErr(w, err) {
				return
			}
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, cfg)
	}
}

func setPrivacyModeHandler(cm storage.ComplianceManager, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		var cfg storage.PrivacyConfig
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if err := cm.SetPrivacyMode(r.Context(), cfg); err != nil {
			if handleLicenseErr(w, err) {
				return
			}
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}
