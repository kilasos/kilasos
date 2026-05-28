//go:build !pro

package api

import (
	"net/http"

	"github.com/kilasos/kilasos/internal/audit"
	"github.com/kilasos/kilasos/internal/storage"
)

func trivyScanHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		http.Error(w, "Container vulnerability scanning requires a Pro license", http.StatusPaymentRequired)
	}
}

func trivyResultsHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		http.Error(w, "Container vulnerability scanning requires a Pro license", http.StatusPaymentRequired)
	}
}

func runLynisHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		http.Error(w, "Security hardening audits require a Pro license", http.StatusPaymentRequired)
	}
}

func lynisStatusHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		http.Error(w, "Security hardening audits require a Pro license", http.StatusPaymentRequired)
	}
}

func lynisReportHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		http.Error(w, "Security hardening audits require a Pro license", http.StatusPaymentRequired)
	}
}

func apparmorStatusHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		http.Error(w, "AppArmor management requires a Pro license", http.StatusPaymentRequired)
	}
}

func selinuxStatusHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		http.Error(w, "SELinux management requires a Pro license", http.StatusPaymentRequired)
	}
}

func usbAllowlistHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		http.Error(w, "USB device management requires a Pro license", http.StatusPaymentRequired)
	}
}

func setUSBAllowlistHandler(p storage.Provider, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		http.Error(w, "USB device management requires a Pro license", http.StatusPaymentRequired)
	}
}

func blockUSBHandler(p storage.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		http.Error(w, "USB device management requires a Pro license", http.StatusPaymentRequired)
	}
}

func setAppArmorProfileHandler(p storage.Provider, auditLog *audit.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		http.Error(w, "AppArmor management requires a Pro license", http.StatusPaymentRequired)
	}
}