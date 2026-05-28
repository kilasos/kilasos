package api

import (
	"errors"
	"net/http"

	"github.com/kilasos/kilasos/internal/license"
)

// handleLicenseErr maps license.ErrFeatureNotLicensed to a 402 Payment Required
// response and reports whether it matched. Callers use it before falling
// through to a generic 500:
//
//	if err != nil {
//	    if handleLicenseErr(w, err) { return }
//	    writeJSON(w, http.StatusInternalServerError, ...)
//	    return
//	}
//
// Returns false for any error that does not wrap ErrFeatureNotLicensed, so
// it is safe to drop in front of any 500-return without changing behavior
// for other error kinds.
func handleLicenseErr(w http.ResponseWriter, err error) bool {
	if errors.Is(err, license.ErrFeatureNotLicensed) {
		writeJSON(w, http.StatusPaymentRequired,
			map[string]string{"error": "feature requires a Pro license"})
		return true
	}
	return false
}
