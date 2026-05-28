package api

import (
	"net/http"

	kilaoslicense "github.com/kilasos/kilasos/internal/license"
)

func requireFeature(feature string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			lic := licenseFromContext(r.Context())
			if !kilaoslicense.HasFeature(lic, feature) {
				writeJSON(w, http.StatusPaymentRequired, map[string]string{
					"error":   "feature requires a Pro license",
					"feature": feature,
				})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
