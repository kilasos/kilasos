package api

import (
	"encoding/json"
	"net/http"
)

type CapabilitiesProvider interface {
	AsMap() map[string]bool
}

func CapabilitiesHandler(cp CapabilitiesProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		data := map[string]interface{}{
			"schema_version": 1,
		}
		for k, v := range cp.AsMap() {
			data[k] = v
		}

		if err := json.NewEncoder(w).Encode(data); err != nil {
			http.Error(w, "failed to encode response", http.StatusInternalServerError)
			return
		}
	}
}
