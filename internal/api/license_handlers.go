package api

import (
	"encoding/base64"
	"io"
	"net/http"
	"os"

	kilaoslicense "github.com/kilasos/kilasos/internal/license"
)

func licenseUploadHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "failed to read body"})
			return
		}
		tokenBytes := body

		if len(tokenBytes) == 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "empty token"})
			return
		}

		if tokenBytes[0] == 0x7B || (tokenBytes[0] == 0x1F && len(tokenBytes) > 1 && tokenBytes[1] == 0x8B) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "token appears to be a file, not raw bytes"})
			return
		}

		var data []byte
		if len(tokenBytes) > 128 && string(tokenBytes[:4]) == "KLS0" {
			data = tokenBytes
		} else {
			data, err = base64.StdEncoding.DecodeString(string(tokenBytes))
			if err != nil {
				data = tokenBytes
			}
		}

		pubKey, err := kilaoslicense.EmbeddedPublicKey()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error: " + err.Error()})
			return
		}

		_, err = kilaoslicense.Verify(data, pubKey)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}

		if err := os.WriteFile("/etc/kilasos/license.key", data, 0600); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to write license file: " + err.Error()})
			return
		}

		writeJSON(w, http.StatusOK, map[string]interface{}{
			"ok":              true,
			"requires_restart": true,
		})
	}
}

func licenseClearHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		if err := os.Remove("/etc/kilasos/license.key"); err != nil && !os.IsNotExist(err) {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to remove license: " + err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"ok":              true,
			"requires_restart": true,
		})
	}
}

