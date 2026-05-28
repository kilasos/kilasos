package api

import (
	"net/http"
	"strings"
)

type EnrichedAuditLogger interface {
	LogEnriched(AuditEntry)
}

type AuditEntry struct {
	User    string
	Action  string
	Detail  string
	IP      string
	OK      bool
}

type responseRecorder struct {
	w      http.ResponseWriter
	status int
}

func (r *responseRecorder) WriteHeader(status int) {
	r.status = status
	r.w.WriteHeader(status)
}

func (r *responseRecorder) Write(b []byte) (int, error) {
	return r.w.Write(b)
}

func (r *responseRecorder) Header() http.Header {
	return r.w.Header()
}

type AuditMiddlewareFunc func(http.Handler) http.Handler

func AuditMiddleware(log EnrichedAuditLogger) func(http.Handler) http.Handler {
	return AuditMiddlewareWith(log, func(r *http.Request) string {
		if ctx := r.Context(); ctx != nil {
			if val := ctx.Value(ctxKey(0)); val != nil {
				if s, ok := val.(string); ok {
					return s
				}
			}
		}
		return ""
	})
}

func AuditMiddlewareWith(log EnrichedAuditLogger, getUser func(*http.Request) string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost && r.Method != http.MethodPut && r.Method != http.MethodDelete && r.Method != http.MethodPatch {
				next.ServeHTTP(w, r)
				return
			}

			recorder := &responseRecorder{w: w, status: 200}
			next.ServeHTTP(recorder, r)

			ip := r.RemoteAddr
			if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
				ips := strings.Split(xff, ",")
				if len(ips) > 0 {
					ip = strings.TrimSpace(ips[0])
				}
			}

			action := r.Method + " " + r.URL.Path
			ok := recorder.status < 400

			log.LogEnriched(AuditEntry{
				User:    getUser(r),
				Action:  action,
				Detail:  "",
				IP:      ip,
				OK:      ok,
			})
		})
	}
}
