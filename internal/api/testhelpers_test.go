package api

import (
	"context"
	"net/http"
	"os"

	"github.com/kilasos/kilasos/internal/audit"
	"github.com/kilasos/kilasos/internal/auth"
)

func newTestAuditLogger(tb interface{ Cleanup(func()) }) *audit.Logger {
	f, err := os.CreateTemp("", "kilasos-audit-test-*.json")
	if err != nil {
		panic(err)
	}
	tb.Cleanup(func() { os.Remove(f.Name()) })
	l, err := audit.New(f.Name())
	if err != nil {
		panic(err)
	}
	return l
}

func newAdminCtx(r *http.Request) *http.Request {
	ctx := context.WithValue(r.Context(), ctxRole, auth.RoleAdmin)
	ctx = context.WithValue(ctx, ctxUsername, "admin")
	return r.WithContext(ctx)
}

func newReadOnlyCtx(r *http.Request) *http.Request {
	ctx := context.WithValue(r.Context(), ctxRole, "user")
	ctx = context.WithValue(ctx, ctxUsername, "user")
	return r.WithContext(ctx)
}
