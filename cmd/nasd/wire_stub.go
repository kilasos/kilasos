//go:build !pro

package main

import (
	"github.com/kilasos/kilasos/internal/audit"
	"github.com/kilasos/kilasos/internal/auth"
	"github.com/kilasos/kilasos/internal/storage"
	"github.com/kilasos/kilasos/internal/zfssend"
)

func wireOIDC(users *auth.UserStore, auditLog *audit.Logger) auth.OIDCAuthenticator {
	return auth.NewHomeOIDC(users, auditLog)
}

func wireLDAP(users *auth.UserStore, auditLog *audit.Logger) auth.LDAPAuthenticator {
	return auth.NewHomeLDAP(users)
}

func wireBackup(p storage.Provider) storage.Backuper {
	return p
}

func wireReplicator(path string) (zfssend.Replicator, error) {
	return zfssend.NewManager(path)
}

func wireCompliance(p storage.Provider) storage.ComplianceManager {
	return p
}
