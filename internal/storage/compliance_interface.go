package storage

import "context"

// ComplianceManager is the interface for compliance & privacy operations.
type ComplianceManager interface {
	GenerateComplianceReport(ctx context.Context, format string) (string, error)
	GDPRExport(ctx context.Context, username string) (string, error)
	GDPRDelete(ctx context.Context, username string) error
	PrivacyMode(ctx context.Context) (PrivacyConfig, error)
	SetPrivacyMode(ctx context.Context, cfg PrivacyConfig) error
}
