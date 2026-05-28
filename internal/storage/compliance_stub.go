package storage

import (
	"context"

	"github.com/kilasos/kilasos/internal/license"
)

func (p *linuxProvider) GenerateComplianceReport(ctx context.Context, format string) (string, error) {
	return "", license.ErrFeatureNotLicensed
}

func (p *linuxProvider) GDPRExport(ctx context.Context, username string) (string, error) {
	return "", license.ErrFeatureNotLicensed
}

func (p *linuxProvider) GDPRDelete(ctx context.Context, username string) error {
	return license.ErrFeatureNotLicensed
}

func (p *linuxProvider) PrivacyMode(ctx context.Context) (PrivacyConfig, error) {
	return PrivacyConfig{}, license.ErrFeatureNotLicensed
}

func (p *linuxProvider) SetPrivacyMode(ctx context.Context, cfg PrivacyConfig) error {
	return license.ErrFeatureNotLicensed
}
