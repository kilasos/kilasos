//go:build !pro

package storage

import (
	"context"

	"github.com/kilasos/kilasos/internal/license"
)

func (p *linuxProvider) TrivyScan(ctx context.Context, image string) (CVEReport, error) {
	return CVEReport{}, license.ErrFeatureNotLicensed
}

func (p *linuxProvider) TrivyResults(ctx context.Context, image string) (CVEReport, error) {
	return CVEReport{}, license.ErrFeatureNotLicensed
}

func (p *linuxProvider) RunLynis(ctx context.Context) (string, error) {
	return "", license.ErrFeatureNotLicensed
}

func (p *linuxProvider) LynisStatus(ctx context.Context) (LynisStatus, error) {
	return LynisStatus{}, license.ErrFeatureNotLicensed
}

func (p *linuxProvider) LynisReport(ctx context.Context) ([]LynisFinding, error) {
	return nil, license.ErrFeatureNotLicensed
}

func (p *linuxProvider) AppArmorStatus(ctx context.Context) ([]AppArmorProfile, error) {
	return nil, license.ErrFeatureNotLicensed
}

func (p *linuxProvider) SetAppArmorProfile(ctx context.Context, name, mode string) error {
	return license.ErrFeatureNotLicensed
}

func (p *linuxProvider) SELinuxStatus(ctx context.Context) (SELinuxInfo, error) {
	return SELinuxInfo{}, license.ErrFeatureNotLicensed
}

func (p *linuxProvider) USBAllowlist(ctx context.Context) ([]string, error) {
	return nil, license.ErrFeatureNotLicensed
}

func (p *linuxProvider) SetUSBAllowlist(ctx context.Context, ids []string) error {
	return license.ErrFeatureNotLicensed
}

func (p *linuxProvider) BlockUSB(ctx context.Context, id string) error {
	return license.ErrFeatureNotLicensed
}