package storage

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/kilasos/kilasos/internal/appcatalog"
)

type mockProvider struct{}

func NewMock() Provider { return &mockProvider{} }

func iptr(v int) *int { return &v }

var mockDisks = []Disk{
	{
		Name: "sda", Path: "/dev/sda",
		SizeBytes: 24 * 1024 * 1024 * 1024, Model: "Mock SSD Alpha",
		SmartOK: true, TempCelsius: iptr(35), PowerOnHours: iptr(1000),
	},
	{
		Name: "sdb", Path: "/dev/sdb",
		SizeBytes: 8 * 1024 * 1024 * 1024, Model: "Mock HDD Beta",
		SmartOK: true, TempCelsius: iptr(40), PowerOnHours: iptr(5000), ReallocatedSectors: iptr(0),
	},
	{
		Name: "sdc", Path: "/dev/sdc",
		SizeBytes: 8 * 1024 * 1024 * 1024, Model: "Mock HDD Gamma",
		SmartOK: true, TempCelsius: iptr(38), PowerOnHours: iptr(3000), ReallocatedSectors: iptr(0),
	},
}

func (m *mockProvider) Disks(_ context.Context) ([]Disk, error)  { return mockDisks, nil }
func (m *mockProvider) Arrays(_ context.Context) ([]Array, error) { return []Array{}, nil }
func (m *mockProvider) CreateArray(_ context.Context, spec ArraySpec, _ bool) (Array, error) {
	return Array{ArraySpec: spec, Status: "online"}, nil
}
func (m *mockProvider) StartArray(_ context.Context, _ string) error  { return nil }
func (m *mockProvider) StopArray(_ context.Context, _ string) error   { return nil }
func (m *mockProvider) DeleteArray(_ context.Context, _ string) error { return nil }
func (m *mockProvider) Shares(_ context.Context) ([]Share, error)     { return []Share{}, nil }
func (m *mockProvider) CreateShare(_ context.Context, s Share) (Share, error) {
	return s, nil
}
func (m *mockProvider) DeleteShare(_ context.Context, _ string) error { return nil }
var mockContainers = []Container{
	{ID: "abc123def456abc1", Name: "nginx", Image: "nginx:latest", State: "running", Status: "Up 2 hours", Created: 1700000000, Ports: []string{"0.0.0.0:8080->80/tcp"}},
	{ID: "def456abc789def2", Name: "redis", Image: "redis:7", State: "exited", Status: "Exited (0) 1 hour ago", Created: 1700000000, Ports: []string{}},
}

func (m *mockProvider) PoolHealth(_ context.Context, name string) (PoolHealth, error) {
	return PoolHealth{
		Name: name, State: "online",
		SizeBytes: 16 * 1024 * 1024 * 1024, AllocBytes: 4 * 1024 * 1024 * 1024,
		FreeBytes: 12 * 1024 * 1024 * 1024, FragPercent: 3,
		VDevs: []VDev{
			{Name: "mirror-0", State: "online", Indent: 0},
			{Name: "/dev/sdb", State: "online", Indent: 1},
			{Name: "/dev/sdc", State: "online", Indent: 1},
		},
		Scrub: ScrubStatus{State: "completed", Progress: 100, Errors: 0},
	}, nil
}
func (m *mockProvider) StartScrub(_ context.Context, _ string) error { return nil }
func (m *mockProvider) Snapshots(_ context.Context, pool string) ([]Snapshot, error) {
	return []Snapshot{
		{Name: "snap-20260429-120000", Pool: pool, FullName: pool + "@snap-20260429-120000",
			Created: 1777460000, UsedBytes: 0, RefdBytes: 4 * 1024 * 1024 * 1024},
	}, nil
}
func (m *mockProvider) CreateSnapshot(_ context.Context, pool, name string) (Snapshot, error) {
	return Snapshot{Name: name, Pool: pool, FullName: pool + "@" + name, Created: time.Now().Unix()}, nil
}
func (m *mockProvider) DeleteSnapshot(_ context.Context, _, _ string) error   { return nil }
func (m *mockProvider) RollbackSnapshot(_ context.Context, _, _ string) error { return nil }
func (m *mockProvider) GetSettings(_ context.Context) (SystemSettings, error) {
	return SystemSettings{Hostname: "kilasos-dev", Timezone: "UTC", NTPEnabled: true, NTPSynced: true}, nil
}
func (m *mockProvider) ApplySettings(_ context.Context, _ SettingsUpdate) error { return nil }

func (m *mockProvider) Containers(_ context.Context) ([]Container, error)          { return mockContainers, nil }
func (m *mockProvider) StartContainer(_ context.Context, _ string) error           { return nil }
func (m *mockProvider) StopContainer(_ context.Context, _ string) error            { return nil }
func (m *mockProvider) RemoveContainer(_ context.Context, _ string) error          { return nil }

func (m *mockProvider) NetInterfaces(_ context.Context) ([]NetworkIface, error) {
	return []NetworkIface{
		{Name: "eth0", MAC: "52:54:00:ab:cd:ef", IPAddresses: []string{"10.10.1.211/24"}, SpeedMbps: 1000, Operstate: "up", IsDefault: true, MTU: 1500},
		{Name: "eth1", MAC: "52:54:00:11:22:33", IPAddresses: []string{}, SpeedMbps: -1, Operstate: "down", IsDefault: false, MTU: 1500},
	}, nil
}
func (m *mockProvider) SetInterfaceState(_ context.Context, _ string, _ bool) error { return nil }
func (m *mockProvider) GetPowerStatus(_ context.Context) (PowerStatus, error) {
	return PowerStatus{Pending: false}, nil
}
func (m *mockProvider) Shutdown(_ context.Context, _ int) error        { return nil }
func (m *mockProvider) Reboot(_ context.Context, _ int) error          { return nil }
func (m *mockProvider) CancelShutdown(_ context.Context) error         { return nil }
func (m *mockProvider) SetDiskSpindown(_ context.Context, _ string, _ int) error { return nil }

var mockSSHKeys = []SSHKey{
	{Type: "ssh-ed25519", Key: "AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyBlobHere1234567890abcdef", Comment: "user@laptop"},
}

func (m *mockProvider) SSHKeys(_ context.Context) ([]SSHKey, error) { return mockSSHKeys, nil }
func (m *mockProvider) AddSSHKey(_ context.Context, pubkey string) (SSHKey, error) {
	fields := strings.Fields(pubkey)
	if len(fields) < 2 {
		return SSHKey{}, fmt.Errorf("invalid key")
	}
	k := SSHKey{Type: fields[0], Key: fields[1]}
	if len(fields) > 2 {
		k.Comment = strings.Join(fields[2:], " ")
	}
	mockSSHKeys = append(mockSSHKeys, k)
	return k, nil
}
func (m *mockProvider) GetIfaceConfig(_ context.Context, name string) (IfaceConfig, error) {
	if name == "eth0" {
		return IfaceConfig{DHCP: false, Address: "10.10.1.211/24", Gateway: "10.10.1.1", DNS: []string{"8.8.8.8", "1.1.1.1"}}, nil
	}
	return IfaceConfig{DHCP: true}, nil
}
func (m *mockProvider) SetIfaceConfig(_ context.Context, _ string, _ IfaceConfig) error { return nil }

func (m *mockProvider) DeleteSSHKey(_ context.Context, blob string) error {
	for i, k := range mockSSHKeys {
		if k.Key == blob {
			mockSSHKeys = append(mockSSHKeys[:i], mockSSHKeys[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("key not found")
}

func (m *mockProvider) GetDatasetQuota(_ context.Context, _ string) (DatasetQuota, error) {
	return DatasetQuota{
		QuotaBytes: 0, ReservationBytes: 0,
		UsedBytes: 4 * 1024 * 1024 * 1024, AvailableBytes: 12 * 1024 * 1024 * 1024,
	}, nil
}
func (m *mockProvider) SetDatasetQuota(_ context.Context, _ string, _ QuotaUpdate) error { return nil }

func (m *mockProvider) StartSmartTest(_ context.Context, _ string, _ string) error { return nil }
func (m *mockProvider) GetSmartTestStatus(_ context.Context, devPath string) (SmartTestStatus, error) {
	return SmartTestStatus{Running: false, Progress: 0, StatusString: "Completed without error"}, nil
}

func (m *mockProvider) Metrics(_ context.Context) (SystemMetrics, error) {
	return SystemMetrics{
		CPUPercent: 23.5,
		MemTotal:   8 * 1024 * 1024 * 1024,
		MemUsed:    3 * 1024 * 1024 * 1024,
		NetInterfaces: []NetIface{
			{Name: "eth0", RxBytesPerSec: 1.2 * 1024 * 1024, TxBytesPerSec: 512 * 1024},
		},
		PoolUsage: []PoolUsage{
			{Name: "datapool", Total: 16 * 1024 * 1024 * 1024, Used: 4 * 1024 * 1024 * 1024, Free: 12 * 1024 * 1024 * 1024},
		},
	}, nil
}

func (m *mockProvider) ImportCandidates(_ context.Context) ([]ImportCandidate, error) {
	return []ImportCandidate{
		{Name: "backup-pool", GUID: "12345678901234567", State: "ONLINE", Disks: []string{"sde"}},
	}, nil
}

func (m *mockProvider) ImportPool(_ context.Context, _, _ string) error { return nil }

func (m *mockProvider) ReplaceDisk(_ context.Context, _, _, _ string) error { return nil }

func (m *mockProvider) Datasets(_ context.Context, pool string) ([]Dataset, error) {
	return []Dataset{
		{Name: pool + "/media", Pool: pool, MountPoint: "/mnt/" + pool + "/media", UsedBytes: 1 << 30, AvailBytes: 10 << 30},
	}, nil
}

func (m *mockProvider) CreateDataset(_ context.Context, pool, name string) (Dataset, error) {
	return Dataset{Name: pool + "/" + name, Pool: pool, MountPoint: "/mnt/" + pool + "/" + name}, nil
}

func (m *mockProvider) DeleteDataset(_ context.Context, _, _ string) error { return nil }

func (m *mockProvider) CreateEncryptedDataset(_ context.Context, pool, name, _ string) (Dataset, error) {
	return Dataset{Name: pool + "/" + name, Pool: pool, Encrypted: true}, nil
}

func (m *mockProvider) LoadEncryptionKey(_ context.Context, _, _ string) error { return nil }

func (m *mockProvider) ContainerStats(_ context.Context, _ string) (ContainerStats, error) {
	return ContainerStats{CPUPercent: 2.5, MemUsed: 128 << 20, MemLimit: 1 << 30, MemPercent: 12.5, RxBytes: 1 << 20, TxBytes: 512 << 10}, nil
}

func (m *mockProvider) ContainerLogs(_ context.Context, _, _ string) (string, error) {
	return "2026-01-01T00:00:00Z container starting\n2026-01-01T00:00:01Z ready on :8080\n", nil
}

func (m *mockProvider) ARCStats(_ context.Context) (ARCStats, error) {
	return ARCStats{SizeBytes: 512 << 20, MaxBytes: 1 << 30, HitPct: 98.5}, nil
}

func (m *mockProvider) SystemInfo(_ context.Context) (SystemInfo, error) {
	return SystemInfo{Hostname: "kilasos", OS: "KilasOS 1.0", Kernel: "6.1.0", Uptime: 86400, LoadAvg1: 0.5, CPUCores: 4}, nil
}

func (m *mockProvider) UpdateShare(_ context.Context, name string, update Share) (Share, error) {
	update.Name = name
	return update, nil
}

func (m *mockProvider) WipeDisk(_ context.Context, _ string) error { return nil }

func (m *mockProvider) TrimPool(_ context.Context, _ string) error { return nil }

func (m *mockProvider) PullImage(_ context.Context, image string) (string, error) {
	return "Pulling " + image + "… done", nil
}

func (m *mockProvider) DiskIO(_ context.Context) ([]DiskIO, error) {
	return []DiskIO{
		{Name: "sda", ReadBytesPS: 12582912, WriteBytesPS: 4194304},
		{Name: "sdb", ReadBytesPS: 524288, WriteBytesPS: 1048576},
	}, nil
}

func (m *mockProvider) Processes(_ context.Context) ([]Process, error) {
	return []Process{
		{PID: 1, User: "root", CPUPct: 0.0, MemPct: 0.1, MemRSS: 8192000, Command: "systemd"},
		{PID: 1234, User: "root", CPUPct: 5.2, MemPct: 2.3, MemRSS: 94371840, Command: "nasd"},
		{PID: 1500, User: "root", CPUPct: 0.8, MemPct: 0.5, MemRSS: 20480000, Command: "dockerd"},
	}, nil
}

func (m *mockProvider) DockerVolumes(_ context.Context) ([]DockerVolume, error) {
	return []DockerVolume{
		{Name: "plex_config", Driver: "local", Mountpoint: "/var/lib/docker/volumes/plex_config/_data", SizeBytes: 104857600},
		{Name: "nextcloud_data", Driver: "local", Mountpoint: "/var/lib/docker/volumes/nextcloud_data/_data", SizeBytes: -1},
	}, nil
}

func (m *mockProvider) RemoveDockerVolume(_ context.Context, _ string) error { return nil }

func (m *mockProvider) NetDiag(_ context.Context, diagType, target string) (NetDiagResult, error) {
	return NetDiagResult{Target: target, Type: diagType, Output: "mock: " + diagType + " " + target + " OK", Success: true}, nil
}

func (m *mockProvider) SMBConnections(_ context.Context) ([]SMBConnection, error) {
	return []SMBConnection{
		{PID: 1234, Username: "alice", Machine: "192.168.1.10", Connected: "Sat May  3 14:22:00 2025"},
	}, nil
}

func (m *mockProvider) CloneSnapshot(_ context.Context, _, _, _ string) error { return nil }

func (m *mockProvider) Resilver(_ context.Context, _ string) error { return nil }

func (m *mockProvider) ExpandPool(_ context.Context, _ string) error { return nil }

func (m *mockProvider) SearchJournal(_ context.Context, query string, _ int) ([]JournalSearchResult, error) {
	return []JournalSearchResult{
		{Unit: "nasd.service", Time: "2025-05-03 14:00:00", Message: "mock search result for: " + query},
	}, nil
}

func (m *mockProvider) PoolEvents(_ context.Context, pool string) ([]PoolEvent, error) {
	return []PoolEvent{
		{Time: 1700000000, Pool: pool, Class: "resource.fs.zfs.ok", Message: pool + ": pool scrub done, 0 errors"},
	}, nil
}

func (m *mockProvider) InspectContainer(_ context.Context, id string) (ContainerInspect, error) {
	return ContainerInspect{
		ID: id, Name: "mock-container", Image: "nginx:alpine", Created: "2024-01-01T00:00:00Z",
		RestartPolicy: "unless-stopped",
		Env:    []string{"PATH=/usr/local/sbin:/usr/local/bin", "NGINX_VERSION=1.25"},
		Mounts: []ContainerMount{{Type: "volume", Source: "nginx_data", Destination: "/data", RW: true}},
		Networks: []string{"bridge"}, CPUShares: 0, MemLimit: 0,
	}, nil
}

func (m *mockProvider) PoolIO(_ context.Context) ([]PoolIO, error) {
	return []PoolIO{
		{Name: "datapool", ReadOpPS: 12, WriteOpPS: 5, ReadBytesPS: 1048576, WriteBytesPS: 524288},
	}, nil
}

func (m *mockProvider) DockerImages(_ context.Context) ([]DockerImage, error) {
	return []DockerImage{
		{ID: "abc123def456", Tags: []string{"nginx:latest"}, SizeBytes: 141000000, Created: 1700000000},
		{ID: "def456ghi789", Tags: []string{"plex/plex:latest"}, SizeBytes: 310000000, Created: 1699000000},
		{ID: "ghi789jkl012", Tags: []string{"<none>"}, SizeBytes: 50000000, Created: 1698000000},
	}, nil
}

func (m *mockProvider) RemoveDockerImage(_ context.Context, _ string) error { return nil }

func (m *mockProvider) GetDatasetProps(_ context.Context, _ string) (DatasetProps, error) {
	return DatasetProps{Compression: "lz4", Atime: "off", Recordsize: "128K", Dedup: "off", Checksum: "on", Readonly: "off", Snapdir: "hidden"}, nil
}

func (m *mockProvider) SetDatasetProps(_ context.Context, _ string, _ DatasetPropsUpdate) error {
	return nil
}

func (m *mockProvider) SmartDetail(_ context.Context, devPath string) (SmartDetail, error) {
	t, h := 38, 8760
	return SmartDetail{
		DevPath: devPath, Model: "WDC WD40EZRZ", Serial: "WD-MOCK01",
		Firmware: "80.00A80", CapacityGB: 4000, SmartOK: true,
		TempC: &t, PowerOnH: &h,
		Attributes: []SmartAttr{
			{ID: 1, Name: "Raw_Read_Error_Rate", Value: 200, Worst: 200, Raw: "0"},
			{ID: 5, Name: "Reallocated_Sector_Ct", Value: 200, Worst: 200, Raw: "0"},
			{ID: 190, Name: "Airflow_Temperature_Cel", Value: 62, Worst: 55, Raw: "38"},
			{ID: 194, Name: "Temperature_Celsius", Value: 112, Worst: 99, Raw: "38"},
			{ID: 197, Name: "Current_Pending_Sector", Value: 200, Worst: 200, Raw: "0"},
			{ID: 198, Name: "Offline_Uncorrectable", Value: 200, Worst: 200, Raw: "0"},
		},
	}, nil
}

func (m *mockProvider) GetPoolProps(_ context.Context, _ string) (ZFSPoolProps, error) {
	return ZFSPoolProps{
		Atime: "off", Compression: "lz4", Dedup: "off",
		Autoexpand: "off", Autoreplace: "off", Listsnapshots: "off",
	}, nil
}

func (m *mockProvider) SetPoolProps(_ context.Context, _ string, _ ZFSPoolPropsUpdate) error {
	return nil
}

func (m *mockProvider) ScanServices(_ context.Context, _ string) ([]ServiceDiscovery, error) {
	return []ServiceDiscovery{
		{Host: "10.10.1.1", Port: 22, Service: "ssh", Banner: "SSH-2.0-OpenSSH_8.9"},
		{Host: "10.10.1.1", Port: 80, Service: "http"},
		{Host: "10.10.1.1", Port: 443, Service: "https"},
	}, nil
}

func (m *mockProvider) PendingUpdates(_ context.Context) ([]PackageUpdate, error) {
	return []PackageUpdate{
		{Name: "linux-image-amd64", CurrentVersion: "6.1.0-20", NewVersion: "6.1.0-21"},
		{Name: "openssl", CurrentVersion: "3.0.11-1", NewVersion: "3.0.13-1"},
		{Name: "curl", CurrentVersion: "7.88.1-10", NewVersion: "7.88.1-11"},
	}, nil
}

func (m *mockProvider) SystemUsers(_ context.Context) ([]SystemUser, error) {
	return []SystemUser{
		{Name: "root", UID: 0, GID: 0, Home: "/root", Shell: "/bin/bash", Groups: []string{"root"}},
		{Name: "kilas", UID: 1000, GID: 1000, Home: "/home/kilas", Shell: "/bin/bash", Groups: []string{"kilas", "sudo", "docker"}},
	}, nil
}

func (m *mockProvider) AddSystemUser(_ context.Context, _, _ string) error { return nil }

func (m *mockProvider) DeleteSystemUser(_ context.Context, _ string) error { return nil }

func (m *mockProvider) CronJobs(_ context.Context) ([]CronJob, error) {
	return []CronJob{
		{User: "root", Schedule: "0 * * * *", Command: "/usr/sbin/logrotate /etc/logrotate.conf", Source: "/etc/cron.d/logrotate"},
		{User: "root", Schedule: "*/5 * * * *", Command: "/usr/lib/nagios/plugins/check_disk", Source: "/etc/cron.d/nagios"},
	}, nil
}

func (m *mockProvider) CPUFreq(_ context.Context) (CPUFreqInfo, error) {
	return CPUFreqInfo{
		Cores: []CPUCore{
			{ID: 0, FreqMHz: 2400, MaxFreqMHz: 3600},
			{ID: 1, FreqMHz: 2200, MaxFreqMHz: 3600},
			{ID: 2, FreqMHz: 2800, MaxFreqMHz: 3600},
			{ID: 3, FreqMHz: 1800, MaxFreqMHz: 3600},
		},
		Zones: []ThermalZone{
			{Name: "x86_pkg_temp", TempC: 52.0},
			{Name: "acpitz", TempC: 27.8},
		},
	}, nil
}

func (m *mockProvider) BenchmarkDisk(_ context.Context, devPath string) (DiskBenchmark, error) {
	return DiskBenchmark{DevPath: devPath, ReadMBps: 245.7, DurationSec: 4.3}, nil
}

func (m *mockProvider) ShareStats(_ context.Context) ([]ShareStats, error) {
	return []ShareStats{
		{Name: "media", Path: "/mnt/datapool/media", TotalBytes: 8 * 1024 * 1024 * 1024, UsedBytes: 3 * 1024 * 1024 * 1024, FreeBytes: 5 * 1024 * 1024 * 1024},
		{Name: "docs", Path: "/mnt/datapool/docs", TotalBytes: 8 * 1024 * 1024 * 1024, UsedBytes: 512 * 1024 * 1024, FreeBytes: 7717 * 1024 * 1024},
	}, nil
}

func (m *mockProvider) ARPTable(_ context.Context) ([]ARPEntry, error) {
	return []ARPEntry{
		{IP: "10.10.1.1", MAC: "aa:bb:cc:dd:ee:ff", Iface: "eth0", State: "reachable"},
		{IP: "10.10.1.100", MAC: "11:22:33:44:55:66", Iface: "eth0", State: "reachable"},
	}, nil
}

func (m *mockProvider) FirewallRules(_ context.Context) (string, error) {
	return "table inet filter {\n  chain input { type filter hook input priority 0; policy accept; }\n  chain forward { type filter hook forward priority 0; policy accept; }\n}", nil
}

func (m *mockProvider) GetDNSConfig(_ context.Context) (DNSConfig, error) {
	return DNSConfig{Nameservers: []string{"8.8.8.8", "1.1.1.1"}, Search: []string{"local"}, Domain: ""}, nil
}
func (m *mockProvider) SetDNSConfig(_ context.Context, _ DNSConfig) error { return nil }
func (m *mockProvider) GetHosts(_ context.Context) ([]HostEntry, error) {
	return []HostEntry{
		{IP: "127.0.0.1", Hostname: "localhost"},
		{IP: "10.10.1.211", Hostname: "KilasOS", Aliases: []string{"nas"}},
	}, nil
}
func (m *mockProvider) AddHost(_ context.Context, _ HostEntry) error    { return nil }
func (m *mockProvider) DeleteHost(_ context.Context, _, _ string) error { return nil }
func (m *mockProvider) ListServices(_ context.Context) ([]SystemService, error) {
	return []SystemService{
		{Name: "nasd", Description: "KilasOS NAS daemon", State: "active", SubState: "running", Enabled: true},
		{Name: "smbd", Description: "Samba SMB daemon", State: "active", SubState: "running", Enabled: true},
		{Name: "docker", Description: "Docker", State: "active", SubState: "running", Enabled: true},
		{Name: "nfs-server", Description: "NFS kernel server", State: "inactive", SubState: "dead", Enabled: false},
	}, nil
}
func (m *mockProvider) ServiceAction(_ context.Context, _, _ string) error { return nil }
func (m *mockProvider) MemDetail(_ context.Context) (MemDetail, error) {
	return MemDetail{
		Total: 8 * 1024 * 1024 * 1024, Used: 2 * 1024 * 1024 * 1024,
		Free: 4 * 1024 * 1024 * 1024, Buffers: 256 * 1024 * 1024,
		Cached: 2 * 1024 * 1024 * 1024, SwapTotal: 2 * 1024 * 1024 * 1024,
		SwapUsed: 0, SwapFree: 2 * 1024 * 1024 * 1024,
	}, nil
}

func (m *mockProvider) GetSambaGlobal(_ context.Context) (SambaGlobal, error) {
	return SambaGlobal{Workgroup: "WORKGROUP", ServerString: "KilasOS NAS", MaxConnections: 0, LogLevel: 1}, nil
}
func (m *mockProvider) SetSambaGlobal(_ context.Context, _ SambaGlobal) error { return nil }
func (m *mockProvider) NetIfaceStats(_ context.Context) ([]NetIfaceStats, error) {
	return []NetIfaceStats{
		{Name: "eth0", RxBytes: 2 * 1024 * 1024 * 1024, TxBytes: 512 * 1024 * 1024},
		{Name: "lo", RxBytes: 10 * 1024 * 1024, TxBytes: 10 * 1024 * 1024},
	}, nil
}
func (m *mockProvider) TLSCert(_ context.Context, host string, _ int) (TLSCertInfo, error) {
	return TLSCertInfo{
		Subject: "CN=" + host, Issuer: "CN=Let's Encrypt Authority X3",
		NotBefore: "Jan  1 00:00:00 2025 UTC", NotAfter: "Jan  1 00:00:00 2026 UTC",
		Valid: true, DaysLeft: 240, SANs: []string{host},
	}, nil
}
func (m *mockProvider) LastLogins(_ context.Context, _ int) ([]LastLogin, error) {
	return []LastLogin{
		{User: "kilas", From: "10.10.1.100", When: "Mon May  5 18:00:00 2026"},
		{User: "root", From: "pts/0", When: "Mon May  5 12:00:00 2026"},
	}, nil
}
func (m *mockProvider) ScrubSchedules(_ context.Context) ([]ScrubSchedule, error) {
	return []ScrubSchedule{
		{Pool: "datapool", Schedule: "0 2 * * 0", Enabled: true},
	}, nil
}
func (m *mockProvider) SetScrubSchedule(_ context.Context, _, _ string, _ bool) error { return nil }

func (m *mockProvider) Exec(_ context.Context, command string) (ExecResult, error) {
	return ExecResult{Stdout: "mock: " + command + "\n", Stderr: "", ExitCode: 0}, nil
}

func (m *mockProvider) SearchFiles(_ context.Context, _, pattern string, _ int) ([]FileSearchResult, error) {
	return []FileSearchResult{
		{Path: "/mnt/datapool/movies", Name: pattern, SizeBytes: 4 * 1024 * 1024 * 1024, Modified: 1700000000, IsDir: false},
		{Path: "/mnt/datapool/docs", Name: pattern, SizeBytes: 1024 * 1024, Modified: 1700100000, IsDir: false},
	}, nil
}
func (m *mockProvider) SnapshotDiff(_ context.Context, _, _, _ string) ([]SnapshotDiff, error) {
	return []SnapshotDiff{
		{Change: "M", Path: "/mnt/datapool/movies/film.mkv"},
		{Change: "+", Path: "/mnt/datapool/new-file.txt"},
	}, nil
}
func (m *mockProvider) ContainerExec(_ context.Context, id, cmd string) (ExecResult, error) {
	return ExecResult{Stdout: "container:" + id + " $ " + cmd + "\nmock output\n", ExitCode: 0}, nil
}
func (m *mockProvider) GetSMTPConfig(_ context.Context) (SMTPConfig, error) {
	return SMTPConfig{Host: "", Port: 587, TLS: true}, nil
}
func (m *mockProvider) SetSMTPConfig(_ context.Context, _ SMTPConfig) error { return nil }
func (m *mockProvider) SendTestEmail(_ context.Context) error               { return nil }
func (m *mockProvider) UPSStatus(_ context.Context) (UPSInfo, error) {
	return UPSInfo{Available: false}, nil
}
func (m *mockProvider) TailscaleStatus(_ context.Context) (TailscaleStatus, error) {
	return TailscaleStatus{Running: false}, nil
}
func (m *mockProvider) ComposeProjects(_ context.Context) ([]ComposeProject, error) {
	return []ComposeProject{}, nil
}
func (m *mockProvider) ComposeAction(_ context.Context, _, _ string) error { return nil }
func (m *mockProvider) UpdateContainerLimits(_ context.Context, _ string, _ int64, _ float64) error {
	return nil
}
func (m *mockProvider) SetSharePerms(_ context.Context, _, _, _ string, _ uint32) error { return nil }
func (m *mockProvider) NFSExports(_ context.Context) ([]NFSExport, error) {
	return []NFSExport{
		{Path: "/mnt/datapool/media", Clients: []string{"*(ro,sync,no_subtree_check)"}},
	}, nil
}
func (m *mockProvider) AddNFSExport(_ context.Context, _, _ string) error { return nil }
func (m *mockProvider) DeleteNFSExport(_ context.Context, _ string) error { return nil }
func (m *mockProvider) GetAlertRules(_ context.Context) ([]AlertRule, error) {
	return []AlertRule{
		{Name: "cpu", Threshold: 90, Enabled: true},
		{Name: "mem", Threshold: 90, Enabled: true},
		{Name: "disk", Threshold: 85, Enabled: true},
	}, nil
}
func (m *mockProvider) SetAlertRules(_ context.Context, _ []AlertRule) error { return nil }
func (m *mockProvider) SmartTestHistory(_ context.Context, _ string) ([]SmartTestResult, error) {
	return []SmartTestResult{
		{Num: 1, Type: "Short offline", Status: "Completed without error", Hours: 1234, Remaining: 0},
		{Num: 2, Type: "Extended offline", Status: "Completed without error", Hours: 1100, Remaining: 0},
	}, nil
}
func (m *mockProvider) UserQuotas(_ context.Context, _ string) ([]UserQuota, error) {
	return []UserQuota{
		{User: "kilas", QuotaBytes: 10 * 1024 * 1024 * 1024, UsedBytes: 2 * 1024 * 1024 * 1024},
	}, nil
}
func (m *mockProvider) SetUserQuota(_ context.Context, _, _ string, _ int64) error { return nil }
func (m *mockProvider) ChangeEncryptionKey(_ context.Context, _, _ string) error { return nil }
func (m *mockProvider) JournalExport(_ context.Context) (string, error) {
	return "mock journal export\n-- example log lines --\n", nil
}
func (m *mockProvider) DockerDaemonConfig(_ context.Context) (map[string]interface{}, error) {
	return map[string]interface{}{"log-driver": "json-file"}, nil
}
func (m *mockProvider) SetDockerDaemonConfig(_ context.Context, _ map[string]interface{}) error {
	return nil
}
func (m *mockProvider) KillProcess(_ context.Context, _ int, _ int) error { return nil }
func (m *mockProvider) SystemEntropy(_ context.Context) (int, error)      { return 3200, nil }
func (m *mockProvider) SetDiskAPM(_ context.Context, _ string, _ int) error { return nil }
func (m *mockProvider) GetDiskAPM(_ context.Context, _ string) (int, error) { return 128, nil }
func (m *mockProvider) ResolveHostname(_ context.Context, ip string) (string, error) {
	return "host-" + strings.ReplaceAll(ip, ".", "-") + ".local", nil
}
func (m *mockProvider) DiskSpinState(_ context.Context, _ string) (string, error) {
	return "active/idle", nil
}
func (m *mockProvider) PingHost(_ context.Context, host string, count int) (PingResult, error) {
	return PingResult{Host: host, Sent: count, Received: count, PacketLoss: 0, AvgMS: 1.2, MinMS: 0.8, MaxMS: 1.8}, nil
}
func (m *mockProvider) FanSpeeds(_ context.Context) ([]FanInfo, error) {
	return []FanInfo{
		{Name: "fan1", RPM: 1200, MinRPM: 0, MaxRPM: 4000, Alarm: false},
		{Name: "fan2", RPM: 950, MinRPM: 0, MaxRPM: 4000, Alarm: false},
	}, nil
}
func (m *mockProvider) RouteTable(_ context.Context) ([]RouteEntry, error) {
	return []RouteEntry{
		{Dest: "0.0.0.0", Gateway: "192.168.1.1", Iface: "eth0", Metric: 100, Flags: "UG"},
		{Dest: "192.168.1.0", Gateway: "0.0.0.0", Iface: "eth0", Metric: 0, Flags: "U"},
	}, nil
}
func (m *mockProvider) TimeStatus(_ context.Context) (TimeInfo, error) {
	return TimeInfo{
		LocalTime: "2026-05-06 12:00:00 UTC",
		Timezone:  "UTC",
		NTPEnabled: true,
		NTPSync:   true,
		NTPServer: "pool.ntp.org",
	}, nil
}
func (m *mockProvider) WireguardStatus(_ context.Context) ([]WireguardIface, error) {
	return []WireguardIface{
		{Name: "wg0", PublicKey: "mock+pub+key==", ListenPort: 51820,
			Peers: []WireguardPeer{{PublicKey: "peer+pub+key==", AllowedIPs: "10.0.0.2/32", RxBytes: 1024, TxBytes: 512}}},
	}, nil
}
func (m *mockProvider) MDRaidStatus(_ context.Context) (string, error) {
	return "Personalities : [raid1]\nmd0 : active raid1 sda1[0] sdb1[1]\n      2048000 blocks [2/2] [UU]\n", nil
}
func (m *mockProvider) SMBSessions(_ context.Context) ([]SMBSession, error) {
	return []SMBSession{{PID: 1234, Machine: "192.168.1.50", Username: "kilas", Share: "media"}}, nil
}
func (m *mockProvider) CPUTemperatures(_ context.Context) ([]TempInfo, error) {
	return []TempInfo{
		{Name: "Core 0", Chip: "coretemp-isa-0000", TempC: 42.0, High: 80.0, Crit: 100.0},
		{Name: "Core 1", Chip: "coretemp-isa-0000", TempC: 44.0, High: 80.0, Crit: 100.0},
	}, nil
}
func (m *mockProvider) GetHostname(_ context.Context) (string, error)        { return "kilasos", nil }
func (m *mockProvider) SetHostname(_ context.Context, _ string) error        { return nil }
func (m *mockProvider) IPTablesRules(_ context.Context) (string, error) {
	return "# Generated by iptables-save\n*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\nCOMMIT\n", nil
}
func (m *mockProvider) TriggerSMARTTest(_ context.Context, _, _ string) error { return nil }
func (m *mockProvider) DockerPrune(_ context.Context, _ bool) (string, error) {
	return "Total reclaimed space: 0B\n", nil
}
func (m *mockProvider) USBDevices(_ context.Context) ([]USBDevice, error) {
	return []USBDevice{
		{Bus: "001", Device: "002", ID: "8087:0024", Name: "Intel Corp. Hub"},
		{Bus: "002", Device: "001", ID: "1d6b:0003", Name: "Linux Foundation 3.0 root hub"},
	}, nil
}
func (m *mockProvider) PCIDevices(_ context.Context) ([]PCIDevice, error) {
	return []PCIDevice{
		{Slot: "00:00.0", Class: "Host bridge", Vendor: "Intel Corporation"},
		{Slot: "00:1f.2", Class: "SATA controller", Vendor: "Intel Corporation"},
	}, nil
}
func (m *mockProvider) LoadAverages(_ context.Context) (LoadAvg, error) {
	return LoadAvg{One: 0.5, Five: 0.7, Fifteen: 0.9, Running: 2, Total: 145}, nil
}
func (m *mockProvider) SwapInfo(_ context.Context) ([]SwapEntry, error) {
	return []SwapEntry{{Filename: "/swapfile", Type: "file", SizeKB: 2048000, UsedKB: 0, Priority: -2}}, nil
}
func (m *mockProvider) ConnectionSummary(_ context.Context) (string, error) {
	return "Total: 234\nTCP: 45 (estab 30, closed 10)\nUDP: 12\n", nil
}
func (m *mockProvider) ContainerEnv(_ context.Context, _ string) ([]string, error) {
	return []string{"PATH=/usr/local/sbin:/usr/local/bin", "HOME=/root"}, nil
}
func (m *mockProvider) DiskPartitions(_ context.Context) ([]LsblkEntry, error) {
	return []LsblkEntry{
		{Name: "sda", Size: "100G", Type: "disk", Children: []LsblkEntry{
			{Name: "sda1", Size: "100G", Type: "part", Fstype: "ext4", Mountpoint: "/"},
		}},
	}, nil
}
func (m *mockProvider) GetSysctl(_ context.Context, _ string) (string, error) { return "60", nil }
func (m *mockProvider) SetSysctl(_ context.Context, _, _ string) error        { return nil }
func (m *mockProvider) ZFSPoolTrim(_ context.Context, _ string) error         { return nil }
func (m *mockProvider) WhoLoggedIn(_ context.Context) (string, error) {
	return "kilas    pts/0    192.168.1.50     12:00    0.00s  0.05s  0.00s w\n", nil
}
func (m *mockProvider) GetACL(_ context.Context, _ string) (string, error) {
	return "# file: /mnt/datapool/share\n# owner: root\n# group: root\nuser::rwx\ngroup::rwx\nother::r-x\n", nil
}
func (m *mockProvider) SetACL(_ context.Context, _, _ string) error                      { return nil }
func (m *mockProvider) SetContainerRestartPolicy(_ context.Context, _, _ string) error { return nil }
func (m *mockProvider) Fail2BanStatus(_ context.Context) (Fail2BanInfo, error) {
	return Fail2BanInfo{Active: true, Jails: []string{"sshd"}, BannedIPs: []string{"203.0.113.5"}, TotalBans: 1}, nil
}
func (m *mockProvider) GetServerCertificate(_ context.Context) (ServerCertInfo, error) {
	return ServerCertInfo{
		Subject: "CN=kilasos",
		Issuer:  "CN=kilasos",
		NotBefore: "Jan 1 00:00:00 2026 GMT",
		NotAfter: "Jan 1 00:00:00 2027 GMT",
		SelfSigned: true,
	}, nil
}
func (m *mockProvider) UploadServerCertificate(ctx context.Context, certPEM, keyPEM []byte) error { return nil }
func (m *mockProvider) GenerateServerCertificate(ctx context.Context, commonName string) (string, error) {
	return "mock cert generated", nil
}
func (m *mockProvider) DestroyDatasetRecursive(_ context.Context, _, _ string, _ bool) error {
	return nil
}
func (m *mockProvider) GetMOTD(_ context.Context) (string, error)         { return "Welcome to KilasOS\n", nil }
func (m *mockProvider) SetMOTD(_ context.Context, _ string) error         { return nil }
func (m *mockProvider) GetCronTab(_ context.Context, _ string) (string, error) {
	return "# m h dom mon dow command\n", nil
}
func (m *mockProvider) SetCronTab(_ context.Context, _, _ string) error { return nil }
func (m *mockProvider) NetstatActive(_ context.Context) ([]NetstatEntry, error) {
	return []NetstatEntry{
		{Proto: "tcp", LocalAddr: "192.168.1.10:22", RemoteAddr: "192.168.1.50:54321", State: "ESTABLISHED", PID: 1234, Process: "sshd"},
	}, nil
}
func (m *mockProvider) TestPort(_ context.Context, _ string, _ int) (bool, error)         { return true, nil }
func (m *mockProvider) ZFSHolds(_ context.Context, _ string) ([]string, error)            { return []string{"keep"}, nil }
func (m *mockProvider) ZFSAddHold(_ context.Context, _, _ string) error                   { return nil }
func (m *mockProvider) ZFSReleaseHold(_ context.Context, _, _ string) error               { return nil }
func (m *mockProvider) FailedSystemdUnits(_ context.Context) ([]SystemdUnitInfo, error)   { return nil, nil }
func (m *mockProvider) NFSActiveMounts(_ context.Context) ([]NFSMount, error)             { return nil, nil }
func (m *mockProvider) ZFSRenameDataset(_ context.Context, _, _ string) error             { return nil }
func (m *mockProvider) LogRotateStatus(_ context.Context) (string, error) {
	return "logrotate state -- version 2\n", nil
}
func (m *mockProvider) GetContainerHealth(_ context.Context, _ string) (ContainerHealthInfo, error) {
	return ContainerHealthInfo{Status: "healthy", FailingStreak: 0}, nil
}
func (m *mockProvider) MDNSServices(_ context.Context) ([]MDNSService, error) {
	return []MDNSService{
		{Name: "kilasos", Type: "_smb._tcp", Domain: "local", Hostname: "kilasos.local", Address: "192.168.1.10", Port: 445},
	}, nil
}
func (m *mockProvider) GetKernelParam(_ context.Context, _ string) (string, error)        { return "", nil }
func (m *mockProvider) PauseContainer(_ context.Context, _ string) error                  { return nil }
func (m *mockProvider) UnpauseContainer(_ context.Context, _ string) error                { return nil }
func (m *mockProvider) RestartContainer(_ context.Context, _ string) error                { return nil }
func (m *mockProvider) ZFSBookmarks(_ context.Context, _ string) ([]ZFSBookmark, error)   { return nil, nil }
func (m *mockProvider) CreateZFSBookmark(_ context.Context, _, _ string) error            { return nil }
func (m *mockProvider) GetCurrentRunlevel(_ context.Context) (string, error)              { return "graphical.target", nil }
func (m *mockProvider) GetUptime(_ context.Context) (UptimeInfo, error) {
	return UptimeInfo{UptimeSec: 3600, IdleSec: 1200, BootTime: "2026-05-06 11:00:00"}, nil
}
func (m *mockProvider) NetMaskInfo(_ context.Context) ([]NetIfaceMask, error) {
	return []NetIfaceMask{{Name: "eth0", Addr: "192.168.1.10", Netmask: "255.255.255.0", CIDR: 24}}, nil
}
func (m *mockProvider) BatteryStatus(_ context.Context) (BatteryInfo, error) {
	return BatteryInfo{Present: false}, nil
}
func (m *mockProvider) GetSystemLocale(_ context.Context) (LocaleInfo, error) {
	return LocaleInfo{Lang: "en_US.UTF-8", Timezone: "UTC", Charmap: "UTF-8"}, nil
}
func (m *mockProvider) SetTimezone(_ context.Context, _ string) error                  { return nil }
func (m *mockProvider) ListTimezones(_ context.Context) ([]string, error) {
	return []string{"UTC", "America/New_York", "Europe/London", "Asia/Tokyo"}, nil
}
func (m *mockProvider) OSRelease(_ context.Context) (OSReleaseInfo, error) {
	return OSReleaseInfo{Name: "Debian", Version: "12", ID: "debian", PrettyName: "Debian GNU/Linux 12 (bookworm)", Codename: "bookworm", Kernel: "6.1.0", Arch: "x86_64"}, nil
}
func (m *mockProvider) KernelModules(_ context.Context) ([]KernelModule, error) {
	return []KernelModule{{Name: "zfs", SizeKB: 4096, UseCount: 5, UsedBy: "zunicode,zcommon"}}, nil
}
func (m *mockProvider) IPRules(_ context.Context) (string, error) {
	return "0:	from all lookup local\n32766:	from all lookup main\n32767:	from all lookup default\n", nil
}
func (m *mockProvider) NICStats(_ context.Context, name string) (NICStatistics, error) {
	return NICStatistics{Name: name, Stats: map[string]int64{"rx_bytes": 1024000, "tx_bytes": 512000, "rx_packets": 1000, "tx_packets": 500}}, nil
}
func (m *mockProvider) SetMTU(_ context.Context, _ string, _ int) error { return nil }
func (m *mockProvider) SystemdUnitDetail(_ context.Context, name string) (SystemdUnitDetail, error) {
	return SystemdUnitDetail{Name: name, Description: "Mock service", LoadState: "loaded", ActiveState: "active", SubState: "running", UnitFile: "enabled", MainPID: 1234, MemoryMB: 64, CPUSec: 5}, nil
}
func (m *mockProvider) StartSystemdUnit(_ context.Context, _ string) error   { return nil }
func (m *mockProvider) StopSystemdUnit(_ context.Context, _ string) error    { return nil }
func (m *mockProvider) EnableSystemdUnit(_ context.Context, _ string) error  { return nil }
func (m *mockProvider) DisableSystemdUnit(_ context.Context, _ string) error { return nil }
func (m *mockProvider) GetSysHostInfo(_ context.Context) (HostHardwareInfo, error) {
	return HostHardwareInfo{Vendor: "QEMU", Product: "Standard PC", BoardVendor: "QEMU", BIOSVersion: "1.0"}, nil
}
func (m *mockProvider) JournalUnits(_ context.Context) ([]string, error) {
	return []string{"nasd.service", "ssh.service", "smbd.service"}, nil
}
func (m *mockProvider) GetJournalForUnit(_ context.Context, unit string, _ int) (string, error) {
	return "May 06 12:00:00 host " + unit + ": Mock log entry\n", nil
}
func (m *mockProvider) ZFSFeatures(_ context.Context, _ string) ([]ZFSFeature, error) {
	return []ZFSFeature{{Name: "lz4_compress", State: "active"}, {Name: "encryption", State: "enabled"}}, nil
}
func (m *mockProvider) IP6Tables(_ context.Context) (string, error) {
	return "*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n", nil
}
func (m *mockProvider) ConntrackCount(_ context.Context) (int, error)             { return 234, nil }
func (m *mockProvider) Dmesg(_ context.Context, _ int) (string, error)            { return "[mock] system started\n", nil }
func (m *mockProvider) KernelCmdline(_ context.Context) (string, error) {
	return "BOOT_IMAGE=/vmlinuz root=/dev/sda1 ro quiet", nil
}
func (m *mockProvider) NICOffloads(_ context.Context, _ string) (map[string]string, error) {
	return map[string]string{"tcp-segmentation-offload": "on", "rx-checksumming": "on"}, nil
}
func (m *mockProvider) GetCPUInfoDetailed(_ context.Context) (CPUDetail, error) {
	return CPUDetail{Model: "Mock CPU @ 3.0GHz", Cores: 4, Threads: 8, MHz: 3000, CacheKB: 8192, Vendor: "GenuineIntel", Family: "6"}, nil
}
func (m *mockProvider) ListMounts(_ context.Context) ([]MountInfo, error) {
	return []MountInfo{{Device: "/dev/sda1", Mountpoint: "/", FSType: "ext4", Options: "rw,relatime"}}, nil
}
func (m *mockProvider) GetReadOnlyMounts(_ context.Context) ([]string, error) { return nil, nil }
func (m *mockProvider) NetlinkConntrack(_ context.Context, _ int) ([]ConntrackEntry, error) {
	return []ConntrackEntry{{Proto: "tcp", SrcIP: "192.168.1.10", DstIP: "8.8.8.8", SrcPort: 54321, DstPort: 443, State: "ESTABLISHED"}}, nil
}
func (m *mockProvider) IOWait(_ context.Context) (float64, error)              { return 1.5, nil }
func (m *mockProvider) ZFSPoolImportable(_ context.Context) ([]string, error)  { return nil, nil }
func (m *mockProvider) ListInstalledKernels(_ context.Context) ([]string, error) {
	return []string{"6.1.0-amd64", "5.15.0-amd64"}, nil
}
func (m *mockProvider) GetCurrentKernel(_ context.Context) (string, error) { return "6.1.0-amd64", nil }
func (m *mockProvider) NetworkSpeedTest(_ context.Context, server string) (NetSpeedResult, error) {
	return NetSpeedResult{Server: server, DownloadMB: 100, UploadMB: 50, PingMS: 10}, nil
}
func (m *mockProvider) GetDiskTemperatures(_ context.Context) ([]DiskTemp, error) {
	return []DiskTemp{{Device: "sda", TempC: 35, State: "active"}}, nil
}
func (m *mockProvider) SystemBuildInfo(_ context.Context) (SystemBuildInfo, error) {
	return SystemBuildInfo{Hostname: "kilasos", OSVersion: "Linux 6.1 #1 SMP", Arch: "x86_64", NumCPU: 4}, nil
}
func (m *mockProvider) GetVMSizes(_ context.Context) ([]VMInfo, error)         { return nil, nil }
func (m *mockProvider) GetSudoers(_ context.Context) (string, error)            { return "%sudo ALL=(ALL:ALL) ALL\n", nil }
func (m *mockProvider) GetSSHDConfig(_ context.Context) (string, error) {
	return "Port 22\nProtocol 2\nPermitRootLogin no\n", nil
}
func (m *mockProvider) SystemRecommendations(_ context.Context) ([]SystemRecommendation, error) {
	return []SystemRecommendation{
		{Category: "security", Severity: "info", Message: "All checks passed"},
	}, nil
}
func (m *mockProvider) GetMaxOpenFiles(_ context.Context) (int, error)              { return 1024 * 1024, nil }
func (m *mockProvider) GetTCPCongestionAlgo(_ context.Context) (string, error)      { return "cubic", nil }
func (m *mockProvider) GetDiskSerial(_ context.Context, _ string) (string, error)   { return "MOCK-SERIAL-1234", nil }
func (m *mockProvider) NetworkInterfaceFeatures(_ context.Context) ([]InterfaceFeature, error) {
	return []InterfaceFeature{
		{Name: "eth0", Driver: "virtio_net", Speed: "1000 Mb/s", Duplex: "full", LinkUp: true},
	}, nil
}
func (m *mockProvider) GetZFSDatasetProperty(_ context.Context, _, _ string) (string, error)   { return "off", nil }
func (m *mockProvider) SetZFSDatasetProperty(_ context.Context, _, _, _ string) error          { return nil }
func (m *mockProvider) OpenPortsAudit(_ context.Context) ([]OpenPort, error) {
	return []OpenPort{{Proto: "tcp", Port: 22, Addr: "0.0.0.0", Process: "sshd"}}, nil
}
func (m *mockProvider) OOMKillerLog(_ context.Context, _ int) ([]OOMEvent, error) { return nil, nil }
func (m *mockProvider) ZRAMInfo(_ context.Context) ([]ZRAMDevice, error)          { return nil, nil }
func (m *mockProvider) GetNTPServers(_ context.Context) ([]string, error) {
	return []string{"pool.ntp.org"}, nil
}
func (m *mockProvider) SetNTPServers(_ context.Context, _ []string) error { return nil }
func (m *mockProvider) GetTimeSyncStatus(_ context.Context) (TimeSyncStatus, error) {
	return TimeSyncStatus{Synchronized: true, Server: "pool.ntp.org", LastSync: "2026-05-06 12:00:00 UTC"}, nil
}
func (m *mockProvider) GetIPv6Status(_ context.Context) (IPv6Status, error) {
	return IPv6Status{Enabled: true, Addresses: []string{"eth0: fe80::1"}}, nil
}
func (m *mockProvider) ZFSScrubProgress(_ context.Context, pool string) (ScrubProgress, error) {
	return ScrubProgress{Pool: pool, State: "idle", Progress: 0, ErrorsFound: 0}, nil
}
func (m *mockProvider) ListLogins(_ context.Context, _ int) ([]LoginEvent, error) {
	return []LoginEvent{{User: "kilas", TTY: "pts/0", From: "192.168.1.50", Login: "Tue May 6 12:00"}}, nil
}
func (m *mockProvider) GetCurrentTimezoneOffset(_ context.Context) (string, error) { return "+00:00", nil }
func (m *mockProvider) GetSystemBoots(_ context.Context) ([]BootRecord, error) {
	return []BootRecord{{Index: 0, BootID: "abc123", First: "2026-05-06 11:00 UTC", Last: "2026-05-06 13:00 UTC"}}, nil
}
func (m *mockProvider) GetSMARTAttributes(_ context.Context, _ string) ([]SMARTAttribute, error) {
	return []SMARTAttribute{
		{ID: 5, Name: "Reallocated_Sector_Ct", Value: 100, Worst: 100, Threshold: 50, Raw: 0},
		{ID: 194, Name: "Temperature_Celsius", Value: 65, Worst: 60, Threshold: 0, Raw: 35},
	}, nil
}
func (m *mockProvider) GetZFSDedupStats(_ context.Context, pool string) (DedupStats, error) {
	return DedupStats{Pool: pool, Ratio: 1.0, Enabled: false}, nil
}
func (m *mockProvider) GetNVMeStats(_ context.Context, devPath string) (NVMeInfo, error) {
	return NVMeInfo{Device: devPath, Temperature: 40, AvailableSpare: 100, PercentageUsed: 5, PowerOnHours: 1000, MediaErrors: 0}, nil
}
func (m *mockProvider) GetGPUInfo(_ context.Context) ([]GPUInfo, error)    { return nil, nil }
func (m *mockProvider) FlushARPCache(_ context.Context) error              { return nil }
func (m *mockProvider) GetECCErrors(_ context.Context) ([]ECCEvent, error) { return nil, nil }
func (m *mockProvider) GetMemFragmentation(_ context.Context) (MemFragInfo, error) {
	return MemFragInfo{OrderFragmentation: map[string]float64{"order_0": 0.5, "order_1": 0.3}}, nil
}
func (m *mockProvider) GetTopBandwidthIPs(_ context.Context, _ int) ([]BandwidthIP, error) {
	return []BandwidthIP{{IP: "192.168.1.50", Connections: 12}}, nil
}
func (m *mockProvider) GetSwapPressure(_ context.Context) (PressureInfo, error) {
	return PressureInfo{Some10s: 0.5, Some60s: 0.3}, nil
}

// M382: SMB AD-joined mode mocks
func (m *mockProvider) SMBADJoin(_ context.Context, _, _, _, _ string) error  { return nil }
func (m *mockProvider) SMBADLeave(_ context.Context, _, _ string) error       { return nil }
func (m *mockProvider) SMBADStatus(_ context.Context) (SMBADStatus, error) {
	return SMBADStatus{Joined: false}, nil
}

// ── Backup & Cloud Sync (M301-M315) ──────────────────────────────────────────

func (m *mockProvider) BorgInit(_ context.Context, name, _, _ string) (BorgRepo, error) {
	return BorgRepo{Name: name, Path: "/var/lib/kilasos/backups/borg-" + name, Encryption: "repokey", LastModified: time.Now().Unix()}, nil
}
func (m *mockProvider) BorgCreateBackup(_ context.Context, _, archiveName, _ string, _ []string) (BorgArchive, error) {
	return BorgArchive{Name: archiveName, ID: "mock-archive-id", Time: time.Now().Format(time.RFC3339), Duration: 120, Size: 4 * 1024 * 1024 * 1024, CompressedSize: 2 * 1024 * 1024 * 1024, FileCount: 1000}, nil
}
func (m *mockProvider) BorgListArchives(_ context.Context, repoName string) ([]BorgArchive, error) {
	return []BorgArchive{
		{Name: "backup-20260501-120000", ID: "archive-id-1", Time: "2026-05-01T12:00:00Z", Duration: 120, Size: 4 * 1024 * 1024 * 1024, CompressedSize: 2 * 1024 * 1024 * 1024, FileCount: 1000},
		{Name: "backup-20260502-120000", ID: "archive-id-2", Time: "2026-05-02T12:00:00Z", Duration: 115, Size: 4508879634, CompressedSize: 2254439817, FileCount: 1050},
	}, nil
}
func (m *mockProvider) BorgDeleteArchive(_ context.Context, _, _ string) error { return nil }
func (m *mockProvider) BorgPrune(_ context.Context, _, _ string) (string, error) { return "Mock prune output", nil }
func (m *mockProvider) BorgRestore(_ context.Context, _, _, _ string) error { return nil }
func (m *mockProvider) BorgVerify(_ context.Context, _, archiveName string) (BackupVerification, error) {
	return BackupVerification{OK: true, ArchiveID: archiveName, FilesChecked: 1000, Errors: 0, Message: "Verification complete"}, nil
}
func (m *mockProvider) ResticInit(_ context.Context, name, _, _ string, _ map[string]string) (ResticRepo, error) {
	return ResticRepo{Name: name, Path: "/var/lib/kilasos/backups/restic-" + name, LastModified: time.Now().Unix()}, nil
}
func (m *mockProvider) ResticCreateBackup(_ context.Context, repoName, paths string, _ []string) (ResticSnapshot, error) {
	return ResticSnapshot{ID: "mock-snapshot-id", Time: time.Now().Format(time.RFC3339), Paths: strings.Fields(paths), Size: 3 * 1024 * 1024 * 1024, FileCount: 800, Tags: []string{}}, nil
}
func (m *mockProvider) ResticListSnapshots(_ context.Context, repoName string) ([]ResticSnapshot, error) {
	return []ResticSnapshot{
		{ID: "snap-001", Time: "2026-05-01T12:00:00Z", Hostname: "kilasos", Paths: []string{"/mnt/datapool"}, Size: 3 * 1024 * 1024 * 1024, FileCount: 800},
		{ID: "snap-002", Time: "2026-05-02T12:00:00Z", Hostname: "kilasos", Paths: []string{"/mnt/datapool"}, Size: 3326107953, FileCount: 820},
	}, nil
}
func (m *mockProvider) ResticDeleteSnapshot(_ context.Context, _, _ string) error { return nil }
func (m *mockProvider) ResticRestore(_ context.Context, _, _, _ string) error { return nil }
func (m *mockProvider) ResticVerify(_ context.Context, _, snapshotID string) (BackupVerification, error) {
	return BackupVerification{OK: true, ArchiveID: snapshotID, FilesChecked: 800, Errors: 0, Message: "Verification complete"}, nil
}
func (m *mockProvider) ResticForget(_ context.Context, _ string, _, _, _, _, _ int) (string, error) {
	return "Mock restic forget output", nil
}
func (m *mockProvider) RcloneRemoteAdd(_ context.Context, name, remoteType, _, _, _ string, _ string) (RcloneRemote, error) {
	return RcloneRemote{Name: name, Type: remoteType, Connected: true}, nil
}
func (m *mockProvider) RcloneRemoteRemove(_ context.Context, name string) error { return nil }
func (m *mockProvider) RcloneRemoteList(_ context.Context) ([]RcloneRemote, error) {
	return []RcloneRemote{
		{Name: "my-b2", Type: "b2", Endpoint: "s3://my-bucket", Connected: true, SourcePath: "/mnt", DestPath: "/kilasos-backup"},
		{Name: "my-gdrive", Type: "drive", Endpoint: "drive:my-folder", Connected: true, SourcePath: "/mnt", DestPath: "/kilasos-backup"},
	}, nil
}
func (m *mockProvider) RcloneSync(_ context.Context, name string, _ bool, _, _ string, _ string) (string, error) {
	return `{"bytes": 1073741824, "objects": 42, "error": ""}`, nil
}
func (m *mockProvider) BackupJobs(_ context.Context) ([]BackupJob, error) {
	return []BackupJob{
		{ID: "bk-001", Name: "Daily Datapool", Type: "borg", Schedule: "0 2 * * *", Enabled: true, Source: "/mnt/datapool", Destination: "local-backup", LastRun: time.Now().Add(-86400).Unix(), LastResult: "ok", LastSize: 4 * 1024 * 1024 * 1024},
		{ID: "bk-002", Name: "Weekly to B2", Type: "restic", Schedule: "0 3 * * 0", Enabled: true, Source: "/mnt/datapool", Destination: "my-b2", LastRun: time.Now().Add(-604800).Unix(), LastResult: "ok", LastSize: 3 * 1024 * 1024 * 1024},
	}, nil
}
func (m *mockProvider) CreateBackupJob(_ context.Context, j BackupJob) (BackupJob, error) {
	if j.ID == "" {
		j.ID = fmt.Sprintf("bk-%d", time.Now().UnixNano())
	}
	return j, nil
}
func (m *mockProvider) DeleteBackupJob(_ context.Context, _ string) error { return nil }
func (m *mockProvider) UpdateBackupJob(_ context.Context, j BackupJob) (BackupJob, error) { return j, nil }
func (m *mockProvider) RunBackupJob(_ context.Context, id string) error { return nil }
func (m *mockProvider) BackupJobRuns(_ context.Context, jobID string) ([]BackupJobRun, error) {
	ts := time.Now().UnixNano()
	return []BackupJobRun{
		{ID: fmt.Sprintf("%d", ts-60000000000), JobID: jobID, Result: "ok", Size: 4096, LogSize: 512, Timestamp: ts - 60000000000},
		{ID: fmt.Sprintf("%d", ts-120000000000), JobID: jobID, Result: "ok", Size: 4096, LogSize: 480, Timestamp: ts - 120000000000},
		{ID: fmt.Sprintf("%d", ts-180000000000), JobID: jobID, Result: "failed", Size: 0, LogSize: 256, Timestamp: ts - 180000000000},
	}, nil
}
func (m *mockProvider) BackupJobRun(_ context.Context, jobID, runID string) (BackupJobRun, error) {
	ts, _ := strconv.ParseInt(runID, 10, 64)
	return BackupJobRun{
		ID:        runID,
		JobID:     jobID,
		Result:    "ok",
		Size:      4096,
		LogSize:   512,
		Timestamp: ts,
	}, nil
}
func (m *mockProvider) RestorePoints(_ context.Context, backupType, repo string) ([]RestorePoint, error) {
	if backupType == "borg" {
		return []RestorePoint{
			{ID: "archive-1", BackupType: "borg", Repo: repo, Archive: "backup-20260501-120000", Time: "2026-05-01T12:00:00Z", Size: 4 * 1024 * 1024 * 1024, FileCount: 1000},
		}, nil
	}
	return []RestorePoint{
		{ID: "snap-001", BackupType: "restic", Repo: repo, Archive: "snap-001", Time: "2026-05-01T12:00:00Z", Size: 3 * 1024 * 1024 * 1024, FileCount: 800},
	}, nil
}
func (m *mockProvider) CloudCostEstimate(_ context.Context, provider string, sizeGB float64) (CloudCostEstimate, error) {
	return CloudCostEstimate{Provider: provider, SizeGB: sizeGB, PricePerGB: 0.020, Monthly: sizeGB * 0.020, Yearly: sizeGB * 0.020 * 12}, nil
}
func (m *mockProvider) BackupSecretsPath() string { return "/etc/kilasos/backup-secrets.json" }
func (m *mockProvider) AppStacks(_ context.Context) ([]AppStack, error) {
	return []AppStack{{Name: "Servarr Stack", Label: "servarr", Icon: "🎞"}}, nil
}
func (m *mockProvider) CreateAppStack(_ context.Context, s AppStack) (AppStack, error) { return s, nil }
func (m *mockProvider) DeleteAppStack(_ context.Context, name string) error { return nil }
func (m *mockProvider) AppUpdateAvailable(_ context.Context, appName string) (AppUpdateInfo, error) {
	return AppUpdateInfo{Available: false, CurrentTag: "latest", LatestTag: "latest"}, nil
}
func (m *mockProvider) AppUpdate(_ context.Context, appName string, backup bool) (string, error) {
	return "mock update output", nil
}
func (m *mockProvider) AppRollback(_ context.Context, appName string, backupID string) (string, error) {
	return "mock rollback output", nil
}
func (m *mockProvider) AppHealthStatus(_ context.Context, appName string) (AppHealthInfo, error) {
	return AppHealthInfo{Status: "healthy", Containers: 2, Running: 2}, nil
}
func (m *mockProvider) AppExportConfig(_ context.Context, appName string) (AppConfigExport, error) {
	return AppConfigExport{AppName: appName, TemplateID: "mock"}, nil
}
func (m *mockProvider) AppImportConfig(_ context.Context, appName string, cfg AppConfigExport) error {
	return nil
}
func (m *mockProvider) AppCustomTemplate(_ context.Context, composeYAML string) (appcatalog.AppTemplate, error) {
	return appcatalog.NewCustomAppTemplate("custom-mock", composeYAML), nil
}
func (m *mockProvider) AppFavorites(_ context.Context) ([]string, error) { return []string{}, nil }
func (m *mockProvider) AppSetFavorite(_ context.Context, appName string, fav bool) error { return nil }
func (m *mockProvider) AppSearch(_ context.Context, q string, category string) ([]appcatalog.AppTemplate, error) {
	return []appcatalog.AppTemplate{}, nil
}

// ╔═════════════════════════════════════════════════════════════════════════════╗
// ║ ── BATCH ANCHOR ZONES (mock.go) ──                                          ║
// ║ Each batch appends ITS mock impls in its own zone below.                    ║
// ╚═════════════════════════════════════════════════════════════════════════════╝

// ── BATCH-B (M316-M330): Monitoring & Alerting mocks ──
func (m *mockProvider) PrometheusMetrics(_ context.Context) (string, error) {
	return `# HELP kilasos_cpu_usage_percent CPU usage percent
# TYPE kilos_cpu_usage_percent gauge
kilasos_cpu_usage_percent 23.5
# HELP kilasos_memory_usage_percent Memory usage percent
# TYPE kilasos_memory_usage_percent gauge
kilasos_memory_usage_percent 61.2
`, nil
}
func (m *mockProvider) HealthchecksPing(_ context.Context, url string) error { return nil }
func (m *mockProvider) Notify(_ context.Context, channel, event, severity string) error { return nil }
func (m *mockProvider) NotificationChannels(_ context.Context) ([]NotificationChannel, error) {
	return []NotificationChannel{{Name: "mock-discord", Type: "discord", URL: "https://discord.com/mock", Enabled: true}}, nil
}
func (m *mockProvider) CreateNotificationChannel(_ context.Context, ch NotificationChannel) (NotificationChannel, error) { return ch, nil }
func (m *mockProvider) UpdateNotificationChannel(_ context.Context, name string, ch NotificationChannel) (NotificationChannel, error) { return ch, nil }
func (m *mockProvider) DeleteNotificationChannel(_ context.Context, name string) error { return nil }
func (m *mockProvider) MonitorAlertRules(_ context.Context) ([]MonitorAlertRule, error) {
	return []MonitorAlertRule{{Name: "high-cpu", Metric: "cpu", Condition: "gt", Threshold: 80, Severity: "warn", Channel: "mock-discord", DedupeMins: 5}}, nil
}
func (m *mockProvider) CreateMonitorAlertRule(_ context.Context, r MonitorAlertRule) (MonitorAlertRule, error) { return r, nil }
func (m *mockProvider) UpdateMonitorAlertRule(_ context.Context, name string, r MonitorAlertRule) (MonitorAlertRule, error) { return r, nil }
func (m *mockProvider) DeleteMonitorAlertRule(_ context.Context, name string) error { return nil }
func (m *mockProvider) AlertEvents(_ context.Context, limit int) ([]AlertEvent, error) {
	return []AlertEvent{{ID: "mock-alert-1", Rule: "high-cpu", Metric: "cpu", Value: 85, Threshold: 80, Severity: "warn", Channel: "mock-discord", Message: "CPU at 85%", Time: time.Now().Add(-5 * time.Minute), Acked: false}}, nil
}
func (m *mockProvider) AcknowledgeAlert(_ context.Context, id string) error { return nil }
func (m *mockProvider) SilenceAlert(_ context.Context, ruleName string, hours int) error { return nil }
func (m *mockProvider) AnomalyScore(_ context.Context, metric string, window int) (AnomalyResult, error) {
	return AnomalyResult{Metric: metric, Score: 0.5, IsAnomaly: false, Threshold: 3.0, Message: "normal"}, nil
}
func (m *mockProvider) TestNotification(_ context.Context, channel string) error { return nil }

// ── BATCH-C (M331-M345): Reverse Proxy & Tunnels mocks ──
func (m *mockProvider) CaddySites(_ context.Context) ([]CaddySite, error) {
	return []CaddySite{
		{Name: "default", Domain: "nas.local", TargetHost: "127.0.0.1", TargetPort: 8080, Enabled: true, TLS: "auto"},
	}, nil
}
func (m *mockProvider) CreateCaddySite(_ context.Context, s CaddySite) (CaddySite, error) { return s, nil }
func (m *mockProvider) UpdateCaddySite(_ context.Context, _ string, s CaddySite) (CaddySite, error) { return s, nil }
func (m *mockProvider) DeleteCaddySite(_ context.Context, _ string) error { return nil }
func (m *mockProvider) CaddyReload(_ context.Context) error               { return nil }
func (m *mockProvider) TunnelStatus(_ context.Context) (TunnelInfo, error) {
	return TunnelInfo{Name: "cloudflared", Connected: false}, nil
}
func (m *mockProvider) TunnelStart(_ context.Context, _, _ string) error { return nil }
func (m *mockProvider) TunnelStop(_ context.Context, _ string) error      { return nil }
func (m *mockProvider) TailscaleFunnel(_ context.Context, _ int, _ bool) error { return nil }
func (m *mockProvider) WireGuardPeers(_ context.Context) ([]WireGuardPeer, error) {
	return []WireGuardPeer{
		{PublicKey: "MOCK+pub+key+============", AllowedIPs: "10.0.0.2/32", PersistentKeep: 25, TransferRx: 1024, TransferTx: 512},
	}, nil
}
func (m *mockProvider) WireGuardAddPeer(_ context.Context, pubKey string) (WireGuardPeer, error) {
	return WireGuardPeer{PublicKey: pubKey, AllowedIPs: "10.0.0.0/24"}, nil
}
func (m *mockProvider) WireGuardRemovePeer(_ context.Context, _ string) error { return nil }
func (m *mockProvider) WireGuardConfig(_ context.Context) (WireGuardConfig, error) {
	return WireGuardConfig{InterfaceAddress: "10.0.0.1/24", ListenPort: 51820}, nil
}
func (m *mockProvider) UPnPStatus(_ context.Context) (UPnPStatus, error) {
	return UPnPStatus{Enabled: false}, nil
}
func (m *mockProvider) UPnPForwardPort(_ context.Context, p int, _ string) (int, error) { return p, nil }
func (m *mockProvider) UPnPRemovePort(_ context.Context, _ int, _ string) error          { return nil }
func (m *mockProvider) DDNSUpdate(_ context.Context, _, _, _, _ string) error            { return nil }
func (m *mockProvider) DNSmasqConfig(_ context.Context) (string, error)                  { return "# mock dnsmasq config\n", nil }
func (m *mockProvider) SetDNSmasqConfig(_ context.Context, _ string) error               { return nil }
func (m *mockProvider) DHCPConfig(_ context.Context) (DHCPConfig, error) {
	return DHCPConfig{Enabled: false, RangeStart: "192.168.1.100", RangeEnd: "192.168.1.199", Subnet: "192.168.1.0/24", Router: "192.168.1.1", DNSServers: []string{"1.1.1.1"}, LeaseTime: 24}, nil
}
func (m *mockProvider) SetDHCPConfig(_ context.Context, _ DHCPConfig) error { return nil }

// ── BATCH-E (M361-M375): Storage Power-User mocks ──
func (m *mockProvider) BtrfsSubvolumes(ctx context.Context) ([]BtrfsSubvol, error) {
	return []BtrfsSubvol{{Path: "/btrfs-pool/subvol1", UUID: "mock-uuid", ParentID: 5}}, nil
}
func (m *mockProvider) CreateBtrfsSubvol(ctx context.Context, path string) (BtrfsSubvol, error) { return BtrfsSubvol{Path: path}, nil }
func (m *mockProvider) DeleteBtrfsSubvol(ctx context.Context, path string) error { return nil }
func (m *mockProvider) BtrfsSnapshots(ctx context.Context) ([]BtrfsSnapshot, error) {
	return []BtrfsSnapshot{{Path: "/snap1", Source: "/btrfs-pool/subvol1", Created: time.Now().Unix(), ReadOnly: true}}, nil
}
func (m *mockProvider) CreateBtrfsSnapshot(ctx context.Context, source, target string) (BtrfsSnapshot, error) {
	return BtrfsSnapshot{Path: target, Source: source, Created: time.Now().Unix(), ReadOnly: false}, nil
}
func (m *mockProvider) DeleteBtrfsSnapshot(ctx context.Context, path string) error { return nil }
func (m *mockProvider) RestoreBtrfsSnapshot(ctx context.Context, path, snapshot string) error { return nil }
func (m *mockProvider) BtrfsScrub(ctx context.Context, path string) error { return nil }
func (m *mockProvider) BtrfsBalance(ctx context.Context, path string) error { return nil }
func (m *mockProvider) ZFSL2ARCStatus(ctx context.Context) ([]L2ARCDevice, error) {
	return []L2ARCDevice{{Pool: "datapool", Device: "/dev/sdc", Size: 16 * 1024 * 1024 * 1024, Allocated: 4 * 1024 * 1024 * 1024, Free: 12 * 1024 * 1024 * 1024}}, nil
}
func (m *mockProvider) ZFSL2ARCAdd(ctx context.Context, pool, device string) error { return nil }
func (m *mockProvider) ZFSL2ARCRemove(ctx context.Context, pool string) error { return nil }
func (m *mockProvider) ZFSSLOGStatus(ctx context.Context) ([]SLOGDevice, error) {
	return []SLOGDevice{{Pool: "datapool", Device: "/dev/sdd", Size: 8 * 1024 * 1024 * 1024, Allocated: 2 * 1024 * 1024 * 1024, Free: 6 * 1024 * 1024 * 1024}}, nil
}
func (m *mockProvider) ZFSSLOGAdd(ctx context.Context, pool, device string) error { return nil }
func (m *mockProvider) ZFSSLOGRemove(ctx context.Context, pool string) error { return nil }
func (m *mockProvider) ZFSSpecialVdevStatus(ctx context.Context) ([]SpecialVdev, error) {
	return []SpecialVdev{{Pool: "datapool", Device: "/dev/sde", Class: "special", Size: 10 * 1024 * 1024 * 1024}}, nil
}
func (m *mockProvider) ZFSSpecialVdevAdd(ctx context.Context, pool, device string) error { return nil }
func (m *mockProvider) ZFSDDTProjection(ctx context.Context) (DDTProjection, error) {
	return DDTProjection{Pool: "datapool", DDTEnabled: true, DDTEntries: 12345, DDTSize: 1024 * 1024, EstMemMB: 1.0, Status: "ready"}, nil
}
func (m *mockProvider) DDTProjectionStatus(ctx context.Context) (DDTProjection, error) {
	return DDTProjection{Pool: "datapool", Status: "ready", DDTEnabled: true, DDTEntries: 12345, DDTSize: 1024 * 1024}, nil
}
func (m *mockProvider) ZFSCompressionRatios(ctx context.Context) ([]CompressionRatio, error) {
	return []CompressionRatio{
		{Dataset: "datapool", Compression: "lz4", UsedBytes: 500 * 1024 * 1024 * 1024, LogicalUsed: 1200 * 1024 * 1024 * 1024, Ratio: 2.4},
		{Dataset: "datapool/containers", Compression: "zstd", UsedBytes: 200 * 1024 * 1024 * 1024, LogicalUsed: 600 * 1024 * 1024 * 1024, Ratio: 3.0},
	}, nil
}
func (m *mockProvider) LifecyclePolicies(ctx context.Context) ([]LifecyclePolicy, error) {
	return []LifecyclePolicy{
		{Name: "daily-snapshots", Dataset: "datapool", Frequency: "daily", KeepRecent: 7, KeepWeekly: 4, Enabled: true},
	}, nil
}
func (m *mockProvider) SetLifecyclePolicy(ctx context.Context, pol LifecyclePolicy) error { return nil }
func (m *mockProvider) DeleteLifecyclePolicy(ctx context.Context, name string) error { return nil }
func (m *mockProvider) StorageTierPolicy(ctx context.Context) (TierPolicy, error) {
	return TierPolicy{Enabled: false, SourcePool: "fast-pool", TargetPool: "cold-pool", AgeDays: 30}, nil
}
func (m *mockProvider) SetStorageTierPolicy(ctx context.Context, pol TierPolicy) error { return nil }
func (m *mockProvider) DedupScannerStatus(ctx context.Context) (DedupScanResult, error) {
	return DedupScanResult{Status: "idle"}, nil
}
func (m *mockProvider) StartDedupScan(ctx context.Context, path string) error { return nil }
func (m *mockProvider) DiskBurnInStatus(ctx context.Context) (BurnInStatus, error) {
	return BurnInStatus{Status: "idle"}, nil
}
func (m *mockProvider) StartDiskBurnIn(ctx context.Context, disk string) error { return nil }
func (m *mockProvider) ReplacementWizardState(ctx context.Context, id string) (ReplacementWizardState, error) {
	return ReplacementWizardState{ID: id, Step: "identify", Message: "Select disk to replace"}, nil
}
func (m *mockProvider) ReplacementWizardStep(ctx context.Context, id string, action string, data map[string]string) (ReplacementWizardState, error) {
	return ReplacementWizardState{ID: id, Step: "complete", Message: "Mock replacement done"}, nil
}
func (m *mockProvider) PoolExpansionWizardState(ctx context.Context, id string) (PoolExpansionState, error) {
	return PoolExpansionState{ID: id, Step: "select_pool", Message: "Select pool to expand"}, nil
}
func (m *mockProvider) PoolExpansionStep(ctx context.Context, id string, action string, data map[string]string) (PoolExpansionState, error) {
	return PoolExpansionState{ID: id, Step: "complete", Message: "Mock expansion done"}, nil
}

// ── BATCH-G (M391-M405): Web File Manager mocks ──
func (m *mockProvider) FileTree(ctx context.Context, path string) ([]FileNode, error) {
	return []FileNode{}, nil
}
func (m *mockProvider) FileList(ctx context.Context, path string) ([]FileNode, error) {
	return []FileNode{}, nil
}
func (m *mockProvider) FileRead(ctx context.Context, path string) (string, error) {
	return "", nil
}
func (m *mockProvider) FilePreview(ctx context.Context, path string) (FilePreview, error) {
	return FilePreview{Kind: "binary", Content: ""}, nil
}

func (m *mockProvider) FileRename(ctx context.Context, oldPath, newPath string) error { return nil }
func (m *mockProvider) FileCopy(ctx context.Context, src, dst string) error { return nil }
func (m *mockProvider) FileDelete(ctx context.Context, path string) error { return nil }
func (m *mockProvider) TrashList(ctx context.Context) ([]FileNode, error) {
	return []FileNode{}, nil
}
func (m *mockProvider) TrashRestore(ctx context.Context, trashPath string) error { return nil }
func (m *mockProvider) TrashEmpty(ctx context.Context) error { return nil }
func (m *mockProvider) FileChmod(ctx context.Context, path string, mode string) error { return nil }
func (m *mockProvider) FileChown(ctx context.Context, path string, uid, gid int) error { return nil }
func (m *mockProvider) CreateShareLink(ctx context.Context, path string, opts ShareLinkOptions) (ShareLink, error) {
	return ShareLink{ID: "mock", Token: "mocktoken", Path: path}, nil
}
func (m *mockProvider) RevokeShareLink(ctx context.Context, id string) error { return nil }
func (m *mockProvider) GetShareLink(ctx context.Context, id string) (ShareLink, error) {
	return ShareLink{}, fmt.Errorf("not found")
}
func (m *mockProvider) ListShareLinks(ctx context.Context) ([]ShareLink, error) { return []ShareLink{}, nil }
func (m *mockProvider) ResolveShareToken(ctx context.Context, token string) (ShareLink, error) {
	return ShareLink{}, fmt.Errorf("share link not found")
}
func (m *mockProvider) BulkDelete(ctx context.Context, paths []string) error { return nil }
func (m *mockProvider) BulkMove(ctx context.Context, ops []BulkMoveOp) error { return nil }

// ── BATCH-H (M406-M420): Mobile & UX Polish (minimal mocks) ──

// ── BATCH-I (M421-M435): Observability & Logs mocks ──
func (m *mockProvider) SyslogForwardingConfig(ctx context.Context) (SyslogConfig, error) {
	return SyslogConfig{Enabled: false, RemoteHost: "", RemotePort: 514, Protocol: "udp"}, nil
}
func (m *mockProvider) SetSyslogForwarding(ctx context.Context, cfg SyslogConfig) error { return nil }
func (m *mockProvider) AuditRetentionPolicy(ctx context.Context) (AuditRetention, error) {
	return AuditRetention{MaxAgeDays: 90, MaxSizeMB: 5000}, nil
}
func (m *mockProvider) SetAuditRetentionPolicy(ctx context.Context, pol AuditRetention) error { return nil }
func (m *mockProvider) RotateAuditLogs(ctx context.Context) error { return nil }
func (m *mockProvider) SearchAuditLogs(ctx context.Context, q AuditLogQuery) ([]AuditLogEntry, error) {
	return []AuditLogEntry{{Time: "2026-05-07 10:00:00", User: "admin", Action: "login", IP: "192.168.1.1", Result: "success", Details: ""}}, nil
}
func (m *mockProvider) AggregateSystemLogs(ctx context.Context, sinceHours int) ([]ServiceLogSummary, error) {
	return []ServiceLogSummary{
		{Service: "nasd.service", ErrorCount: 2, WarnCount: 5, InfoCount: 100, LastSeen: "2026-05-07T10:00:00Z"},
		{Service: "smbd.service", ErrorCount: 0, WarnCount: 1, InfoCount: 50, LastSeen: "2026-05-07T09:55:00Z"},
	}, nil
}
func (m *mockProvider) SearchContainerLogs(ctx context.Context, q ContainerLogQuery) ([]ContainerLogEntry, error) {
	return []ContainerLogEntry{
		{Time: "2026-05-07T10:00:00Z", Container: "sonarr", Message: "Database updated", Level: "info"},
		{Time: "2026-05-07T09:58:00Z", Container: "sonarr", Message: "Error connecting to indexer", Level: "error"},
	}, nil
}
func (m *mockProvider) LogDownload(ctx context.Context, units []string, sinceHours int) (string, error) {
	return "/tmp/mock-logs.tar.gz", nil
}
func (m *mockProvider) LogAlertRules(ctx context.Context) ([]LogAlertRule, error) {
	return []LogAlertRule{
		{Name: "error-spike", Pattern: "error", Service: "nasd.service", Threshold: 5, WindowMins: 10, Severity: "crit", Channel: "discord", Enabled: true},
	}, nil
}
func (m *mockProvider) CreateLogAlertRule(ctx context.Context, r LogAlertRule) (LogAlertRule, error) { return r, nil }
func (m *mockProvider) DeleteLogAlertRule(ctx context.Context, name string) error { return nil }
func (m *mockProvider) LogStats(ctx context.Context) ([]LogStats, error) {
	return []LogStats{
		{Service: "nasd.service", LinesPerSec: 0.5, ErrorsPerMin: 2, Sparkline: []int{10, 12, 8, 15, 11, 9, 13, 7, 14, 10}},
		{Service: "smbd.service", LinesPerSec: 0.2, ErrorsPerMin: 0, Sparkline: []int{5, 3, 7, 4, 6, 2, 8, 5, 3, 7}},
	}, nil
}
func (m *mockProvider) ContainerRestartLoops(ctx context.Context) ([]ContainerRestartEvent, error) {
	return []ContainerRestartEvent{}, nil
}
func (m *mockProvider) LokiConfig(ctx context.Context) (LokiConfig, error) {
	return LokiConfig{Enabled: false, URL: "", PushIntervalSec: 60}, nil
}
func (m *mockProvider) SetLokiConfig(ctx context.Context, cfg LokiConfig) error { return nil }
func (m *mockProvider) ExportLogsToS3(ctx context.Context, units []string, sinceHours int) (string, error) {
	return "/tmp/mock-logs-s3.tar.gz", nil
}

// ── BATCH-J (M436-M450): Security & Compliance mocks ──
func (m *mockProvider) TrivyScan(ctx context.Context, image string) (CVEReport, error) {
	return CVEReport{
		Image:     image,
		ScannedAt: time.Now().Unix(),
		Vulnerabilities: []CVEEntry{
			{ID: "CVE-2024-1234", Severity: "HIGH", Title: "Buffer overflow in libssl", Package: "libssl", Installed: "1.1.0", Fixed: "1.1.1"},
			{ID: "CVE-2024-5678", Severity: "MEDIUM", Title: "Integer overflow", Package: "libcrypto", Installed: "1.1.0", Fixed: ""},
		},
		Summary: CVESummary{Total: 2, High: 1, Medium: 1},
	}, nil
}
func (m *mockProvider) TrivyResults(ctx context.Context, image string) (CVEReport, error) {
	return m.TrivyScan(ctx, image)
}
func (m *mockProvider) RunLynis(ctx context.Context) (string, error) {
	return "Lynis audit started in background", nil
}
func (m *mockProvider) LynisStatus(ctx context.Context) (LynisStatus, error) {
	return LynisStatus{Running: false, ReportID: "/var/lib/kilasos/lynis-reports/mock-report.txt"}, nil
}
func (m *mockProvider) LynisReport(ctx context.Context) ([]LynisFinding, error) {
	return []LynisFinding{
		{ID: "FILE-9810", Severity: "warning", Category: "File Permissions", Title: "world-writable file found", Solution: "chmod o-w"},
		{ID: "ACCT-9620", Severity: "suggestion", Category: "Users/Groups", Title: "minimum uid check", Solution: "configure min uid in login.defs"},
	}, nil
}
func (m *mockProvider) AppArmorStatus(ctx context.Context) ([]AppArmorProfile, error) {
	return []AppArmorProfile{
		{Name: "/usr/sbin/named", Mode: "enforce", Status: "loaded"},
		{Name: "/usr/sbin/smbd", Mode: "complain", Status: "loaded"},
	}, nil
}
func (m *mockProvider) SetAppArmorProfile(ctx context.Context, name, mode string) error { return nil }
func (m *mockProvider) SELinuxStatus(ctx context.Context) (SELinuxInfo, error) {
	return SELinuxInfo{Enabled: false, Mode: "Disabled"}, nil
}
func (m *mockProvider) USBAllowlist(ctx context.Context) ([]string, error) {
	return []string{"usb-vendor-1234", "usb-vendor-5678"}, nil
}
func (m *mockProvider) SetUSBAllowlist(ctx context.Context, ids []string) error { return nil }
func (m *mockProvider) BlockUSB(ctx context.Context, id string) error { return nil }
func (m *mockProvider) SSHKeyAudit(ctx context.Context) ([]SSHKeyAuditEntry, error) {
	return []SSHKeyAuditEntry{
		{Fingerprint: "SHA256:abc123...", KeyType: "ed25519", Comment: "admin@laptop", Used: true, LastUsed: "2026-05-01T10:00:00Z"},
		{Fingerprint: "SHA256:def456...", KeyType: "rsa", Comment: "backup@server", Used: false},
	}, nil
}
func (m *mockProvider) MarkSSHKeyUsed(ctx context.Context, fingerprint string) error { return nil }
func (m *mockProvider) SudoAudit(ctx context.Context, sinceDays int) ([]SudoEvent, error) {
	return []SudoEvent{
		{Time: "2026-05-07 10:00:00", User: "admin", TTY: "pts/0", Command: "/usr/bin/apt update", RunAs: "root"},
		{Time: "2026-05-07 09:30:00", User: "admin", TTY: "pts/0", Command: "/usr/bin/systemctl restart nasd", RunAs: "root"},
	}, nil
}
func (m *mockProvider) FailedLogins(ctx context.Context, sinceDays int) ([]FailedLogin, error) {
	return []FailedLogin{
		{Time: "2026-05-07 08:00:00", User: "admin", IP: "192.168.1.100", Count: 5},
		{Time: "2026-05-06 14:22:00", User: "root", IP: "10.0.0.1", Count: 3},
	}, nil
}
func (m *mockProvider) GenerateComplianceReport(ctx context.Context, format string) (string, error) {
	return fmt.Sprintf("/var/lib/kilasos/compliance-reports/CIS-report-mock.%s", format), nil
}
func (m *mockProvider) GDPRExport(ctx context.Context, username string) (string, error) {
	return "/var/lib/kilasos/gdpr-export-mock.tar.gz", nil
}
func (m *mockProvider) GDPRDelete(ctx context.Context, username string) error { return nil }
func (m *mockProvider) PrivacyMode(ctx context.Context) (PrivacyConfig, error) {
	return PrivacyConfig{Enabled: false, AnonymizeLogs: false, DisableTelemetry: false}, nil
}
func (m *mockProvider) SetPrivacyMode(ctx context.Context, cfg PrivacyConfig) error { return nil }
func (m *mockProvider) IntegrityCheck(ctx context.Context) ([]IntegrityFinding, error) {
	return []IntegrityFinding{
		{Path: "/usr/bin/openssl", Status: "OK"},
		{Path: "/bin/bash", Status: "OK"},
		{Path: "/usr/local/sbin/nasd", Status: "OK"},
	}, nil
}
