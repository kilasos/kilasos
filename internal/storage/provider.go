package storage

import (
	"context"
	"time"

	"github.com/kilasos/kilasos/internal/appcatalog"
)

type ArrayType string

const (
	ArrayTypeZFS          ArrayType = "zfs"
	ArrayTypeMergerFSSnap ArrayType = "mergerfs+snap"
	ArrayTypeZFSFlash     ArrayType = "zfs-flash"
)

type Topology string

const (
	TopologyStripe Topology = "stripe"
	TopologyMirror Topology = "mirror"
	TopologyRAIDZ  Topology = "raidz"
	TopologyRAIDZ2 Topology = "raidz2"
)

type Disk struct {
	Name               string `json:"name"`
	Path               string `json:"path"`
	SizeBytes          int64  `json:"size_bytes"`
	Model              string `json:"model,omitempty"`
	Serial             string `json:"serial,omitempty"`
	SmartOK            bool   `json:"smart_ok"`
	TempCelsius        *int   `json:"temp_celsius,omitempty"`
	PowerOnHours       *int   `json:"power_on_hours,omitempty"`
	ReallocatedSectors *int   `json:"reallocated_sectors,omitempty"`
}

type ArraySpec struct {
	Name     string    `json:"name"`
	Type     ArrayType `json:"type"`
	Topology Topology  `json:"topology,omitempty"`
	Devices  []string  `json:"devices"`
}

type Array struct {
	ArraySpec
	MountPath string `json:"mount_path,omitempty"`
	Status    string `json:"status"`
}

type Share struct {
	Name       string `json:"name"`
	Pool       string `json:"pool"`
	Path       string `json:"path"`
	Comment    string `json:"comment,omitempty"`
	ReadOnly   bool   `json:"read_only"`
	Public     bool   `json:"public"`
	NFS        bool   `json:"nfs"`
	NFSClients string `json:"nfs_clients,omitempty"` // e.g. "192.168.1.0/24" or "*"
	NFSOptions string `json:"nfs_options,omitempty"` // e.g. "rw,sync,no_subtree_check"
}

type SystemMetrics struct {
	CPUPercent    float64     `json:"cpu_percent"`
	MemTotal      int64       `json:"mem_total"`
	MemUsed       int64       `json:"mem_used"`
	NetInterfaces []NetIface  `json:"net_interfaces"`
	PoolUsage     []PoolUsage `json:"pool_usage"`
}

type NetIface struct {
	Name          string  `json:"name"`
	RxBytesPerSec float64 `json:"rx_bytes_per_sec"`
	TxBytesPerSec float64 `json:"tx_bytes_per_sec"`
}

type PoolUsage struct {
	Name  string `json:"name"`
	Total int64  `json:"total"`
	Used  int64  `json:"used"`
	Free  int64  `json:"free"`
}

type Container struct {
	ID      string           `json:"id"`
	Name    string           `json:"name"`
	Image   string           `json:"image"`
	State   string           `json:"state"`
	Status  string           `json:"status"`
	Created int64            `json:"created"`
	Ports   []string         `json:"ports"`
	Mounts  []ContainerMount `json:"mounts,omitempty"`
}

type ContainerInspect struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Image       string            `json:"image"`
	Created     string            `json:"created"`
	RestartPolicy string          `json:"restart_policy"`
	Env         []string          `json:"env"`
	Mounts      []ContainerMount  `json:"mounts"`
	Networks    []string          `json:"networks"`
	CPUShares   int64             `json:"cpu_shares"`
	MemLimit    int64             `json:"mem_limit"`
	PidLimit    int64             `json:"pid_limit,omitempty"`
}

type ContainerMount struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Source      string `json:"source"`
	Destination string `json:"destination"`
	RW          bool   `json:"rw"`
}

type ContainerStats struct {
	CPUPercent float64 `json:"cpu_percent"`
	MemUsed    int64   `json:"mem_used"`
	MemLimit   int64   `json:"mem_limit"`
	MemPercent float64 `json:"mem_percent"`
	RxBytes    int64   `json:"rx_bytes"`
	TxBytes    int64   `json:"tx_bytes"`
}

type ARCStats struct {
	SizeBytes   int64   `json:"size_bytes"`
	MaxBytes    int64   `json:"max_bytes"`
	HitPct      float64 `json:"hit_pct"`
	L2SizeBytes int64   `json:"l2_size_bytes"`
	L2HitPct    float64 `json:"l2_hit_pct"`
}

type SystemInfo struct {
	Hostname   string  `json:"hostname"`
	OS         string  `json:"os"`
	Kernel     string  `json:"kernel"`
	Uptime     int64   `json:"uptime_seconds"`
	LoadAvg1   float64 `json:"load_avg_1"`
	LoadAvg5   float64 `json:"load_avg_5"`
	LoadAvg15  float64 `json:"load_avg_15"`
	CPUCores   int     `json:"cpu_cores"`
}

type VDev struct {
	Name      string `json:"name"`
	State     string `json:"state"`
	ReadErrs  int64  `json:"read_errs"`
	WriteErrs int64  `json:"write_errs"`
	CksmErrs  int64  `json:"cksum_errs"`
	Indent    int    `json:"indent"`
}

type ScrubStatus struct {
	State    string  `json:"state"`    // none | scrubbing | completed | paused | canceled
	Progress float64 `json:"progress"` // 0–100
	Errors   int64   `json:"errors"`
}

type PoolHealth struct {
	Name        string      `json:"name"`
	State       string      `json:"state"`
	SizeBytes   int64       `json:"size_bytes"`
	AllocBytes  int64       `json:"alloc_bytes"`
	FreeBytes   int64       `json:"free_bytes"`
	FragPercent int         `json:"frag_percent"`
	VDevs       []VDev      `json:"vdevs"`
	Scrub       ScrubStatus `json:"scrub"`
	Errors      string      `json:"errors,omitempty"`
}

type Dataset struct {
	Name         string  `json:"name"`         // full name e.g. datapool/movies
	Pool         string  `json:"pool"`         // just the pool name
	MountPoint   string  `json:"mountpoint"`   // e.g. /mnt/datapool/movies
	UsedBytes    int64   `json:"used_bytes"`
	AvailBytes   int64   `json:"avail_bytes"`
	Encrypted    bool    `json:"encrypted"`
	CompressRatio float64 `json:"compress_ratio"` // e.g. 1.50 means 1.5x compression
}

type PoolEvent struct {
	Time    int64  `json:"time"`
	Class   string `json:"class"`   // e.g. "resource.fs.zfs.ok"
	Pool    string `json:"pool"`
	Message string `json:"message"`
}

type SMBConnection struct {
	PID      int    `json:"pid"`
	Machine  string `json:"machine"`
	Username string `json:"username"`
	Connected string `json:"connected"` // timestamp string
}

type JournalSearchResult struct {
	Unit    string `json:"unit"`
	Time    string `json:"time"`
	Message string `json:"message"`
}

type ServiceDiscovery struct {
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Service string `json:"service"` // e.g. "http", "ssh", "smb"
	Banner  string `json:"banner,omitempty"`
}

type ZFSPoolProps struct {
	Atime         string `json:"atime"`
	Compression   string `json:"compression"`
	Dedup         string `json:"dedup"`
	Autoexpand    string `json:"autoexpand"`
	Autoreplace   string `json:"autoreplace"`
	Listsnapshots string `json:"listsnapshots"`
}

type ZFSPoolPropsUpdate struct {
	Compression   *string `json:"compression,omitempty"`
	Dedup         *string `json:"dedup,omitempty"`
	Autoexpand    *string `json:"autoexpand,omitempty"`
	Autoreplace   *string `json:"autoreplace,omitempty"`
	Listsnapshots *string `json:"listsnapshots,omitempty"`
}

type PackageUpdate struct {
	Name           string `json:"name"`
	CurrentVersion string `json:"current_version"`
	NewVersion     string `json:"new_version"`
}

type SystemUser struct {
	Name   string   `json:"name"`
	UID    int      `json:"uid"`
	GID    int      `json:"gid"`
	Home   string   `json:"home"`
	Shell  string   `json:"shell"`
	Groups []string `json:"groups"`
}

type CronJob struct {
	User     string `json:"user"`
	Schedule string `json:"schedule"`
	Command  string `json:"command"`
	Source   string `json:"source"`
}

type CPUCore struct {
	ID         int     `json:"id"`
	FreqMHz    float64 `json:"freq_mhz"`
	MaxFreqMHz float64 `json:"max_freq_mhz"`
}

type ThermalZone struct {
	Name  string  `json:"name"`
	TempC float64 `json:"temp_c"`
}

type CPUFreqInfo struct {
	Cores []CPUCore    `json:"cores"`
	Zones []ThermalZone `json:"zones"`
}

type DiskBenchmark struct {
	DevPath     string  `json:"dev_path"`
	ReadMBps    float64 `json:"read_mbps"`
	DurationSec float64 `json:"duration_sec"`
}

type ShareStats struct {
	Name       string `json:"name"`
	Path       string `json:"path"`
	TotalBytes int64  `json:"total_bytes"`
	UsedBytes  int64  `json:"used_bytes"`
	FreeBytes  int64  `json:"free_bytes"`
}

type ARPEntry struct {
	IP    string `json:"ip"`
	MAC   string `json:"mac"`
	Iface string `json:"iface"`
	State string `json:"state"`
}

type Snapshot struct {
	Name      string `json:"name"`
	Pool      string `json:"pool"`
	FullName  string `json:"full_name"`
	Created   int64  `json:"created"`
	UsedBytes int64  `json:"used_bytes"`
	RefdBytes int64  `json:"refd_bytes"`
}

type DNSConfig struct {
	Nameservers []string `json:"nameservers"`
	Search      []string `json:"search"`
	Domain      string   `json:"domain,omitempty"`
}

type HostEntry struct {
	IP       string   `json:"ip"`
	Hostname string   `json:"hostname"`
	Aliases  []string `json:"aliases,omitempty"`
}

type SystemService struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	State       string `json:"state"`   // active/inactive/failed
	SubState    string `json:"substate"` // running/dead/exited
	Enabled     bool   `json:"enabled"`
}

type MemDetail struct {
	Total    int64 `json:"total"`
	Used     int64 `json:"used"`
	Free     int64 `json:"free"`
	Buffers  int64 `json:"buffers"`
	Cached   int64 `json:"cached"`
	SwapTotal int64 `json:"swap_total"`
	SwapUsed int64 `json:"swap_used"`
	SwapFree int64 `json:"swap_free"`
}

type SystemSettings struct {
	Hostname   string `json:"hostname"`
	Timezone   string `json:"timezone"`
	NTPEnabled bool   `json:"ntp_enabled"`
	NTPSynced  bool   `json:"ntp_synced"`
}

type SettingsUpdate struct {
	Hostname *string `json:"hostname,omitempty"`
	Timezone *string `json:"timezone,omitempty"`
	NTP      *bool   `json:"ntp,omitempty"`
}

type DatasetQuota struct {
	QuotaBytes       int64 `json:"quota_bytes"`       // 0 = none
	ReservationBytes int64 `json:"reservation_bytes"` // 0 = none
	UsedBytes        int64 `json:"used_bytes"`
	AvailableBytes   int64 `json:"available_bytes"`
}

type SambaGlobal struct {
	Workgroup      string `json:"workgroup"`
	ServerString   string `json:"server_string"`
	MaxConnections int    `json:"max_connections"`
	LogLevel       int    `json:"log_level"`
}

type NetIfaceStats struct {
	Name     string `json:"name"`
	RxBytes  int64  `json:"rx_bytes"`
	TxBytes  int64  `json:"tx_bytes"`
	RxErrors int64  `json:"rx_errors"`
	TxErrors int64  `json:"tx_errors"`
	RxDropped int64 `json:"rx_dropped"`
	TxDropped int64 `json:"tx_dropped"`
}

type TLSCertInfo struct {
	Subject    string   `json:"subject"`
	Issuer     string   `json:"issuer"`
	NotBefore  string   `json:"not_before"`
	NotAfter   string   `json:"not_after"`
	SANs       []string `json:"sans"`
	Valid      bool     `json:"valid"`
	DaysLeft   int      `json:"days_left"`
}

type LastLogin struct {
	User string `json:"user"`
	From string `json:"from"`
	When string `json:"when"`
}

type ScrubSchedule struct {
	Pool     string `json:"pool"`
	Schedule string `json:"schedule"` // cron expression or human-readable
	Enabled  bool   `json:"enabled"`
}

type ExecResult struct {
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	ExitCode int    `json:"exit_code"`
}

type FileSearchResult struct {
	Path     string `json:"path"`
	Name     string `json:"name"`
	SizeBytes int64 `json:"size_bytes"`
	Modified int64  `json:"modified"`
	IsDir    bool   `json:"is_dir"`
}

type SnapshotDiff struct {
	Change string `json:"change"` // "+" added, "-" removed, "M" modified
	Path   string `json:"path"`
}

type SMTPConfig struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	User     string `json:"user"`
	Password string `json:"password,omitempty"`
	From     string `json:"from"`
	To       string `json:"to"`
	TLS      bool   `json:"tls"`
}

type QuotaUpdate struct {
	QuotaBytes       *int64 `json:"quota_bytes"`       // nil = don't change; 0 = remove
	ReservationBytes *int64 `json:"reservation_bytes"` // nil = don't change; 0 = remove
}

type ImportCandidate struct {
	Name  string `json:"name"`
	GUID  string `json:"guid"`
	State string `json:"state"` // e.g. "ONLINE", "DEGRADED"
	Disks []string `json:"disks,omitempty"`
}

type SmartTestStatus struct {
	Running      bool   `json:"running"`
	Progress     int    `json:"progress"`      // percent complete when running
	StatusString string `json:"status_string"` // human-readable from smartctl
}

type SmartTestResult struct {
	Num        int    `json:"num"`
	Type       string `json:"type"`
	Status     string `json:"status"`
	Hours      int    `json:"lifetime_hours"`
	LBA        string `json:"lba_first_error,omitempty"`
	Remaining  int    `json:"remaining_pct"`
}

type UserQuota struct {
	User      string `json:"user"`
	QuotaBytes int64 `json:"quota_bytes"`
	UsedBytes  int64 `json:"used_bytes"`
}

type NFSExport struct {
	Path    string   `json:"path"`
	Clients []string `json:"clients"` // e.g. ["*(rw,sync,no_subtree_check)"]
}

type AlertRule struct {
	Name      string  `json:"name"`      // e.g. "cpu", "mem", "disk:tank"
	Threshold float64 `json:"threshold"` // percentage
	Enabled   bool    `json:"enabled"`
}

type TailscaleNode struct {
	Hostname  string   `json:"hostname"`
	IP        string   `json:"ip"`
	OS        string   `json:"os,omitempty"`
	Online    bool     `json:"online"`
	ExitNode  bool     `json:"exit_node"`
	Tags      []string `json:"tags,omitempty"`
}

type TailscaleStatus struct {
	Self    TailscaleNode   `json:"self"`
	Peers   []TailscaleNode `json:"peers"`
	Running bool            `json:"running"`
}

type ComposeProject struct {
	Name     string `json:"name"`
	Dir      string `json:"dir"`
	Status   string `json:"status"` // "running", "partial", "exited"
	Services int    `json:"services"`
}

type UPSInfo struct {
	Available    bool    `json:"available"`
	Model        string  `json:"model,omitempty"`
	Status       string  `json:"status,omitempty"`  // ONLINE, ONBATT, LOWBATT
	BattPct      float64 `json:"batt_pct,omitempty"`
	TimeLeft     float64 `json:"time_left_min,omitempty"`
	LoadPct      float64 `json:"load_pct,omitempty"`
	LineVoltage  float64 `json:"line_voltage,omitempty"`
	BattVoltage  float64 `json:"batt_voltage,omitempty"`
	Driver       string  `json:"driver,omitempty"` // "apcupsd" or "nut"
}


type IfaceConfig struct {
	DHCP    bool     `json:"dhcp"`
	Address string   `json:"address,omitempty"` // CIDR e.g. "10.0.0.1/24"
	Gateway string   `json:"gateway,omitempty"`
	DNS     []string `json:"dns,omitempty"`
}

type SSHKey struct {
	Type    string `json:"type"`
	Key     string `json:"key"`     // base64 blob — used as identifier for deletion
	Comment string `json:"comment,omitempty"`
}

type PoolIO struct {
	Name         string  `json:"name"`
	ReadOpPS     float64 `json:"read_ops_ps"`
	WriteOpPS    float64 `json:"write_ops_ps"`
	ReadBytesPS  float64 `json:"read_bytes_ps"`
	WriteBytesPS float64 `json:"write_bytes_ps"`
}

type DockerImage struct {
	ID         string   `json:"id"`
	Tags       []string `json:"tags"`
	SizeBytes  int64    `json:"size_bytes"`
	Created    int64    `json:"created"`
}

type DatasetProps struct {
	Compression  string `json:"compression"`   // on/off/lz4/gzip/zstd
	Atime        string `json:"atime"`         // on/off
	Recordsize   string `json:"recordsize"`    // 512/4K/8K/16K/32K/64K/128K
	Dedup        string `json:"dedup"`         // on/off
	Checksum     string `json:"checksum"`      // on/off/sha256/sha512
	Readonly     string `json:"readonly"`      // on/off
	Snapdir      string `json:"snapdir"`       // hidden/visible
	Volsize      string `json:"volsize,omitempty"`
}

type DatasetPropsUpdate struct {
	Compression *string `json:"compression,omitempty"`
	Atime       *string `json:"atime,omitempty"`
	Recordsize  *string `json:"recordsize,omitempty"`
	Dedup       *string `json:"dedup,omitempty"`
	Readonly    *string `json:"readonly,omitempty"`
}

type SmartDetail struct {
	DevPath    string       `json:"dev_path"`
	Model      string       `json:"model"`
	Serial     string       `json:"serial"`
	Firmware   string       `json:"firmware"`
	CapacityGB float64      `json:"capacity_gb"`
	SmartOK    bool         `json:"smart_ok"`
	TempC      *int         `json:"temp_celsius,omitempty"`
	PowerOnH   *int         `json:"power_on_hours,omitempty"`
	Attributes []SmartAttr  `json:"attributes"`
}

type SmartAttr struct {
	ID        int    `json:"id"`
	Name      string `json:"name"`
	Value     int    `json:"value"`
	Worst     int    `json:"worst"`
	Raw       string `json:"raw"`
	WhenFail  string `json:"when_fail"`
}

type DiskIO struct {
	Name        string  `json:"name"`         // e.g. "sda"
	ReadBytesPS float64 `json:"read_bytes_ps"` // bytes/sec
	WriteBytesPS float64 `json:"write_bytes_ps"`
}

type Process struct {
	PID     int     `json:"pid"`
	User    string  `json:"user"`
	CPUPct  float64 `json:"cpu_pct"`
	MemPct  float64 `json:"mem_pct"`
	MemRSS  int64   `json:"mem_rss_bytes"`
	Command string  `json:"command"`
}

type DockerVolume struct {
	Name       string `json:"name"`
	Driver     string `json:"driver"`
	Mountpoint string `json:"mountpoint"`
	SizeBytes  int64  `json:"size_bytes"` // -1 if unknown
}

type NetDiagResult struct {
	Target  string   `json:"target"`
	Type    string   `json:"type"` // ping | dns
	Output  string   `json:"output"`
	Success bool     `json:"success"`
}

type PowerStatus struct {
	Pending bool   `json:"pending"`
	Action  string `json:"action,omitempty"` // poweroff | reboot
	When    string `json:"when,omitempty"`   // RFC3339
}

type NetworkIface struct {
	Name        string   `json:"name"`
	MAC         string   `json:"mac"`
	IPAddresses []string `json:"ip_addresses"`
	SpeedMbps   int      `json:"speed_mbps"` // -1 if unknown
	Operstate   string   `json:"operstate"`  // up/down/unknown
	IsDefault   bool     `json:"is_default"`
	MTU         int      `json:"mtu"`
}

type Provider interface {
	Disks(ctx context.Context) ([]Disk, error)
	Arrays(ctx context.Context) ([]Array, error)
	CreateArray(ctx context.Context, spec ArraySpec, force bool) (Array, error)
	StartArray(ctx context.Context, name string) error
	StopArray(ctx context.Context, name string) error
	DeleteArray(ctx context.Context, name string) error
	Shares(ctx context.Context) ([]Share, error)
	CreateShare(ctx context.Context, s Share) (Share, error)
	DeleteShare(ctx context.Context, name string) error
	Metrics(ctx context.Context) (SystemMetrics, error)
	Containers(ctx context.Context) ([]Container, error)
	StartContainer(ctx context.Context, id string) error
	StopContainer(ctx context.Context, id string) error
	RemoveContainer(ctx context.Context, id string) error
	PoolHealth(ctx context.Context, name string) (PoolHealth, error)
	StartScrub(ctx context.Context, name string) error
	Snapshots(ctx context.Context, pool string) ([]Snapshot, error)
	CreateSnapshot(ctx context.Context, pool, name string) (Snapshot, error)
	DeleteSnapshot(ctx context.Context, pool, snap string) error
	RollbackSnapshot(ctx context.Context, pool, snap string) error
	GetSettings(ctx context.Context) (SystemSettings, error)
	ApplySettings(ctx context.Context, u SettingsUpdate) error
	NetInterfaces(ctx context.Context) ([]NetworkIface, error)
	SetInterfaceState(ctx context.Context, name string, up bool) error
	GetPowerStatus(ctx context.Context) (PowerStatus, error)
	Shutdown(ctx context.Context, delayMinutes int) error
	Reboot(ctx context.Context, delayMinutes int) error
	CancelShutdown(ctx context.Context) error
	SetDiskSpindown(ctx context.Context, devPath string, seconds int) error
	SSHKeys(ctx context.Context) ([]SSHKey, error)
	AddSSHKey(ctx context.Context, pubkey string) (SSHKey, error)
	DeleteSSHKey(ctx context.Context, blob string) error
	GetIfaceConfig(ctx context.Context, name string) (IfaceConfig, error)
	SetIfaceConfig(ctx context.Context, name string, cfg IfaceConfig) error
	StartSmartTest(ctx context.Context, devPath string, testType string) error
	GetSmartTestStatus(ctx context.Context, devPath string) (SmartTestStatus, error)
	GetDatasetQuota(ctx context.Context, pool string) (DatasetQuota, error)
	SetDatasetQuota(ctx context.Context, pool string, u QuotaUpdate) error
	ImportCandidates(ctx context.Context) ([]ImportCandidate, error)
	ImportPool(ctx context.Context, name, guid string) error
	ReplaceDisk(ctx context.Context, pool, oldDisk, newDisk string) error
	ContainerStats(ctx context.Context, id string) (ContainerStats, error)
	ContainerLogs(ctx context.Context, id, tail string) (string, error)
	ARCStats(ctx context.Context) (ARCStats, error)
	SystemInfo(ctx context.Context) (SystemInfo, error)
	UpdateShare(ctx context.Context, name string, update Share) (Share, error)
	Datasets(ctx context.Context, pool string) ([]Dataset, error)
	CreateDataset(ctx context.Context, pool, name string) (Dataset, error)
	CreateEncryptedDataset(ctx context.Context, pool, name, passphrase string) (Dataset, error)
	DeleteDataset(ctx context.Context, pool, name string) error
	LoadEncryptionKey(ctx context.Context, dataset, passphrase string) error
	WipeDisk(ctx context.Context, path string) error
	TrimPool(ctx context.Context, pool string) error
	PullImage(ctx context.Context, image string) (string, error)
	DiskIO(ctx context.Context) ([]DiskIO, error)
	Processes(ctx context.Context) ([]Process, error)
	DockerVolumes(ctx context.Context) ([]DockerVolume, error)
	RemoveDockerVolume(ctx context.Context, name string) error
	NetDiag(ctx context.Context, diagType, target string) (NetDiagResult, error)
	GetDatasetProps(ctx context.Context, dataset string) (DatasetProps, error)
	SetDatasetProps(ctx context.Context, dataset string, u DatasetPropsUpdate) error
	SmartDetail(ctx context.Context, devPath string) (SmartDetail, error)
	DockerImages(ctx context.Context) ([]DockerImage, error)
	RemoveDockerImage(ctx context.Context, id string) error
	PoolIO(ctx context.Context) ([]PoolIO, error)
	InspectContainer(ctx context.Context, id string) (ContainerInspect, error)
	PoolEvents(ctx context.Context, pool string) ([]PoolEvent, error)
	SMBConnections(ctx context.Context) ([]SMBConnection, error)
	CloneSnapshot(ctx context.Context, pool, snap, cloneName string) error
	Resilver(ctx context.Context, pool string) error
	ExpandPool(ctx context.Context, pool string) error
	SearchJournal(ctx context.Context, query string, n int) ([]JournalSearchResult, error)
	GetPoolProps(ctx context.Context, pool string) (ZFSPoolProps, error)
	SetPoolProps(ctx context.Context, pool string, u ZFSPoolPropsUpdate) error
	ScanServices(ctx context.Context, host string) ([]ServiceDiscovery, error)
	PendingUpdates(ctx context.Context) ([]PackageUpdate, error)
	SystemUsers(ctx context.Context) ([]SystemUser, error)
	AddSystemUser(ctx context.Context, name, password string) error
	DeleteSystemUser(ctx context.Context, name string) error
	CronJobs(ctx context.Context) ([]CronJob, error)
	CPUFreq(ctx context.Context) (CPUFreqInfo, error)
	BenchmarkDisk(ctx context.Context, devPath string) (DiskBenchmark, error)
	ShareStats(ctx context.Context) ([]ShareStats, error)
	ARPTable(ctx context.Context) ([]ARPEntry, error)
	FirewallRules(ctx context.Context) (string, error)
	GetDNSConfig(ctx context.Context) (DNSConfig, error)
	SetDNSConfig(ctx context.Context, cfg DNSConfig) error
	GetHosts(ctx context.Context) ([]HostEntry, error)
	AddHost(ctx context.Context, entry HostEntry) error
	DeleteHost(ctx context.Context, ip, hostname string) error
	ListServices(ctx context.Context) ([]SystemService, error)
	ServiceAction(ctx context.Context, name, action string) error
	MemDetail(ctx context.Context) (MemDetail, error)
	GetSambaGlobal(ctx context.Context) (SambaGlobal, error)
	SetSambaGlobal(ctx context.Context, cfg SambaGlobal) error
	NetIfaceStats(ctx context.Context) ([]NetIfaceStats, error)
	TLSCert(ctx context.Context, host string, port int) (TLSCertInfo, error)
	LastLogins(ctx context.Context, n int) ([]LastLogin, error)
	ScrubSchedules(ctx context.Context) ([]ScrubSchedule, error)
	SetScrubSchedule(ctx context.Context, pool, schedule string, enabled bool) error
	Exec(ctx context.Context, command string) (ExecResult, error)
	SearchFiles(ctx context.Context, root, pattern string, maxResults int) ([]FileSearchResult, error)
	SnapshotDiff(ctx context.Context, pool, snapA, snapB string) ([]SnapshotDiff, error)
	ContainerExec(ctx context.Context, containerID, command string) (ExecResult, error)
	GetSMTPConfig(ctx context.Context) (SMTPConfig, error)
	SetSMTPConfig(ctx context.Context, cfg SMTPConfig) error
	SendTestEmail(ctx context.Context) error
	UPSStatus(ctx context.Context) (UPSInfo, error)
	TailscaleStatus(ctx context.Context) (TailscaleStatus, error)
	ComposeProjects(ctx context.Context) ([]ComposeProject, error)
	ComposeAction(ctx context.Context, dir, action string) error
	UpdateContainerLimits(ctx context.Context, id string, memBytes int64, cpuPercent float64) error
	SetSharePerms(ctx context.Context, shareName, owner, group string, mode uint32) error
	NFSExports(ctx context.Context) ([]NFSExport, error)
	AddNFSExport(ctx context.Context, path, clients string) error
	DeleteNFSExport(ctx context.Context, path string) error
	GetAlertRules(ctx context.Context) ([]AlertRule, error)
	SetAlertRules(ctx context.Context, rules []AlertRule) error
	SmartTestHistory(ctx context.Context, devPath string) ([]SmartTestResult, error)
	UserQuotas(ctx context.Context, dataset string) ([]UserQuota, error)
	SetUserQuota(ctx context.Context, dataset, user string, quotaBytes int64) error
	ChangeEncryptionKey(ctx context.Context, dataset, newPassphrase string) error
	JournalExport(ctx context.Context) (string, error)
	DockerDaemonConfig(ctx context.Context) (map[string]interface{}, error)
	SetDockerDaemonConfig(ctx context.Context, cfg map[string]interface{}) error
	KillProcess(ctx context.Context, pid, signal int) error
	SystemEntropy(ctx context.Context) (int, error)
	SetDiskAPM(ctx context.Context, devPath string, level int) error
	GetDiskAPM(ctx context.Context, devPath string) (int, error)
	ResolveHostname(ctx context.Context, ip string) (string, error)
	DiskSpinState(ctx context.Context, devPath string) (string, error)
	PingHost(ctx context.Context, host string, count int) (PingResult, error)
	FanSpeeds(ctx context.Context) ([]FanInfo, error)
	RouteTable(ctx context.Context) ([]RouteEntry, error)
	TimeStatus(ctx context.Context) (TimeInfo, error)
	WireguardStatus(ctx context.Context) ([]WireguardIface, error)
	MDRaidStatus(ctx context.Context) (string, error)
	SMBSessions(ctx context.Context) ([]SMBSession, error)
	CPUTemperatures(ctx context.Context) ([]TempInfo, error)
	GetHostname(ctx context.Context) (string, error)
	SetHostname(ctx context.Context, name string) error
	IPTablesRules(ctx context.Context) (string, error)
	TriggerSMARTTest(ctx context.Context, devPath, testType string) error
	DockerPrune(ctx context.Context, volumes bool) (string, error)
	USBDevices(ctx context.Context) ([]USBDevice, error)
	PCIDevices(ctx context.Context) ([]PCIDevice, error)
	LoadAverages(ctx context.Context) (LoadAvg, error)
	SwapInfo(ctx context.Context) ([]SwapEntry, error)
	ConnectionSummary(ctx context.Context) (string, error)
	ContainerEnv(ctx context.Context, id string) ([]string, error)
	DiskPartitions(ctx context.Context) ([]LsblkEntry, error)
	GetSysctl(ctx context.Context, key string) (string, error)
	SetSysctl(ctx context.Context, key, value string) error
	ZFSPoolTrim(ctx context.Context, pool string) error
	WhoLoggedIn(ctx context.Context) (string, error)
	GetACL(ctx context.Context, path string) (string, error)
	SetACL(ctx context.Context, path, spec string) error
	SetContainerRestartPolicy(ctx context.Context, id, policy string) error
	Fail2BanStatus(ctx context.Context) (Fail2BanInfo, error)
	GetServerCertificate(ctx context.Context) (ServerCertInfo, error)
	UploadServerCertificate(ctx context.Context, certPEM, keyPEM []byte) error
	GenerateServerCertificate(ctx context.Context, commonName string) (string, error)
	DestroyDatasetRecursive(ctx context.Context, pool, dataset string, recursive bool) error
	GetMOTD(ctx context.Context) (string, error)
	SetMOTD(ctx context.Context, content string) error
	GetCronTab(ctx context.Context, user string) (string, error)
	SetCronTab(ctx context.Context, user, content string) error
	NetstatActive(ctx context.Context) ([]NetstatEntry, error)
	TestPort(ctx context.Context, host string, port int) (bool, error)
	ZFSHolds(ctx context.Context, snapshot string) ([]string, error)
	ZFSAddHold(ctx context.Context, snapshot, tag string) error
	ZFSReleaseHold(ctx context.Context, snapshot, tag string) error
	FailedSystemdUnits(ctx context.Context) ([]SystemdUnitInfo, error)
	NFSActiveMounts(ctx context.Context) ([]NFSMount, error)
	ZFSRenameDataset(ctx context.Context, oldName, newName string) error
	LogRotateStatus(ctx context.Context) (string, error)
	GetContainerHealth(ctx context.Context, id string) (ContainerHealthInfo, error)
	MDNSServices(ctx context.Context) ([]MDNSService, error)
	GetKernelParam(ctx context.Context, key string) (string, error)
	PauseContainer(ctx context.Context, id string) error
	UnpauseContainer(ctx context.Context, id string) error
	RestartContainer(ctx context.Context, id string) error
	ZFSBookmarks(ctx context.Context, dataset string) ([]ZFSBookmark, error)
	CreateZFSBookmark(ctx context.Context, snapshot, bookmark string) error
	GetCurrentRunlevel(ctx context.Context) (string, error)
	GetUptime(ctx context.Context) (UptimeInfo, error)
	NetMaskInfo(ctx context.Context) ([]NetIfaceMask, error)
	BatteryStatus(ctx context.Context) (BatteryInfo, error)
	GetSystemLocale(ctx context.Context) (LocaleInfo, error)
	SetTimezone(ctx context.Context, tz string) error
	ListTimezones(ctx context.Context) ([]string, error)
	OSRelease(ctx context.Context) (OSReleaseInfo, error)
	KernelModules(ctx context.Context) ([]KernelModule, error)
	IPRules(ctx context.Context) (string, error)
	NICStats(ctx context.Context, name string) (NICStatistics, error)
	SetMTU(ctx context.Context, name string, mtu int) error
	SystemdUnitDetail(ctx context.Context, name string) (SystemdUnitDetail, error)
	StartSystemdUnit(ctx context.Context, name string) error
	StopSystemdUnit(ctx context.Context, name string) error
	EnableSystemdUnit(ctx context.Context, name string) error
	DisableSystemdUnit(ctx context.Context, name string) error
	GetSysHostInfo(ctx context.Context) (HostHardwareInfo, error)
	JournalUnits(ctx context.Context) ([]string, error)
	GetJournalForUnit(ctx context.Context, unit string, lines int) (string, error)
	ZFSFeatures(ctx context.Context, pool string) ([]ZFSFeature, error)
	IP6Tables(ctx context.Context) (string, error)
	ConntrackCount(ctx context.Context) (int, error)
	Dmesg(ctx context.Context, lines int) (string, error)
	KernelCmdline(ctx context.Context) (string, error)
	NICOffloads(ctx context.Context, name string) (map[string]string, error)
	GetCPUInfoDetailed(ctx context.Context) (CPUDetail, error)
	ListMounts(ctx context.Context) ([]MountInfo, error)
	GetReadOnlyMounts(ctx context.Context) ([]string, error)
	NetlinkConntrack(ctx context.Context, max int) ([]ConntrackEntry, error)
	IOWait(ctx context.Context) (float64, error)
	ZFSPoolImportable(ctx context.Context) ([]string, error)
	ListInstalledKernels(ctx context.Context) ([]string, error)
	GetCurrentKernel(ctx context.Context) (string, error)
	NetworkSpeedTest(ctx context.Context, server string) (NetSpeedResult, error)
	GetDiskTemperatures(ctx context.Context) ([]DiskTemp, error)
	SystemBuildInfo(ctx context.Context) (SystemBuildInfo, error)
	GetVMSizes(ctx context.Context) ([]VMInfo, error)
	GetSudoers(ctx context.Context) (string, error)
	GetSSHDConfig(ctx context.Context) (string, error)
	SystemRecommendations(ctx context.Context) ([]SystemRecommendation, error)
	GetMaxOpenFiles(ctx context.Context) (int, error)
	GetTCPCongestionAlgo(ctx context.Context) (string, error)
	GetDiskSerial(ctx context.Context, devPath string) (string, error)
	NetworkInterfaceFeatures(ctx context.Context) ([]InterfaceFeature, error)
	GetZFSDatasetProperty(ctx context.Context, dataset, prop string) (string, error)
	SetZFSDatasetProperty(ctx context.Context, dataset, prop, value string) error
	OpenPortsAudit(ctx context.Context) ([]OpenPort, error)
	OOMKillerLog(ctx context.Context, lines int) ([]OOMEvent, error)
	ZRAMInfo(ctx context.Context) ([]ZRAMDevice, error)
	GetNTPServers(ctx context.Context) ([]string, error)
	SetNTPServers(ctx context.Context, servers []string) error
	GetTimeSyncStatus(ctx context.Context) (TimeSyncStatus, error)
	GetIPv6Status(ctx context.Context) (IPv6Status, error)
	ZFSScrubProgress(ctx context.Context, pool string) (ScrubProgress, error)
	ListLogins(ctx context.Context, count int) ([]LoginEvent, error)
	GetCurrentTimezoneOffset(ctx context.Context) (string, error)
	GetSystemBoots(ctx context.Context) ([]BootRecord, error)
	GetSMARTAttributes(ctx context.Context, devPath string) ([]SMARTAttribute, error)
	GetZFSDedupStats(ctx context.Context, pool string) (DedupStats, error)
	GetNVMeStats(ctx context.Context, devPath string) (NVMeInfo, error)
	GetGPUInfo(ctx context.Context) ([]GPUInfo, error)
	FlushARPCache(ctx context.Context) error
	GetECCErrors(ctx context.Context) ([]ECCEvent, error)
	GetMemFragmentation(ctx context.Context) (MemFragInfo, error)
	GetTopBandwidthIPs(ctx context.Context, max int) ([]BandwidthIP, error)
	GetSwapPressure(ctx context.Context) (PressureInfo, error)

	// ── Backup & Cloud Sync (M301-M315) ─────────────────────────────────────
	BorgInit(ctx context.Context, name, passphrase, encryption string) (BorgRepo, error)
	BorgCreateBackup(ctx context.Context, repoName, archiveName, paths string, excludes []string) (BorgArchive, error)
	BorgListArchives(ctx context.Context, repoName string) ([]BorgArchive, error)
	BorgDeleteArchive(ctx context.Context, repoName, archiveName string) error
	BorgPrune(ctx context.Context, repoName, policy string) (string, error)
	BorgRestore(ctx context.Context, repoName, archiveName, targetPath string) error
	BorgVerify(ctx context.Context, repoName, archiveName string) (BackupVerification, error)
	ResticInit(ctx context.Context, name, passphrase, backend string, creds map[string]string) (ResticRepo, error)
	ResticCreateBackup(ctx context.Context, repoName, paths string, tags []string) (ResticSnapshot, error)
	ResticListSnapshots(ctx context.Context, repoName string) ([]ResticSnapshot, error)
	ResticDeleteSnapshot(ctx context.Context, repoName, snapshotID string) error
	ResticRestore(ctx context.Context, repoName, snapshotID, targetPath string) error
	ResticVerify(ctx context.Context, repoName, snapshotID string) (BackupVerification, error)
	ResticForget(ctx context.Context, repoName string, keepHourly, keepDaily, keepWeekly, keepMonthly, keepYearly int) (string, error)
	RcloneRemoteAdd(ctx context.Context, name, remoteType, endpoint, sourcePath, destPath string, bandwidth string) (RcloneRemote, error)
	RcloneRemoteRemove(ctx context.Context, name string) error
	RcloneRemoteList(ctx context.Context) ([]RcloneRemote, error)
	RcloneSync(ctx context.Context, name string, oneWay bool, srcPath, destPath string, bandwidth string) (string, error)
	BackupJobs(ctx context.Context) ([]BackupJob, error)
	CreateBackupJob(ctx context.Context, j BackupJob) (BackupJob, error)
	DeleteBackupJob(ctx context.Context, id string) error
	UpdateBackupJob(ctx context.Context, j BackupJob) (BackupJob, error)
	RunBackupJob(ctx context.Context, id string) error
	BackupJobRuns(ctx context.Context, jobID string) ([]BackupJobRun, error)
	BackupJobRun(ctx context.Context, jobID, runID string) (BackupJobRun, error)
	RestorePoints(ctx context.Context, backupType, repo string) ([]RestorePoint, error)
	CloudCostEstimate(ctx context.Context, provider string, sizeGB float64) (CloudCostEstimate, error)
	BackupSecretsPath() string

	// M382: SMB Active Directory join
	SMBADJoin(ctx context.Context, realm, adminUser, adminPassword, ouPath string) error
	SMBADLeave(ctx context.Context, adminUser, adminPassword string) error
	SMBADStatus(ctx context.Context) (SMBADStatus, error)

	// ── App Marketplace (M346-M360) ─────────────────────────────────────────
	AppStacks(ctx context.Context) ([]AppStack, error)
	CreateAppStack(ctx context.Context, s AppStack) (AppStack, error)
	DeleteAppStack(ctx context.Context, name string) error
	AppUpdateAvailable(ctx context.Context, appName string) (AppUpdateInfo, error)
	AppUpdate(ctx context.Context, appName string, backup bool) (string, error)
	AppRollback(ctx context.Context, appName string, backupID string) (string, error)
	AppHealthStatus(ctx context.Context, appName string) (AppHealthInfo, error)
	AppExportConfig(ctx context.Context, appName string) (AppConfigExport, error)
	AppImportConfig(ctx context.Context, appName string, cfg AppConfigExport) error
	AppCustomTemplate(ctx context.Context, composeYAML string) (appcatalog.AppTemplate, error)
	AppFavorites(ctx context.Context) ([]string, error)
	AppSetFavorite(ctx context.Context, appName string, fav bool) error
	AppSearch(ctx context.Context, q string, category string) ([]appcatalog.AppTemplate, error)

	// ╔═════════════════════════════════════════════════════════════════════════╗
	// ║ ── BATCH ANCHOR ZONES ── (each batch appends ITS methods only here)    ║
	// ║ Coordinator uses these to keep batches from colliding on append spots. ║
	// ║ DO NOT REMOVE these markers — they are load-bearing for clean merges.  ║
	// ╚═════════════════════════════════════════════════════════════════════════╝

	// ── BATCH-B (M316-M330): Monitoring & Alerting ──
	PrometheusMetrics(ctx context.Context) (string, error)
	HealthchecksPing(ctx context.Context, url string) error
	Notify(ctx context.Context, channel, event string, severity string) error
	NotificationChannels(ctx context.Context) ([]NotificationChannel, error)
	CreateNotificationChannel(ctx context.Context, ch NotificationChannel) (NotificationChannel, error)
	UpdateNotificationChannel(ctx context.Context, name string, ch NotificationChannel) (NotificationChannel, error)
	DeleteNotificationChannel(ctx context.Context, name string) error
	MonitorAlertRules(ctx context.Context) ([]MonitorAlertRule, error)
	CreateMonitorAlertRule(ctx context.Context, r MonitorAlertRule) (MonitorAlertRule, error)
	UpdateMonitorAlertRule(ctx context.Context, name string, r MonitorAlertRule) (MonitorAlertRule, error)
	DeleteMonitorAlertRule(ctx context.Context, name string) error
	AlertEvents(ctx context.Context, limit int) ([]AlertEvent, error)
	AcknowledgeAlert(ctx context.Context, id string) error
	SilenceAlert(ctx context.Context, ruleName string, hours int) error
	AnomalyScore(ctx context.Context, metric string, window int) (AnomalyResult, error)
	TestNotification(ctx context.Context, channel string) error

	// ── BATCH-C (M331-M345): Reverse Proxy & Tunnels ──
	// M331-M345: Caddy reverse proxy, Cloudflare Tunnel, Tailscale Funnel, WireGuard, DDNS, DHCP
	CaddySites(ctx context.Context) ([]CaddySite, error)
	CreateCaddySite(ctx context.Context, s CaddySite) (CaddySite, error)
	UpdateCaddySite(ctx context.Context, name string, s CaddySite) (CaddySite, error)
	DeleteCaddySite(ctx context.Context, name string) error
	CaddyReload(ctx context.Context) error
	TunnelStatus(ctx context.Context) (TunnelInfo, error)
	TunnelStart(ctx context.Context, name string, config string) error
	TunnelStop(ctx context.Context, name string) error
	TailscaleFunnel(ctx context.Context, port int, enable bool) error
	WireGuardPeers(ctx context.Context) ([]WireGuardPeer, error)
	WireGuardAddPeer(ctx context.Context, pubKey string) (WireGuardPeer, error)
	WireGuardRemovePeer(ctx context.Context, pubKey string) error
	WireGuardConfig(ctx context.Context) (WireGuardConfig, error)
	UPnPStatus(ctx context.Context) (UPnPStatus, error)
	UPnPForwardPort(ctx context.Context, internalPort int, protocol string) (int, error)
	UPnPRemovePort(ctx context.Context, internalPort int, protocol string) error
	DDNSUpdate(ctx context.Context, provider, domain, token string, ip string) error
	DNSmasqConfig(ctx context.Context) (string, error)
	SetDNSmasqConfig(ctx context.Context, cfg string) error
	DHCPConfig(ctx context.Context) (DHCPConfig, error)
	SetDHCPConfig(ctx context.Context, cfg DHCPConfig) error

	// ── BATCH-E (M361-M375): Storage Power-User ──
	BtrfsSubvolumes(ctx context.Context) ([]BtrfsSubvol, error)
	CreateBtrfsSubvol(ctx context.Context, path string) (BtrfsSubvol, error)
	DeleteBtrfsSubvol(ctx context.Context, path string) error
	BtrfsSnapshots(ctx context.Context) ([]BtrfsSnapshot, error)
	CreateBtrfsSnapshot(ctx context.Context, source, target string) (BtrfsSnapshot, error)
	DeleteBtrfsSnapshot(ctx context.Context, path string) error
	RestoreBtrfsSnapshot(ctx context.Context, path, snapshot string) error
	BtrfsScrub(ctx context.Context, path string) error
	BtrfsBalance(ctx context.Context, path string) error
	ZFSL2ARCStatus(ctx context.Context) ([]L2ARCDevice, error)
	ZFSL2ARCAdd(ctx context.Context, pool, device string) error
	ZFSL2ARCRemove(ctx context.Context, pool string) error
	ZFSSLOGStatus(ctx context.Context) ([]SLOGDevice, error)
	ZFSSLOGAdd(ctx context.Context, pool, device string) error
	ZFSSLOGRemove(ctx context.Context, pool string) error
	ZFSSpecialVdevStatus(ctx context.Context) ([]SpecialVdev, error)
	ZFSSpecialVdevAdd(ctx context.Context, pool, device string) error
	ZFSDDTProjection(ctx context.Context) (DDTProjection, error)
	DDTProjectionStatus(ctx context.Context) (DDTProjection, error)
	ZFSCompressionRatios(ctx context.Context) ([]CompressionRatio, error)
	LifecyclePolicies(ctx context.Context) ([]LifecyclePolicy, error)
	SetLifecyclePolicy(ctx context.Context, pol LifecyclePolicy) error
	DeleteLifecyclePolicy(ctx context.Context, name string) error
	StorageTierPolicy(ctx context.Context) (TierPolicy, error)
	SetStorageTierPolicy(ctx context.Context, pol TierPolicy) error
	DedupScannerStatus(ctx context.Context) (DedupScanResult, error)
	StartDedupScan(ctx context.Context, path string) error
	DiskBurnInStatus(ctx context.Context) (BurnInStatus, error)
	StartDiskBurnIn(ctx context.Context, disk string) error
	ReplacementWizardState(ctx context.Context, id string) (ReplacementWizardState, error)
	ReplacementWizardStep(ctx context.Context, id string, action string, data map[string]string) (ReplacementWizardState, error)
	PoolExpansionWizardState(ctx context.Context, id string) (PoolExpansionState, error)
	PoolExpansionStep(ctx context.Context, id string, action string, data map[string]string) (PoolExpansionState, error)

	// ── BATCH-G (M391-M405): Web File Manager ──
	FileTree(ctx context.Context, path string) ([]FileNode, error)
	FileList(ctx context.Context, path string) ([]FileNode, error)
	FileRead(ctx context.Context, path string) (string, error)
	FilePreview(ctx context.Context, path string) (FilePreview, error)
	FileRename(ctx context.Context, oldPath, newPath string) error
	FileCopy(ctx context.Context, src, dst string) error
	FileDelete(ctx context.Context, path string) error
	TrashList(ctx context.Context) ([]FileNode, error)
	TrashRestore(ctx context.Context, trashPath string) error
	TrashEmpty(ctx context.Context) error
	FileChmod(ctx context.Context, path string, mode string) error
	FileChown(ctx context.Context, path string, uid, gid int) error
	CreateShareLink(ctx context.Context, path string, opts ShareLinkOptions) (ShareLink, error)
	RevokeShareLink(ctx context.Context, id string) error
	GetShareLink(ctx context.Context, id string) (ShareLink, error)
	ListShareLinks(ctx context.Context) ([]ShareLink, error)
	// ResolveShareToken looks up a share by its public token, validates expiry
	// and max-uses, atomically increments the Used counter, and returns the link.
	// Used by the unauthenticated /share/{token} endpoint.
	ResolveShareToken(ctx context.Context, token string) (ShareLink, error)
	BulkDelete(ctx context.Context, paths []string) error
	BulkMove(ctx context.Context, ops []BulkMoveOp) error

	// ── BATCH-H (M406-M420): Mobile & UX Polish ──
	// (Builder 2 / MiniMax: mostly frontend; minimal Provider methods expected)

	// ── BATCH-I (M421-M435): Observability & Logs ──
	SyslogForwardingConfig(ctx context.Context) (SyslogConfig, error)
	SetSyslogForwarding(ctx context.Context, cfg SyslogConfig) error
	AuditRetentionPolicy(ctx context.Context) (AuditRetention, error)
	SetAuditRetentionPolicy(ctx context.Context, pol AuditRetention) error
	RotateAuditLogs(ctx context.Context) error
	SearchAuditLogs(ctx context.Context, q AuditLogQuery) ([]AuditLogEntry, error)
	AggregateSystemLogs(ctx context.Context, sinceHours int) ([]ServiceLogSummary, error)
	SearchContainerLogs(ctx context.Context, q ContainerLogQuery) ([]ContainerLogEntry, error)
	LogDownload(ctx context.Context, units []string, sinceHours int) (string, error)
	LogAlertRules(ctx context.Context) ([]LogAlertRule, error)
	CreateLogAlertRule(ctx context.Context, r LogAlertRule) (LogAlertRule, error)
	DeleteLogAlertRule(ctx context.Context, name string) error
	LogStats(ctx context.Context) ([]LogStats, error)
	ContainerRestartLoops(ctx context.Context) ([]ContainerRestartEvent, error)
	LokiConfig(ctx context.Context) (LokiConfig, error)
	SetLokiConfig(ctx context.Context, cfg LokiConfig) error
	ExportLogsToS3(ctx context.Context, units []string, sinceHours int) (string, error)

	// ── BATCH-J (M436-M450): Security & Compliance ──
	TrivyScan(ctx context.Context, image string) (CVEReport, error)
	TrivyResults(ctx context.Context, image string) (CVEReport, error)
	RunLynis(ctx context.Context) (string, error)
	LynisStatus(ctx context.Context) (LynisStatus, error)
	LynisReport(ctx context.Context) ([]LynisFinding, error)
	AppArmorStatus(ctx context.Context) ([]AppArmorProfile, error)
	SetAppArmorProfile(ctx context.Context, name, mode string) error
	SELinuxStatus(ctx context.Context) (SELinuxInfo, error)
	USBAllowlist(ctx context.Context) ([]string, error)
	SetUSBAllowlist(ctx context.Context, ids []string) error
	BlockUSB(ctx context.Context, id string) error
	SSHKeyAudit(ctx context.Context) ([]SSHKeyAuditEntry, error)
	MarkSSHKeyUsed(ctx context.Context, fingerprint string) error
	SudoAudit(ctx context.Context, sinceDays int) ([]SudoEvent, error)
	FailedLogins(ctx context.Context, sinceDays int) ([]FailedLogin, error)
	GenerateComplianceReport(ctx context.Context, format string) (string, error)
	GDPRExport(ctx context.Context, username string) (string, error)
	GDPRDelete(ctx context.Context, username string) error
	PrivacyMode(ctx context.Context) (PrivacyConfig, error)
	SetPrivacyMode(ctx context.Context, cfg PrivacyConfig) error
	IntegrityCheck(ctx context.Context) ([]IntegrityFinding, error)
}

// ── BATCH-C types ────────────────────────────────────────────────────────────

type CaddySite struct {
	Name       string            `json:"name"`
	Domain     string            `json:"domain"`
	TargetHost string            `json:"target_host"`
	TargetPort int               `json:"target_port"`
	BasicAuth  []CaddyBasicAuth  `json:"basic_auth,omitempty"`
	IPAllow    []string          `json:"ip_allow,omitempty"`
	Enabled    bool              `json:"enabled"`
	ACMEEmail  string            `json:"acme_email,omitempty"`
	TLS        string            `json:"tls"` // "auto", "off", or a cert path
}

type CaddyBasicAuth struct {
	User     string `json:"user"`
	Password string `json:"password"`
}

type TunnelInfo struct {
	Name      string `json:"name"`
	Connected bool   `json:"connected"`
	Endpoints []string `json:"endpoints,omitempty"`
	Error     string `json:"error,omitempty"`
}

type WireGuardPeer struct {
	PublicKey       string `json:"public_key"`
	AllowedIPs      string `json:"allowed_ips"`
	Endpoint        string `json:"endpoint,omitempty"`
	PersistentKeep  int    `json:"persistent_keepalive,omitempty"`
	LastHandshake   int64  `json:"last_handshake_unix,omitempty"`
	TransferRx      int64  `json:"transfer_rx_bytes"`
	TransferTx      int64  `json:"transfer_tx_bytes"`
}

type WireGuardConfig struct {
	InterfaceAddress string `json:"interface_address"`
	ListenPort       int    `json:"listen_port"`
	PrivateKey       string `json:"private_key,omitempty"`
	Peers            []WireGuardPeer `json:"peers"`
}

type UPnPStatus struct {
	Enabled    bool     `json:"enabled"`
	Gateway    string   `json:"gateway_ip"`
	MappedPorts []PortMap `json:"mapped_ports"`
}

type PortMap struct {
	InternalPort int    `json:"internal_port"`
	ExternalPort int    `json:"external_port"`
	Protocol     string `json:"protocol"`
	Description  string `json:"description,omitempty"`
}

type DHCPConfig struct {
	Enabled      bool     `json:"enabled"`
	RangeStart   string   `json:"range_start"`
	RangeEnd     string   `json:"range_end"`
	Subnet       string   `json:"subnet"`
	Router       string   `json:"router"`
	DNSServers   []string `json:"dns_servers"`
	LeaseTime    int      `json:"lease_time_hours"`
}

type SMBADStatus struct {
	Joined bool   `json:"joined"`
	Realm  string `json:"realm,omitempty"`
	Server string `json:"server,omitempty"`
	Site   string `json:"site,omitempty"`
}

// ── BATCH-B types ─────────────────────────────────────────────────────────────

type NotificationChannel struct {
	Name       string `json:"name"`
	Type       string `json:"type"` // healthchecks, ntfy, pushover, discord, telegram
	URL        string `json:"url,omitempty"`
	Token      string `json:"token,omitempty"`
	ChatID     string `json:"chat_id,omitempty"`
	WebhookURL string `json:"webhook_url,omitempty"`
	Enabled    bool   `json:"enabled"`
}

type MonitorAlertRule struct {
	Name         string    `json:"name"`
	Metric       string    `json:"metric"`
	Condition    string    `json:"condition"`
	Threshold    float64   `json:"threshold"`
	Severity     string    `json:"severity"`
	Channel      string    `json:"channel"`
	DedupeMins   int       `json:"dedupe_minutes"`
	EscalateMins int       `json:"escalate_minutes,omitempty"`
	SilenceUntil time.Time `json:"silence_until,omitempty"`
}

type AlertEvent struct {
	ID        string    `json:"id"`
	Rule      string    `json:"rule"`
	Metric    string    `json:"metric"`
	Value     float64   `json:"value"`
	Threshold float64   `json:"threshold"`
	Severity  string    `json:"severity"`
	Channel   string    `json:"channel"`
	Message   string    `json:"message"`
	Time      time.Time `json:"time"`
	Acked     bool      `json:"acked"`
	Silenced  bool      `json:"silenced"`
}

type AnomalyResult struct {
	Metric    string  `json:"metric"`
	Score     float64 `json:"score"` // z-score
	IsAnomaly bool    `json:"is_anomaly"`
	Threshold float64 `json:"threshold"`
	Message   string  `json:"message"`
}

type AppStack struct {
	Name        string       `json:"name"`
	Label       string       `json:"label"`
	Description string       `json:"description"`
	Services    []AppService `json:"services"`
	Icon        string       `json:"icon"`
}

type AppService struct {
	TemplateID string  `json:"template_id"`
	Name       string  `json:"name"`
	CPUPercent float64 `json:"cpu_percent,omitempty"`
	MemBytes   int64   `json:"mem_bytes,omitempty"`
}

type AppUpdateInfo struct {
	Available   bool   `json:"available"`
	CurrentTag  string `json:"current_tag"`
	LatestTag   string `json:"latest_tag"`
	ImageDigest string `json:"image_digest,omitempty"`
}

type AppBackup struct {
	ID        string    `json:"id"`
	AppName   string    `json:"app_name"`
	CreatedAt time.Time `json:"created_at"`
	Path      string    `json:"path"`
}

type AppHealthInfo struct {
	Status     string `json:"status"`
	Containers int    `json:"containers"`
	Running    int    `json:"running"`
	Message    string `json:"message,omitempty"`
}

type AppConfigExport struct {
	AppName       string            `json:"app_name"`
	TemplateID    string            `json:"template_id"`
	ComposeYAML   string            `json:"compose_yaml"`
	EnvVars       map[string]string `json:"env_vars"`
	Volumes       []AppVolumeMount  `json:"volumes"`
	AutoUpdate    bool              `json:"auto_update"`
	ResourceLimit AppResourceLimit `json:"resource_limit"`
}

type AppVolumeMount struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
	RW          bool   `json:"rw"`
}

type AppResourceLimit struct {
	CPUPercent float64 `json:"cpu_percent"`
	MemBytes   int64   `json:"mem_bytes"`
}

type FanInfo struct {
	Name    string `json:"name"`
	RPM     int    `json:"rpm"`
	MinRPM  int    `json:"min_rpm,omitempty"`
	MaxRPM  int    `json:"max_rpm,omitempty"`
	Alarm   bool   `json:"alarm"`
}

type RouteEntry struct {
	Dest    string `json:"dest"`
	Gateway string `json:"gateway"`
	Iface   string `json:"iface"`
	Metric  int    `json:"metric"`
	Flags   string `json:"flags,omitempty"`
}

type PingResult struct {
	Host        string  `json:"host"`
	Sent        int     `json:"sent"`
	Received    int     `json:"received"`
	PacketLoss  float64 `json:"packet_loss_pct"`
	MinMS       float64 `json:"min_ms"`
	AvgMS       float64 `json:"avg_ms"`
	MaxMS       float64 `json:"max_ms"`
	ReachableIP string  `json:"reachable_ip,omitempty"`
}

type TimeInfo struct {
	LocalTime   string `json:"local_time"`
	Timezone    string `json:"timezone"`
	NTPEnabled  bool   `json:"ntp_enabled"`
	NTPSync     bool   `json:"ntp_synced"`
	NTPServer   string `json:"ntp_server,omitempty"`
	RTCTime     string `json:"rtc_time,omitempty"`
}

type WireguardPeer struct {
	PublicKey       string `json:"public_key"`
	Endpoint        string `json:"endpoint,omitempty"`
	AllowedIPs      string `json:"allowed_ips"`
	LastHandshake   int64  `json:"last_handshake_sec"`
	RxBytes         int64  `json:"rx_bytes"`
	TxBytes         int64  `json:"tx_bytes"`
}

type WireguardIface struct {
	Name      string          `json:"name"`
	PublicKey string          `json:"public_key"`
	ListenPort int            `json:"listen_port"`
	Peers     []WireguardPeer `json:"peers"`
}

type SMBSession struct {
	PID      int    `json:"pid"`
	Machine  string `json:"machine"`
	Username string `json:"username"`
	Share    string `json:"share,omitempty"`
}

type TempInfo struct {
	Name  string  `json:"name"`
	Chip  string  `json:"chip"`
	TempC float64 `json:"temp_c"`
	High  float64 `json:"high_c,omitempty"`
	Crit  float64 `json:"crit_c,omitempty"`
}

type USBDevice struct {
	Bus    string `json:"bus"`
	Device string `json:"device"`
	ID     string `json:"id"`
	Name   string `json:"name"`
}

type PCIDevice struct {
	Slot   string `json:"slot"`
	Class  string `json:"class"`
	Vendor string `json:"vendor"`
	Device string `json:"device"`
}

type LoadAvg struct {
	One     float64 `json:"one"`
	Five    float64 `json:"five"`
	Fifteen float64 `json:"fifteen"`
	Running int     `json:"running"`
	Total   int     `json:"total"`
}

type SwapEntry struct {
	Filename string `json:"filename"`
	Type     string `json:"type"`
	SizeKB   int64  `json:"size_kb"`
	UsedKB   int64  `json:"used_kb"`
	Priority int    `json:"priority"`
}

type LsblkEntry struct {
	Name       string       `json:"name"`
	Size       string       `json:"size"`
	Type       string       `json:"type"`
	Fstype     string       `json:"fstype,omitempty"`
	Label      string       `json:"label,omitempty"`
	Mountpoint string       `json:"mountpoint,omitempty"`
	Children   []LsblkEntry `json:"children,omitempty"`
}

type Fail2BanInfo struct {
	Active     bool     `json:"active"`
	Jails      []string `json:"jails"`
	BannedIPs  []string `json:"banned_ips,omitempty"`
	TotalBans  int      `json:"total_bans"`
}

type ServerCertInfo struct {
	Subject    string `json:"subject"`
	Issuer     string `json:"issuer"`
	NotBefore  string `json:"not_before"`
	NotAfter   string `json:"not_after"`
	DNSNames   []string `json:"dns_names,omitempty"`
	SelfSigned bool   `json:"self_signed"`
}

type NetstatEntry struct {
	Proto      string `json:"proto"`
	LocalAddr  string `json:"local_addr"`
	RemoteAddr string `json:"remote_addr"`
	State      string `json:"state"`
	PID        int    `json:"pid,omitempty"`
	Process    string `json:"process,omitempty"`
}

type SystemdUnitInfo struct {
	Name        string `json:"name"`
	Load        string `json:"load"`
	Active      string `json:"active"`
	Sub         string `json:"sub"`
	Description string `json:"description"`
}

type NFSMount struct {
	Server     string `json:"server"`
	Export     string `json:"export"`
	Mountpoint string `json:"mountpoint"`
	Options    string `json:"options"`
}

type ContainerHealthInfo struct {
	Status      string `json:"status"`
	FailingStreak int  `json:"failing_streak"`
	LastCheck   string `json:"last_check,omitempty"`
	LastOutput  string `json:"last_output,omitempty"`
}

type MDNSService struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Domain   string `json:"domain"`
	Hostname string `json:"hostname,omitempty"`
	Address  string `json:"address,omitempty"`
	Port     int    `json:"port,omitempty"`
}

type ZFSBookmark struct {
	Name      string `json:"name"`
	GUID      string `json:"guid"`
	CreateTxg string `json:"create_txg"`
}

type UptimeInfo struct {
	UptimeSec  int64   `json:"uptime_sec"`
	IdleSec    float64 `json:"idle_sec"`
	BootTime   string  `json:"boot_time"`
}

type NetIfaceMask struct {
	Name    string `json:"name"`
	Addr    string `json:"addr"`
	Netmask string `json:"netmask"`
	CIDR    int    `json:"cidr"`
}

type BatteryInfo struct {
	Present    bool    `json:"present"`
	Capacity   int     `json:"capacity_pct"`
	Status     string  `json:"status"`
	Technology string  `json:"technology,omitempty"`
}

type LocaleInfo struct {
	Lang     string `json:"lang"`
	LCAll    string `json:"lc_all,omitempty"`
	Timezone string `json:"timezone"`
	Charmap  string `json:"charmap,omitempty"`
}

type OSReleaseInfo struct {
	Name       string `json:"name"`
	Version    string `json:"version"`
	ID         string `json:"id"`
	IDLike     string `json:"id_like,omitempty"`
	PrettyName string `json:"pretty_name"`
	Codename   string `json:"codename,omitempty"`
	Kernel     string `json:"kernel"`
	Arch       string `json:"arch"`
}

type KernelModule struct {
	Name      string `json:"name"`
	SizeKB    int    `json:"size_kb"`
	UseCount  int    `json:"use_count"`
	UsedBy    string `json:"used_by,omitempty"`
}

type NICStatistics struct {
	Name     string            `json:"name"`
	Stats    map[string]int64  `json:"stats"`
}

type SystemdUnitDetail struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	LoadState   string `json:"load_state"`
	ActiveState string `json:"active_state"`
	SubState    string `json:"sub_state"`
	UnitFile    string `json:"unit_file_state,omitempty"`
	MainPID     int    `json:"main_pid,omitempty"`
	MemoryMB    int64  `json:"memory_mb,omitempty"`
	CPUSec      int64  `json:"cpu_sec,omitempty"`
}

type HostHardwareInfo struct {
	Vendor       string `json:"vendor"`
	Product      string `json:"product"`
	Serial       string `json:"serial,omitempty"`
	Family       string `json:"family,omitempty"`
	BoardVendor  string `json:"board_vendor,omitempty"`
	BoardProduct string `json:"board_product,omitempty"`
	BIOSVersion  string `json:"bios_version,omitempty"`
	BIOSDate     string `json:"bios_date,omitempty"`
}

type ZFSFeature struct {
	Name        string `json:"name"`
	State       string `json:"state"`
	Description string `json:"description,omitempty"`
}

type CPUDetail struct {
	Model       string  `json:"model"`
	Cores       int     `json:"cores"`
	Threads     int     `json:"threads"`
	MHz         float64 `json:"mhz"`
	CacheKB     int     `json:"cache_kb"`
	Flags       string  `json:"flags,omitempty"`
	Vendor      string  `json:"vendor"`
	Family      string  `json:"family"`
	StepingRev  string  `json:"stepping,omitempty"`
}

type MountInfo struct {
	Device     string `json:"device"`
	Mountpoint string `json:"mountpoint"`
	FSType     string `json:"fstype"`
	Options    string `json:"options"`
}

type ConntrackEntry struct {
	Proto      string `json:"proto"`
	SrcIP      string `json:"src_ip"`
	DstIP      string `json:"dst_ip"`
	SrcPort    int    `json:"src_port,omitempty"`
	DstPort    int    `json:"dst_port,omitempty"`
	State      string `json:"state,omitempty"`
}

type NetSpeedResult struct {
	Server     string  `json:"server"`
	DownloadMB float64 `json:"download_mb"`
	UploadMB   float64 `json:"upload_mb"`
	PingMS     float64 `json:"ping_ms"`
	DurationS  float64 `json:"duration_s"`
}

type DiskTemp struct {
	Device  string `json:"device"`
	Model   string `json:"model,omitempty"`
	TempC   int    `json:"temp_c"`
	State   string `json:"state,omitempty"`
}

type SystemBuildInfo struct {
	Hostname  string `json:"hostname"`
	OSVersion string `json:"os_version"`
	Arch      string `json:"arch"`
	NumCPU    int    `json:"num_cpu"`
	GoVersion string `json:"go_version,omitempty"`
}

type VMInfo struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	State  string `json:"state"`
	Memory int64  `json:"memory_kb"`
}

type SystemRecommendation struct {
	Category    string `json:"category"`
	Severity    string `json:"severity"`
	Message     string `json:"message"`
	Action      string `json:"action,omitempty"`
}

type InterfaceFeature struct {
	Name     string `json:"name"`
	Driver   string `json:"driver"`
	Speed    string `json:"speed,omitempty"`
	Duplex   string `json:"duplex,omitempty"`
	LinkUp   bool   `json:"link_up"`
}

type OpenPort struct {
	Proto    string `json:"proto"`
	Port     int    `json:"port"`
	Addr     string `json:"addr"`
	Process  string `json:"process,omitempty"`
	PID      int    `json:"pid,omitempty"`
}

type OOMEvent struct {
	When    string `json:"when"`
	Process string `json:"process"`
	PID     int    `json:"pid"`
	Score   int    `json:"score,omitempty"`
}

type ZRAMDevice struct {
	Name        string `json:"name"`
	SizeKB      int64  `json:"size_kb"`
	UsedKB      int64  `json:"used_kb"`
	Algorithm   string `json:"algorithm"`
	CompressionRatio float64 `json:"compression_ratio,omitempty"`
}

type TimeSyncStatus struct {
	Synchronized bool   `json:"synchronized"`
	Server       string `json:"server,omitempty"`
	PollInterval string `json:"poll_interval,omitempty"`
	LastSync     string `json:"last_sync,omitempty"`
	Offset       string `json:"offset,omitempty"`
}

type IPv6Status struct {
	Enabled    bool     `json:"enabled"`
	Addresses  []string `json:"addresses,omitempty"`
}

type ScrubProgress struct {
	Pool         string  `json:"pool"`
	State        string  `json:"state"`
	Progress     float64 `json:"progress_pct"`
	Speed        string  `json:"speed,omitempty"`
	ETA          string  `json:"eta,omitempty"`
	ErrorsFound  int     `json:"errors_found"`
}

type LoginEvent struct {
	User      string `json:"user"`
	TTY       string `json:"tty,omitempty"`
	From      string `json:"from,omitempty"`
	Login     string `json:"login"`
	Duration  string `json:"duration,omitempty"`
}

type BootRecord struct {
	Index    int    `json:"index"`
	BootID   string `json:"boot_id"`
	First    string `json:"first"`
	Last     string `json:"last"`
}

type SMARTAttribute struct {
	ID         int    `json:"id"`
	Name       string `json:"name"`
	Value      int    `json:"value"`
	Worst      int    `json:"worst"`
	Threshold  int    `json:"threshold"`
	WhenFailed string `json:"when_failed,omitempty"`
	Raw        int64  `json:"raw"`
}

type DedupStats struct {
	Pool         string  `json:"pool"`
	Ratio        float64 `json:"ratio"`
	Allocated    int64   `json:"allocated"`
	Referenced   int64   `json:"referenced"`
	Enabled      bool    `json:"enabled"`
}

type NVMeInfo struct {
	Device           string  `json:"device"`
	Temperature      int     `json:"temperature_c"`
	AvailableSpare   int     `json:"available_spare_pct"`
	PercentageUsed   int     `json:"percentage_used"`
	PowerOnHours     int64   `json:"power_on_hours"`
	UnsafeShutdowns  int64   `json:"unsafe_shutdowns"`
	MediaErrors      int64   `json:"media_errors"`
	NumErrLogEntries int64   `json:"num_err_log_entries"`
}

type GPUInfo struct {
	Index       int    `json:"index"`
	Name        string `json:"name"`
	Driver      string `json:"driver,omitempty"`
	MemoryMB    int    `json:"memory_mb,omitempty"`
	Temperature int    `json:"temperature_c,omitempty"`
	UtilPct     int    `json:"util_pct,omitempty"`
}

type ECCEvent struct {
	When    string `json:"when"`
	Type    string `json:"type"`
	Address string `json:"address,omitempty"`
	Count   int    `json:"count"`
}

type MemFragInfo struct {
	OrderFragmentation map[string]float64 `json:"order_fragmentation"`
	HighOrderUnusable  bool               `json:"high_order_unusable"`
}

type BandwidthIP struct {
	IP         string `json:"ip"`
	BytesIn    int64  `json:"bytes_in"`
	BytesOut   int64  `json:"bytes_out"`
	Connections int   `json:"connections"`
}

type PressureInfo struct {
	Some10s  float64 `json:"some_10s"`
	Some60s  float64 `json:"some_60s"`
	Some300s float64 `json:"some_300s"`
	Full10s  float64 `json:"full_10s,omitempty"`
}

// ── Backup types (M301-M315) ────────────────────────────────────────────────

type BorgRepo struct {
	Name         string `json:"name"`
	Path         string `json:"path"`
	Encryption   string `json:"encryption"`
	TotalSize    int64  `json:"total_size"`
	TotalChunks  int64  `json:"total_chunks"`
	UniqueChunks int64  `json:"unique_chunks"`
	LastModified int64  `json:"last_modified"`
	Comment      string `json:"comment,omitempty"`
}

type BorgArchive struct {
	Name         string `json:"name"`
	ID           string `json:"id"`
	Time         string `json:"time"`
	Duration     int64  `json:"duration_sec"`
	Size         int64  `json:"size"`
	CompressedSize int64 `json:"compressed_size"`
	FileCount    int64  `json:"file_count"`
}

type ResticRepo struct {
	Name         string `json:"name"`
	Path         string `json:"path"`
	Backend      string `json:"backend,omitempty"` // "", "s3", "b2", "azure", "gs", "swift", "rest"
	TotalSize    int64  `json:"total_size"`
	IndexedSize  int64  `json:"indexed_size"`
	BlobSize     int64  `json:"blob_size"`
	LastModified int64  `json:"last_modified"`
}

type ResticSnapshot struct {
	ID        string `json:"id"`
	Time      string `json:"time"`
	Hostname  string `json:"hostname"`
	Paths     []string `json:"paths"`
	Size      int64  `json:"size"`
	FileCount int64  `json:"file_count"`
	Tags      []string `json:"tags,omitempty"`
}

type RcloneRemote struct {
	Name       string `json:"name"`
	Type       string `json:"type"`
	Endpoint   string `json:"endpoint,omitempty"`
	Provider   string `json:"provider,omitempty"`
	Bandwidth  string `json:"bandwidth,omitempty"`
	Connected  bool   `json:"connected"`
	SourcePath string `json:"source_path,omitempty"`
	DestPath   string `json:"dest_path,omitempty"`
}

type BackupJob struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Type        string   `json:"type"` // borg, restic, rclone-sync, rclone-bisync
	Schedule    string   `json:"schedule"` // cron expression
	Enabled     bool     `json:"enabled"`
	Source      string   `json:"source"`
	Destination string   `json:"destination"`
	Excludes    []string `json:"excludes,omitempty"`
	LastRun     int64    `json:"last_run,omitempty"`
	LastResult  string   `json:"last_result,omitempty"` // ok, failed, skipped
	LastSize    int64    `json:"last_size,omitempty"`
	NextRun     int64    `json:"next_run,omitempty"`
	KeepHourly  int      `json:"keep_hourly,omitempty"`
	KeepDaily   int      `json:"keep_daily,omitempty"`
	KeepWeekly  int      `json:"keep_weekly,omitempty"`
	KeepMonthly int      `json:"keep_monthly,omitempty"`
	KeepYearly  int      `json:"keep_yearly,omitempty"`
}

type BackupJobRun struct {
	ID        string `json:"id"` // nanosecond timestamp, sort-safe as filename
	JobID     string `json:"job_id"`
	Result    string `json:"result"` // ok, failed
	Size      int64  `json:"size"`
	LogSize   int64  `json:"log_size"`
	Timestamp int64  `json:"timestamp"` // UnixNano
}

type RestorePoint struct {
	ID         string `json:"id"`
	BackupType string `json:"backup_type"` // borg, restic, rclone
	Repo       string `json:"repo"`
	Archive    string `json:"archive"`
	Time       string `json:"time"`
	Size       int64  `json:"size"`
	FileCount  int64  `json:"file_count"`
}

type CloudCostEstimate struct {
	Provider  string  `json:"provider"`
	SizeGB    float64 `json:"size_gb"`
	PricePerGB float64 `json:"price_per_gb"`
	Monthly   float64 `json:"monthly_usd"`
	Yearly    float64 `json:"yearly_usd"`
}

type BackupVerification struct {
	OK           bool   `json:"ok"`
	ArchiveID    string `json:"archive_id,omitempty"`
	FilesChecked int64  `json:"files_checked"`
	Errors       int64  `json:"errors"`
	Message      string `json:"message,omitempty"`
}

type SyslogConfig struct {
	Enabled    bool   `json:"enabled"`
	RemoteHost string `json:"remote_host"`
	RemotePort int    `json:"remote_port"`
	Protocol   string `json:"protocol"` // udp, tcp, tls
}

type AuditRetention struct {
	MaxAgeDays int `json:"max_age_days"`
	MaxSizeMB  int `json:"max_size_mb"`
}

type AuditLogQuery struct {
	User     string `json:"user,omitempty"`
	Action   string `json:"action,omitempty"`
	IP       string `json:"ip,omitempty"`
	Since    string `json:"since,omitempty"`
	Until    string `json:"until,omitempty"`
	Limit    int    `json:"limit"`
}

type AuditLogEntry struct {
	Time    string `json:"time"`
	User    string `json:"user"`
	Action  string `json:"action"`
	IP      string `json:"ip"`
	Result  string `json:"result"`
	Details string `json:"details,omitempty"`
}

type ServiceLogSummary struct {
	Service    string `json:"service"`
	ErrorCount int    `json:"error_count"`
	WarnCount  int    `json:"warn_count"`
	InfoCount  int    `json:"info_count"`
	LastSeen   string `json:"last_seen"`
}

type ContainerLogQuery struct {
	Container string `json:"container,omitempty"`
	Search    string `json:"search,omitempty"`
	Since     string `json:"since,omitempty"`
	Limit     int    `json:"limit"`
}

type ContainerLogEntry struct {
	Time      string `json:"time"`
	Container string `json:"container"`
	Message   string `json:"message"`
	Level     string `json:"level"` // info, warn, error
}

type LogAlertRule struct {
	Name        string `json:"name"`
	Pattern     string `json:"pattern"` // regex to match
	Service     string `json:"service"` // journal unit or "container:<name>"
	Threshold   int    `json:"threshold"` // count per window
	WindowMins  int    `json:"window_minutes"`
	Severity    string `json:"severity"` // warn, crit
	Channel     string `json:"channel"`
	Enabled     bool   `json:"enabled"`
	LastTrigger string `json:"last_trigger,omitempty"`
	Alerted     bool   `json:"alerted"`
}

type LogStats struct {
	Service      string  `json:"service"`
	LinesPerSec  float64 `json:"lines_per_sec"`
	ErrorsPerMin int     `json:"errors_per_min"`
	Sparkline    []int   `json:"sparkline"` // last 30 data points
}

type ContainerRestartEvent struct {
	Container   string `json:"container"`
	Restarts    int    `json:"restarts"`
	WindowMins  int    `json:"window_minutes"`
	Alerted     bool   `json:"alerted"`
	LastRestart string `json:"last_restart,omitempty"`
}

type LokiConfig struct {
	Enabled         bool   `json:"enabled"`
	URL             string `json:"url"` // e.g. https://logs-prod-us-central1.grafana.net
	User            string `json:"user,omitempty"`
	Password        string `json:"password,omitempty"`
	TenantID        string `json:"tenant_id,omitempty"`
	PushIntervalSec int    `json:"push_interval_seconds"`
	Labels          string `json:"labels,omitempty"` // extra labels json
}

type CVEReport struct {
	Image      string     `json:"image"`
	ScannedAt  int64      `json:"scanned_at"`
	Vulnerabilities []CVEEntry `json:"vulnerabilities"`
	Summary    CVESummary `json:"summary"`
}

type CVEEntry struct {
	ID          string `json:"id"`
	Severity    string `json:"severity"` // LOW, MEDIUM, HIGH, CRITICAL
	Title       string `json:"title"`
	Description string `json:"description"`
	Package     string `json:"package"`
	Installed   string `json:"installed_version"`
	Fixed       string `json:"fixed_version,omitempty"`
}

type CVESummary struct {
	Total   int `json:"total"`
	Low     int `json:"low"`
	Medium  int `json:"medium"`
	High    int `json:"high"`
	Critical int `json:"critical"`
}

type LynisStatus struct {
	Running   bool   `json:"running"`
	StartedAt string `json:"started_at,omitempty"`
	PID       int    `json:"pid,omitempty"`
	Progress  string `json:"progress,omitempty"`
	ReportID  string `json:"report_id,omitempty"`
	Error     string `json:"error,omitempty"`
}

type LynisFinding struct {
	ID       string `json:"id"`
	Severity string `json:"severity"` // warning, suggestion, security
	Category string `json:"category"`
	Title    string `json:"title"`
	Description string `json:"description,omitempty"`
	Solution string `json:"solution,omitempty"`
}

type AppArmorProfile struct {
	Name    string `json:"name"`
	Mode    string `json:"mode"` // enforce, complain, unconfined
	Status  string `json:"status"`
}

type SELinuxInfo struct {
	Enabled  bool   `json:"enabled"`
	Mode     string `json:"mode"` // enforcing, permissive, disabled
	Policy   string `json:"policy,omitempty"`
}

type USBAllowlistEntry struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	VendorID string `json:"vendor_id"`
	ProductID string `json:"product_id"`
	Allowed  bool   `json:"allowed"`
}

type SSHKeyAuditEntry struct {
	Fingerprint string `json:"fingerprint"`
	KeyType     string `json:"key_type"`
	Comment     string `json:"comment"`
	Used        bool   `json:"used"`
	LastUsed    string `json:"last_used,omitempty"`
}

type SudoEvent struct {
	Time    string `json:"time"`
	User    string `json:"user"`
	TTY     string `json:"tty"`
	Command string `json:"command"`
	RunAs   string `json:"run_as"`
}

type FailedLogin struct {
	Time    string `json:"time"`
	User    string `json:"user"`
	IP      string `json:"ip"`
	Count   int    `json:"count"`
}

type ComplianceReport struct {
	GeneratedAt string             `json:"generated_at"`
	Format      string             `json:"format"`
	Checks      []ComplianceCheck   `json:"checks"`
	Score       int                `json:"score"`
}

type ComplianceCheck struct {
	ID       string `json:"id"`
	Severity string `json:"severity"` // HIGH, MEDIUM, LOW, INFO
	Title    string `json:"title"`
	Status   string `json:"status"` // PASS, FAIL, WARN, N/A
	Details  string `json:"details,omitempty"`
}

type PrivacyConfig struct {
	Enabled      bool `json:"enabled"`
	AnonymizeLogs bool `json:"anonymize_logs"`
	DisableTelemetry bool `json:"disable_telemetry"`
}

type IntegrityFinding struct {
	Path       string `json:"path"`
	Status     string `json:"status"` // OK, MODIFIED, MISSING, UNEXPECTED
	Expected   string `json:"expected,omitempty"`
	Actual     string `json:"actual,omitempty"`
}

type BtrfsSubvol struct {
	Path     string `json:"path"`
	UUID     string `json:"uuid"`
	ParentID int64  `json:"parent_id"`
}

type BtrfsSnapshot struct {
	Path      string `json:"path"`
	Source    string `json:"source"`
	Created   int64  `json:"created"`
	ReadOnly  bool   `json:"readonly"`
}

type L2ARCDevice struct {
	Pool       string `json:"pool"`
	Device     string `json:"device"`
	Size       uint64 `json:"size"`
	Allocated  uint64 `json:"allocated"`
	Free       uint64 `json:"free"`
}

type SLOGDevice struct {
	Pool       string `json:"pool"`
	Device     string `json:"device"`
	Size       uint64 `json:"size"`
	Allocated  uint64 `json:"allocated"`
	Free       uint64 `json:"free"`
}

type SpecialVdev struct {
	Pool     string `json:"pool"`
	Device   string `json:"device"`
	Class    string `json:"class"` // metadata, special
	Size     uint64 `json:"size"`
}

type DDTProjection struct {
	Pool       string  `json:"pool"`
	DDTEnabled bool    `json:"ddt_enabled"`
	DDTEntries uint64  `json:"ddt_entries"`
	DDTSize    uint64  `json:"ddt_size_bytes"`
	EstMemMB   float64 `json:"estimated_memory_mb"`
	Status     string  `json:"status"` // computing, ready, error
}

type CompressionRatio struct {
	Dataset     string  `json:"dataset"`
	Compression string  `json:"compression"`
	UsedBytes   uint64  `json:"used_bytes"`
	LogicalUsed uint64  `json:"logical_used_bytes"`
	Ratio       float64 `json:"ratio"`
}

type LifecyclePolicy struct {
	Name        string   `json:"name"`
	Dataset     string   `json:"dataset"`
	Frequency   string   `json:"frequency"` // daily, weekly, monthly
	KeepRecent  int      `json:"keep_recent"`
	KeepHourly  int      `json:"keep_hourly"`
	KeepDaily   int      `json:"keep_daily"`
	KeepWeekly  int      `json:"keep_weekly"`
	KeepMonthly int      `json:"keep_monthly"`
	KeepYearly  int      `json:"keep_yearly"`
	Enabled     bool     `json:"enabled"`
	LastRun     int64    `json:"last_run,omitempty"`
	NextRun     int64    `json:"next_run,omitempty"`
}

type TierPolicy struct {
	Enabled     bool         `json:"enabled"`
	SourcePool string       `json:"source_pool"`
	TargetPool string       `json:"target_pool"`
	AgeDays    int          `json:"age_days"`
	Datasets   []string     `json:"datasets"`
}

type DedupScanResult struct {
	Status      string `json:"status"` // idle, running, complete, error
	StartedAt   int64  `json:"started_at,omitempty"`
	CompletedAt int64  `json:"completed_at,omitempty"`
	GroupsFound int    `json:"groups_found"`
	SpaceSaved  uint64 `json:"space_saved_bytes"`
	ScannedBytes uint64 `json:"scanned_bytes"`
	Error       string `json:"error,omitempty"`
}

type BurnInStatus struct {
	Disk       string `json:"disk"`
	Status     string `json:"status"` // idle, running, passed, failed
	StartedAt  int64  `json:"started_at,omitempty"`
	CompletedAt int64  `json:"completed_at,omitempty"`
	CurrentBlock int64 `json:"current_block"`
	TotalBlocks  int64 `json:"total_blocks"`
	PercentDone  int   `json:"percent_done"`
	Error       string `json:"error,omitempty"`
}

type ReplacementWizardState struct {
	ID         string `json:"id"`
	Step       string `json:"step"` // identify, confirm_offline, insert, resilver, confirm
	Disk       string `json:"disk"`
	Pool       string `json:"pool"`
	Vdev       string `json:"vdev"`
	NewDevice  string `json:"new_device"`
	Progress   int    `json:"progress"`
	Message    string `json:"message"`
}

type PoolExpansionState struct {
	ID         string `json:"id"`
	Step       string `json:"step"` // select_pool, confirm_vdev, add_device, verify, complete
	Pool       string `json:"pool"`
	VdevType   string `json:"vdev_type"` // stripe, mirror, raidz1, raidz2, raidz3
	Devices    []string `json:"devices"`
	Progress   int    `json:"progress"`
	Message    string `json:"message"`
}

type FileNode struct {
	Name      string    `json:"name"`
	Path      string    `json:"path"`
	Type      string    `json:"type"` // file, dir, symlink
	Size      int64     `json:"size"`
	Mode      string    `json:"mode"`
	Uid       int       `json:"uid"`
	Gid       int       `json:"gid"`
	Modified  int64     `json:"modified"`
	Target    string    `json:"target,omitempty"` // symlink target
	Children  []FileNode `json:"children,omitempty"`
}

type FilePreview struct {
	Kind      string `json:"kind"` // text, image, pdf, binary
	Content   string `json:"content,omitempty"` // base64 for image, text content, or "" for binary
	MimeType string `json:"mime_type"`
}

type ShareLinkOptions struct {
	ExpiresIn  int    `json:"expires_in"`  // seconds from now, 0 = never
	MaxUses   int    `json:"max_uses"`     // 0 = unlimited
}

type ShareLink struct {
	ID         string `json:"id"`
	Token     string `json:"token"`
	Path      string `json:"path"`
	CreatedBy string `json:"created_by"`
	CreatedAt int64  `json:"created_at"`
	ExpiresAt int64  `json:"expires_at"`
	MaxUses   int    `json:"max_uses"`
	Used      int    `json:"used"`
}

type BulkMoveOp struct {
	Src  string `json:"src"`
	Dst  string `json:"dst"`
}
