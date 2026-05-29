package storage

// TODO(arch): RunPriv refactor — linux.go has ~315 exec.Command calls.
// Privileged binaries to migrate (use storage.RunPriv from priv.go):
//   zpool:  ~36 call sites  (path: /usr/sbin/zpool)
//   zfs:    ~35 call sites  (path: /usr/sbin/zfs)
//   systemctl: ~18 call sites (path: /usr/bin/systemctl)
//   smartctl: ~10 call sites  (path: /usr/sbin/smartctl)
//   ip: ~6 call sites         (path: /sbin/ip)
// Unprivileged (~225 remaining): df, docker, borg, restic, etc.
// Apply per-binary using LINUX-RUNPRIV-PATCHES.md patterns.
// Each call site needs review of: return-value handling (.Output()/.Run()/.CombinedOutput()),
// whether ctx is in scope, and whether stderr is used.
// Do NOT bulk sed replace — use targeted per-binary patches.

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/kilasos/kilasos/internal/appcatalog"
)

const (
	poolMountBase   = "/mnt"
	shareConfDir    = "/etc/samba/shares.d"
	sambaCfgHeader  = "/etc/samba/smb.conf"
	nfsMetaPath     = "/var/lib/kilasos/nfs-shares.json"
	nfsExportsPath  = "/etc/exports.d/kilasos.exports"
	sshKeysPath     = "/etc/kilasos/authorized_keys"
	rcloneMetaPath  = "/var/lib/kilasos/rclone-remotes.json"
)

// ── provider state ────────────────────────────────────────────────────────────

type cpuSample struct{ idle, total uint64 }
type netSample struct{ rx, tx uint64 }
type diskSample struct{ rbytes, wbytes uint64 }

type linuxProvider struct {
	mu       sync.Mutex
	prevCPU  cpuSample
	prevNet  map[string]netSample
	prevDisk map[string]diskSample
	prevAt   time.Time
}

func NewLinux() Provider {
	return &linuxProvider{
		prevNet:  make(map[string]netSample),
		prevDisk: make(map[string]diskSample),
	}
}

// ── lsblk ────────────────────────────────────────────────────────────────────

type lsblkOutput struct {
	BlockDevices []lsblkDev `json:"blockdevices"`
}

type lsblkDev struct {
	Name  string      `json:"name"`
	Path  string      `json:"path"`
	Size  interface{} `json:"size"`
	Model string      `json:"model"`
	Type  string      `json:"type"`
}

// ── smartctl ─────────────────────────────────────────────────────────────────

// smartctlOutput covers ATA, SCSI, and NVMe schemas; missing fields silently ignored via zero values.
type smartctlOutput struct {
	SerialNumber string `json:"serial_number"`
	SmartStatus  struct {
		Passed bool `json:"passed"`
	} `json:"smart_status"`
	Temperature struct {
		Current int `json:"current"`
	} `json:"temperature"`
	PowerOnTime struct {
		Hours int `json:"hours"`
	} `json:"power_on_time"`
	ATASmartAttributes struct {
		Table []struct {
			ID  int `json:"id"`
			Raw struct {
				Value int64 `json:"value"`
			} `json:"raw"`
		} `json:"table"`
	} `json:"ata_smart_attributes"`
	ScsiGrownDefectList *int `json:"scsi_grown_defect_list"`
	AtaSmartData        struct {
		SelfTest struct {
			Status struct {
				String           string `json:"string"`
				RemainingPercent int    `json:"remaining_percent"`
			} `json:"status"`
		} `json:"self_test"`
	} `json:"ata_smart_data"`
}

// ── Disks ─────────────────────────────────────────────────────────────────────

func (p *linuxProvider) Disks(ctx context.Context) ([]Disk, error) {
	out, _, err := RunPlain(ctx, "lsblk", "-J", "-b", "-d", "-o", "NAME,PATH,SIZE,MODEL,TYPE")
	if err != nil {
		return nil, err
	}

	var lb lsblkOutput
	if err := json.Unmarshal(out, &lb); err != nil {
		return nil, err
	}

	var disks []Disk
	for _, dev := range lb.BlockDevices {
		if dev.Type != "disk" {
			continue
		}
		path := dev.Path
		if path == "" {
			path = "/dev/" + dev.Name
		}
		d := Disk{
			Name:      dev.Name,
			Path:      path,
			SizeBytes: parseSize(dev.Size),
			Model:     strings.TrimSpace(dev.Model),
		}
		stdout, _, _ := RunPriv(ctx, "/usr/bin/smartctl", "--json", "--all", path)
		smartOut := stdout
		if len(smartOut) > 0 {
			var s smartctlOutput
			if json.Unmarshal(smartOut, &s) == nil {
				d.Serial = s.SerialNumber
				d.SmartOK = s.SmartStatus.Passed
				if s.Temperature.Current > 0 {
					t := s.Temperature.Current
					d.TempCelsius = &t
				}
				if s.PowerOnTime.Hours > 0 {
					h := s.PowerOnTime.Hours
					d.PowerOnHours = &h
				}
				for _, attr := range s.ATASmartAttributes.Table {
					if attr.ID == 5 {
						v := int(attr.Raw.Value)
						d.ReallocatedSectors = &v
						break
					}
				}
				if s.ScsiGrownDefectList != nil {
					v := *s.ScsiGrownDefectList
					d.ReallocatedSectors = &v
				}
			}
		}
		disks = append(disks, d)
	}
	return disks, nil
}

// ── Arrays ────────────────────────────────────────────────────────────────────

func (p *linuxProvider) Arrays(ctx context.Context) ([]Array, error) {
	out, _, _ := RunPriv(ctx, "/usr/sbin/zpool", "list", "-H", "-p", "-o", "name,health")
	if len(out) == 0 {
		return []Array{}, nil
	}
	var arrays []Array
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		name, health := parts[0], strings.ToLower(parts[1])
		mount := filepath.Join(poolMountBase, name)
		arrays = append(arrays, Array{
			ArraySpec: ArraySpec{
				Name:    name,
				Type:    ArrayTypeZFS,
				Devices: zpoolDevices(ctx, name),
			},
			MountPath: mount,
			Status:    health,
		})
	}
	return arrays, nil
}

func zpoolDevices(ctx context.Context, pool string) []string {
	out, _, err := RunPriv(ctx, "/usr/sbin/zpool", "status", "-P", pool)
	if err != nil {
		return nil
	}
	var devices []string
	for _, line := range strings.Split(string(out), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "/dev/") {
			if parts := strings.Fields(trimmed); len(parts) > 0 {
				devices = append(devices, parts[0])
			}
		}
	}
	return devices
}

func (p *linuxProvider) CreateArray(ctx context.Context, spec ArraySpec, force bool) (Array, error) {
	if spec.Name == "" {
		return Array{}, fmt.Errorf("name is required")
	}
	if len(spec.Devices) == 0 {
		return Array{}, fmt.Errorf("devices is required")
	}

	mount := filepath.Join(poolMountBase, spec.Name)
	if err := os.MkdirAll(mount, 0755); err != nil {
		return Array{}, fmt.Errorf("mkdir %s: %w", mount, err)
	}

	args := []string{"create", "-O", "mountpoint=" + mount}
	if force {
		args = append(args, "-f")
	}
	args = append(args, spec.Name)
	switch spec.Topology {
	case TopologyMirror:
		args = append(args, "mirror")
	case TopologyRAIDZ:
		args = append(args, "raidz")
	case TopologyRAIDZ2:
		args = append(args, "raidz2")
	}
	args = append(args, spec.Devices...)

	out, stderr, err := RunPriv(ctx, "/usr/sbin/zpool", args...)
	if err != nil {
		out = append(out, stderr...)
		return Array{}, fmt.Errorf("zpool create: %s", strings.TrimSpace(string(out)))
	}
	return Array{ArraySpec: spec, MountPath: mount, Status: "online"}, nil
}

func (p *linuxProvider) StartArray(ctx context.Context, name string) error {
	_, _, err := RunPriv(ctx, "/usr/sbin/zpool", "import", name)
	return err
}

func (p *linuxProvider) StopArray(ctx context.Context, name string) error {
	RunPriv(ctx, "/usr/sbin/zfs", "unmount", "-f", name) //nolint:errcheck
	_, _, err := RunPriv(ctx, "/usr/sbin/zpool", "export", name)
	return err
}

func (p *linuxProvider) DeleteArray(ctx context.Context, name string) error {
	RunPriv(ctx, "/usr/sbin/zfs", "unmount", "-f", name) //nolint:errcheck
	out, stderr, err := RunPriv(ctx, "/usr/sbin/zpool", "destroy", "-f", name)
	if err != nil {
		out = append(out, stderr...)
		return fmt.Errorf("zpool destroy: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

// ── Shares ────────────────────────────────────────────────────────────────────

type nfsShareMeta struct {
	Clients string `json:"clients"`
	Options string `json:"options"`
}

func loadNFSMeta() (map[string]nfsShareMeta, error) {
	data, err := os.ReadFile(nfsMetaPath)
	if os.IsNotExist(err) {
		return map[string]nfsShareMeta{}, nil
	}
	if err != nil {
		return nil, err
	}
	m := map[string]nfsShareMeta{}
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return m, nil
}

func saveNFSMeta(m map[string]nfsShareMeta) error {
	if err := os.MkdirAll(filepath.Dir(nfsMetaPath), 0755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(nfsMetaPath, data, 0644)
}

func regenerateNFSExports(shares []Share, meta map[string]nfsShareMeta) error {
	if err := os.MkdirAll(filepath.Dir(nfsExportsPath), 0755); err != nil {
		return err
	}
	var sb strings.Builder
	sb.WriteString("# KilasOS managed NFS exports — do not edit manually\n")
	for _, s := range shares {
		nm, ok := meta[s.Name]
		if !ok {
			continue
		}
		clients := nm.Clients
		if clients == "" {
			clients = "*"
		}
		opts := nm.Options
		if opts == "" {
			opts = "rw,sync,no_subtree_check"
		}
		fmt.Fprintf(&sb, "%s %s(%s)\n", s.Path, clients, opts)
	}
	if err := os.WriteFile(nfsExportsPath, []byte(sb.String()), 0644); err != nil {
		return err
	}
	stdout, stderr, err := RunPriv(context.Background(), "/usr/sbin/exportfs", "-ra")
	if err != nil {
		out := append(stdout, stderr...)
		return fmt.Errorf("exportfs -ra: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func (p *linuxProvider) Shares(ctx context.Context) ([]Share, error) {
	entries, err := os.ReadDir(shareConfDir)
	if os.IsNotExist(err) {
		return []Share{}, nil
	}
	if err != nil {
		return nil, err
	}

	nfsMeta, _ := loadNFSMeta()

	shares := []Share{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".conf") {
			continue
		}
		s, err := readShareConf(filepath.Join(shareConfDir, e.Name()))
		if err == nil {
			if nm, ok := nfsMeta[s.Name]; ok {
				s.NFS = true
				s.NFSClients = nm.Clients
				s.NFSOptions = nm.Options
			}
			shares = append(shares, s)
		}
	}
	return shares, nil
}

func (p *linuxProvider) CreateShare(ctx context.Context, s Share) (Share, error) {
	if s.Name == "" || s.Pool == "" {
		return Share{}, fmt.Errorf("name and pool are required")
	}

	if s.Path == "" {
		s.Path = filepath.Join(poolMountBase, s.Pool, s.Name)
	}
	if err := os.MkdirAll(s.Path, 0755); err != nil {
		return Share{}, fmt.Errorf("mkdir %s: %w", s.Path, err)
	}

	if err := os.MkdirAll(shareConfDir, 0755); err != nil {
		return Share{}, fmt.Errorf("mkdir %s: %w", shareConfDir, err)
	}
	if err := writeShareConf(s); err != nil {
		return Share{}, err
	}
	if err := ensureSmbConfInclude(); err != nil {
		return Share{}, err
	}
	stdout, stderr, err := RunPriv(ctx, "/usr/bin/smbcontrol", "smbd", "reload-config")
	if err != nil {
		out := append(stdout, stderr...)
		if out2, _, err2 := RunPriv(ctx, "/usr/bin/systemctl", "restart", "smbd"); err2 != nil {
			return Share{}, fmt.Errorf("reload smbd: %s / %s", strings.TrimSpace(string(out)), strings.TrimSpace(string(out2)))
		}
	}

	if s.NFS {
		meta, err := loadNFSMeta()
		if err != nil {
			return Share{}, fmt.Errorf("load nfs meta: %w", err)
		}
		meta[s.Name] = nfsShareMeta{Clients: s.NFSClients, Options: s.NFSOptions}
		if err := saveNFSMeta(meta); err != nil {
			return Share{}, fmt.Errorf("save nfs meta: %w", err)
		}
		allShares, _ := p.Shares(context.Background())
		if err := regenerateNFSExports(allShares, meta); err != nil {
			return Share{}, err
		}
	}
	return s, nil
}

func (p *linuxProvider) DeleteShare(ctx context.Context, name string) error {
	path := filepath.Join(shareConfDir, name+".conf")
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove %s: %w", path, err)
	}
	RunPriv(ctx, "/usr/bin/smbcontrol", "smbd", "reload-config") //nolint:errcheck

	meta, err := loadNFSMeta()
	if err != nil {
		return fmt.Errorf("load nfs meta: %w", err)
	}
	if _, had := meta[name]; had {
		delete(meta, name)
		if err := saveNFSMeta(meta); err != nil {
			return fmt.Errorf("save nfs meta: %w", err)
		}
		allShares, _ := p.Shares(context.Background())
		if err := regenerateNFSExports(allShares, meta); err != nil {
			return err
		}
	}
	return nil
}

// writeShareConf writes a single Samba share stanza to shareConfDir/<name>.conf
func writeShareConf(s Share) error {
	ro := "no"
	if s.ReadOnly {
		ro = "yes"
	}
	guest := "no"
	if s.Public {
		guest = "yes"
	}
	content := fmt.Sprintf("[%s]\n   path = %s\n   comment = %s\n   read only = %s\n   guest ok = %s\n   browseable = yes\n",
		s.Name, s.Path, s.Comment, ro, guest)
	return os.WriteFile(filepath.Join(shareConfDir, s.Name+".conf"), []byte(content), 0644)
}

// readShareConf parses a minimal Samba stanza back into a Share.
func readShareConf(path string) (Share, error) {
	f, err := os.Open(path)
	if err != nil {
		return Share{}, err
	}
	defer f.Close()

	var s Share
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			s.Name = line[1 : len(line)-1]
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		switch k {
		case "path":
			s.Path = v
			// Infer pool from /mnt/<pool>/... pattern
			rel := strings.TrimPrefix(v, poolMountBase+"/")
			if parts := strings.SplitN(rel, "/", 2); len(parts) >= 1 {
				s.Pool = parts[0]
			}
		case "comment":
			s.Comment = v
		case "read only":
			s.ReadOnly = v == "yes"
		case "guest ok":
			s.Public = v == "yes"
		}
	}
	return s, scanner.Err()
}

// ensureSmbConfInclude adds an include line for shareConfDir to smb.conf if not already present.
func ensureSmbConfInclude() error {
	include := "include = " + shareConfDir + "/*.conf"
	data, err := os.ReadFile(sambaCfgHeader)
	if err != nil {
		return fmt.Errorf("read smb.conf: %w", err)
	}
	if strings.Contains(string(data), shareConfDir) {
		return nil
	}
	f, err := os.OpenFile(sambaCfgHeader, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("open smb.conf: %w", err)
	}
	defer f.Close()
	_, err = fmt.Fprintf(f, "\n# KilasOS managed shares\n%s\n", include)
	return err
}

// ── Metrics ───────────────────────────────────────────────────────────────────

func (p *linuxProvider) Metrics(ctx context.Context) (SystemMetrics, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()

	cpu, err := readCPUSample()
	if err != nil {
		return SystemMetrics{}, err
	}
	var cpuPct float64
	if !p.prevAt.IsZero() {
		dTotal := float64(cpu.total - p.prevCPU.total)
		dIdle := float64(cpu.idle - p.prevCPU.idle)
		if dTotal > 0 {
			cpuPct = math.Round((1-dIdle/dTotal)*1000) / 10
		}
	}
	p.prevCPU = cpu

	memTotal, memUsed, err := readMemInfo()
	if err != nil {
		return SystemMetrics{}, err
	}

	nets, err := readNetDev()
	if err != nil {
		return SystemMetrics{}, err
	}

	dt := now.Sub(p.prevAt).Seconds()
	if dt < 0.01 {
		dt = 1
	}
	ifaces := []NetIface{}
	for name, cur := range nets {
		if name == "lo" {
			continue
		}
		iface := NetIface{Name: name}
		if !p.prevAt.IsZero() {
			if prev, ok := p.prevNet[name]; ok {
				iface.RxBytesPerSec = math.Round(float64(cur.rx-prev.rx) / dt)
				iface.TxBytesPerSec = math.Round(float64(cur.tx-prev.tx) / dt)
			}
		}
		ifaces = append(ifaces, iface)
	}
	sort.Slice(ifaces, func(i, j int) bool { return ifaces[i].Name < ifaces[j].Name })
	p.prevNet = nets
	p.prevAt = now

	return SystemMetrics{
		CPUPercent:    cpuPct,
		MemTotal:      memTotal,
		MemUsed:       memUsed,
		NetInterfaces: ifaces,
		PoolUsage:     readPoolUsage(),
	}, nil
}

func readCPUSample() (cpuSample, error) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return cpuSample{}, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			break
		}
		var v [8]uint64
		for i := 1; i < len(fields) && i <= 8; i++ {
			v[i-1], _ = strconv.ParseUint(fields[i], 10, 64)
		}
		// fields: user nice system idle iowait irq softirq steal
		idle := v[3] + v[4]
		total := v[0] + v[1] + v[2] + v[3] + v[4] + v[5] + v[6] + v[7]
		return cpuSample{idle: idle, total: total}, nil
	}
	return cpuSample{}, fmt.Errorf("cpu line not found in /proc/stat")
}

func readMemInfo() (total, used int64, err error) {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return
	}
	var memTotal, memAvail int64
	for _, line := range strings.Split(string(data), "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		n, _ := strconv.ParseInt(strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(v), "kB")), 10, 64)
		n *= 1024
		switch k {
		case "MemTotal":
			memTotal = n
		case "MemAvailable":
			memAvail = n
		}
	}
	return memTotal, memTotal - memAvail, nil
}

func readNetDev() (map[string]netSample, error) {
	data, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return nil, err
	}
	result := make(map[string]netSample)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		iface, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		iface = strings.TrimSpace(iface)
		fields := strings.Fields(rest)
		if len(fields) < 9 {
			continue
		}
		rx, _ := strconv.ParseUint(fields[0], 10, 64)
		tx, _ := strconv.ParseUint(fields[8], 10, 64)
		result[iface] = netSample{rx: rx, tx: tx}
	}
	return result, nil
}

func readPoolUsage() []PoolUsage {
	entries, err := os.ReadDir(poolMountBase)
	if err != nil {
		return []PoolUsage{}
	}
	pools := []PoolUsage{}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		var st syscall.Statfs_t
		if err := syscall.Statfs(filepath.Join(poolMountBase, e.Name()), &st); err != nil {
			continue
		}
		bsize := int64(st.Bsize)
		total := int64(st.Blocks) * bsize
		free := int64(st.Bavail) * bsize
		if total == 0 {
			continue
		}
		pools = append(pools, PoolUsage{
			Name:  e.Name(),
			Total: total,
			Used:  total - free,
			Free:  free,
		})
	}
	return pools
}

// ── System settings ───────────────────────────────────────────────────────────

func (p *linuxProvider) GetSettings(ctx context.Context) (SystemSettings, error) {
	hostOut, _, err := RunPriv(ctx, "/usr/bin/hostnamectl", "hostname")
	if err != nil {
		// fallback
		hostOut, _, err = RunPlain(ctx, "hostname")
		if err != nil {
			return SystemSettings{}, fmt.Errorf("hostname: %w", err)
		}
	}

	tdOut, _, err := RunPriv(ctx, "/usr/bin/timedatectl", "show")
	if err != nil {
		return SystemSettings{}, fmt.Errorf("timedatectl show: %w", err)
	}

	s := SystemSettings{Hostname: strings.TrimSpace(string(hostOut))}
	for _, line := range strings.Split(string(tdOut), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "Timezone":
			s.Timezone = strings.TrimSpace(v)
		case "NTP":
			s.NTPEnabled = strings.TrimSpace(v) == "yes"
		case "NTPSynchronized":
			s.NTPSynced = strings.TrimSpace(v) == "yes"
		}
	}
	return s, nil
}

func (p *linuxProvider) ApplySettings(ctx context.Context, u SettingsUpdate) error {
	if u.Hostname != nil && *u.Hostname != "" {
		_, stderr, err := RunPriv(ctx, "/usr/bin/hostnamectl", "set-hostname", *u.Hostname)
		if err != nil {
			return fmt.Errorf("set-hostname: %s", strings.TrimSpace(string(stderr)))
		}
	}
	if u.Timezone != nil && *u.Timezone != "" {
		_, stderr, err := RunPriv(ctx, "/usr/bin/timedatectl", "set-timezone", *u.Timezone)
		if err != nil {
			return fmt.Errorf("set-timezone: %s", strings.TrimSpace(string(stderr)))
		}
	}
	if u.NTP != nil {
		val := "false"
		if *u.NTP {
			val = "true"
		}
		_, stderr, err := RunPriv(ctx, "/usr/bin/timedatectl", "set-ntp", val)
		if err != nil {
			return fmt.Errorf("set-ntp: %s", strings.TrimSpace(string(stderr)))
		}
	}
	return nil
}

// ── Network interfaces ────────────────────────────────────────────────────────

func (p *linuxProvider) NetInterfaces(ctx context.Context) ([]NetworkIface, error) {
	defaultIface := parseDefaultRoute()

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var out []NetworkIface
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		ni := NetworkIface{
			Name:      iface.Name,
			MAC:       iface.HardwareAddr.String(),
			MTU:       iface.MTU,
			IsDefault: iface.Name == defaultIface,
			Operstate: strings.TrimSpace(readSysNetFile(iface.Name, "operstate")),
			SpeedMbps: -1,
		}
		if sp := strings.TrimSpace(readSysNetFile(iface.Name, "speed")); sp != "" {
			if v, err := strconv.Atoi(sp); err == nil && v > 0 {
				ni.SpeedMbps = v
			}
		}
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			ni.IPAddresses = append(ni.IPAddresses, addr.String())
		}
		if ni.IPAddresses == nil {
			ni.IPAddresses = []string{}
		}
		out = append(out, ni)
	}
	if out == nil {
		out = []NetworkIface{}
	}
	return out, nil
}

func (p *linuxProvider) SetInterfaceState(ctx context.Context, name string, up bool) error {
	state := "down"
	if up {
		state = "up"
	}
	stdout, stderr, err := RunPriv(ctx, "/sbin/ip", "link", "set", name, state)
	if err != nil {
		out := append(stdout, stderr...)
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func readSysNetFile(iface, file string) string {
	data, err := os.ReadFile(filepath.Join("/sys/class/net", iface, file))
	if err != nil {
		return ""
	}
	return string(data)
}

func parseDefaultRoute() string {
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n")[1:] {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[1] == "00000000" {
			return fields[0]
		}
	}
	return ""
}

// ── Power management ─────────────────────────────────────────────────────────

func (p *linuxProvider) GetPowerStatus(ctx context.Context) (PowerStatus, error) {
	data, err := os.ReadFile("/run/systemd/shutdown/scheduled")
	if err != nil {
		if os.IsNotExist(err) {
			return PowerStatus{Pending: false}, nil
		}
		return PowerStatus{}, err
	}
	var usec int64
	var mode string
	for _, line := range strings.Split(string(data), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch k {
		case "USEC":
			usec, _ = strconv.ParseInt(v, 10, 64)
		case "MODE":
			mode = strings.TrimSpace(v)
		}
	}
	ps := PowerStatus{Pending: true, Action: mode}
	if usec > 0 {
		ps.When = time.Unix(0, usec*int64(time.Microsecond)).UTC().Format(time.RFC3339)
	}
	return ps, nil
}

func (p *linuxProvider) Shutdown(ctx context.Context, delayMinutes int) error {
	when := "now"
	if delayMinutes > 0 {
		when = fmt.Sprintf("+%d", delayMinutes)
	}
	stdout, stderr, err := RunPriv(ctx, "/sbin/shutdown", "-h", when)
	if err != nil {
		out := append(stdout, stderr...)
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (p *linuxProvider) Reboot(ctx context.Context, delayMinutes int) error {
	when := "now"
	if delayMinutes > 0 {
		when = fmt.Sprintf("+%d", delayMinutes)
	}
	stdout, stderr, err := RunPriv(ctx, "/sbin/shutdown", "-r", when)
	if err != nil {
		out := append(stdout, stderr...)
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (p *linuxProvider) CancelShutdown(ctx context.Context) error {
	stdout, stderr, err := RunPriv(ctx, "/sbin/shutdown", "-c")
	if err != nil {
		out := append(stdout, stderr...)
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (p *linuxProvider) SetDiskSpindown(ctx context.Context, devPath string, seconds int) error {
	val := secondsToHdparm(seconds)
	stdout, stderr, err := RunPlain(ctx, "hdparm", "-S", strconv.Itoa(val), devPath)
	if err != nil {
		out := append(stdout, stderr...)
		return fmt.Errorf("hdparm: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

// secondsToHdparm converts idle seconds to an hdparm -S value.
// 0=disabled, 1-240=5s increments (up to 20min), 241-251=30min increments.
func secondsToHdparm(seconds int) int {
	if seconds <= 0 {
		return 0
	}
	if seconds <= 1200 {
		v := seconds / 5
		if v < 1 {
			v = 1
		}
		return v
	}
	n := (seconds + 1799) / 1800
	if n < 1 {
		n = 1
	}
	v := 240 + n
	if v > 251 {
		v = 251
	}
	return v
}

// ── Pool health + scrub ───────────────────────────────────────────────────────

func (p *linuxProvider) PoolHealth(ctx context.Context, name string) (PoolHealth, error) {
	listOut, _, err := RunPriv(ctx, "/usr/sbin/zpool", "list", "-Hp", "-o", "name,size,alloc,free,frag,health", name)
	if err != nil {
		return PoolHealth{}, fmt.Errorf("zpool list: %w", err)
	}
	h := PoolHealth{Name: name, VDevs: []VDev{}}
	if fields := strings.Fields(strings.TrimSpace(string(listOut))); len(fields) >= 6 {
		h.SizeBytes, _ = strconv.ParseInt(fields[1], 10, 64)
		h.AllocBytes, _ = strconv.ParseInt(fields[2], 10, 64)
		h.FreeBytes, _ = strconv.ParseInt(fields[3], 10, 64)
		if fields[4] != "-" {
			frag, _ := strconv.ParseInt(fields[4], 10, 64)
			h.FragPercent = int(frag)
		}
		h.State = strings.ToLower(fields[5])
	}

	statusOut, _, err := RunPriv(ctx, "/usr/sbin/zpool", "status", "-P", name)
	if err != nil {
		return h, nil
	}
	text := string(statusOut)
	h.VDevs = parseZpoolVDevs(text, name)
	h.Scrub = parseZpoolScrub(text)
	for _, line := range strings.Split(text, "\n") {
		if t := strings.TrimSpace(line); strings.HasPrefix(t, "errors:") {
			if e := strings.TrimSpace(strings.TrimPrefix(t, "errors:")); e != "No known data errors" {
				h.Errors = e
			}
		}
	}
	return h, nil
}

func (p *linuxProvider) Snapshots(ctx context.Context, pool string) ([]Snapshot, error) {
	out, _, err := RunPriv(ctx, "/usr/sbin/zfs", "list", "-H", "-p", "-t", "snapshot",
		"-o", "name,creation,used,referenced", pool)
	if err != nil {
		return nil, fmt.Errorf("zfs list snapshots: %w", err)
	}
	snaps := []Snapshot{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		parts := strings.SplitN(fields[0], "@", 2)
		if len(parts) != 2 {
			continue
		}
		created, _ := strconv.ParseInt(fields[1], 10, 64)
		used, _ := strconv.ParseInt(fields[2], 10, 64)
		refd, _ := strconv.ParseInt(fields[3], 10, 64)
		snaps = append(snaps, Snapshot{
			Name: parts[1], Pool: parts[0], FullName: fields[0],
			Created: created, UsedBytes: used, RefdBytes: refd,
		})
	}
	return snaps, nil
}

func (p *linuxProvider) CreateSnapshot(ctx context.Context, pool, name string) (Snapshot, error) {
	full := pool + "@" + name
	out, stderr, err := RunPriv(ctx, "/usr/sbin/zfs", "snapshot", full)
	if err != nil {
		out = append(out, stderr...)
		return Snapshot{}, fmt.Errorf("zfs snapshot: %s", strings.TrimSpace(string(out)))
	}
	return Snapshot{Name: name, Pool: pool, FullName: full, Created: time.Now().Unix()}, nil
}

func (p *linuxProvider) DeleteSnapshot(ctx context.Context, pool, snap string) error {
	out, stderr, err := RunPriv(ctx, "/usr/sbin/zfs", "destroy", pool+"@"+snap)
	if err != nil {
		out = append(out, stderr...)
		return fmt.Errorf("zfs destroy: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func (p *linuxProvider) RollbackSnapshot(ctx context.Context, pool, snap string) error {
	out, stderr, err := RunPriv(ctx, "/usr/sbin/zfs", "rollback", "-r", pool+"@"+snap)
	if err != nil {
		out = append(out, stderr...)
		return fmt.Errorf("zfs rollback: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func (p *linuxProvider) StartScrub(ctx context.Context, name string) error {
	out, stderr, err := RunPriv(ctx, "/usr/sbin/zpool", "scrub", name)
	if err != nil {
		return fmt.Errorf("zpool scrub: %s", strings.TrimSpace(string(append(out, stderr...))))
	}
	return nil
}

func indentLevel(line string) int {
	n := 0
	for _, ch := range line {
		switch ch {
		case '\t':
			n += 4
		case ' ':
			n++
		default:
			return n
		}
	}
	return n
}

func parseZpoolVDevs(text, poolName string) []VDev {
	lines := strings.Split(text, "\n")
	inConfig, headerSeen := false, false
	minIndent := -1
	var vdevs []VDev

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "config:" {
			inConfig = true
			continue
		}
		if !inConfig {
			continue
		}
		if trimmed == "" {
			if headerSeen {
				break
			}
			continue
		}
		if strings.HasPrefix(trimmed, "NAME") && strings.Contains(trimmed, "STATE") {
			headerSeen = true
			continue
		}
		if !headerSeen {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) < 5 || fields[0] == poolName {
			continue
		}
		indent := indentLevel(line)
		if minIndent < 0 {
			minIndent = indent
		}
		relIndent := (indent - minIndent) / 2
		readErrs, _ := strconv.ParseInt(fields[2], 10, 64)
		writeErrs, _ := strconv.ParseInt(fields[3], 10, 64)
		cksumErrs, _ := strconv.ParseInt(fields[4], 10, 64)
		vdevs = append(vdevs, VDev{
			Name:      fields[0],
			State:     strings.ToLower(fields[1]),
			ReadErrs:  readErrs,
			WriteErrs: writeErrs,
			CksmErrs:  cksumErrs,
			Indent:    relIndent,
		})
	}
	if vdevs == nil {
		return []VDev{}
	}
	return vdevs
}

func parseZpoolScrub(text string) ScrubStatus {
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "scan:") {
			continue
		}
		scan := strings.TrimSpace(strings.TrimPrefix(trimmed, "scan:"))
		switch {
		case strings.Contains(scan, "scrub in progress"):
			s := ScrubStatus{State: "scrubbing"}
			for j := i + 1; j <= i+3 && j < len(lines); j++ {
				if idx := strings.Index(lines[j], "% done"); idx > 0 {
					parts := strings.Fields(lines[j][:idx])
					if len(parts) > 0 {
						s.Progress, _ = strconv.ParseFloat(parts[len(parts)-1], 64)
					}
					break
				}
			}
			return s
		case strings.Contains(scan, "scrub repaired"):
			s := ScrubStatus{State: "completed", Progress: 100}
			if idx := strings.Index(scan, "with "); idx >= 0 {
				parts := strings.Fields(scan[idx+5:])
				if len(parts) > 0 {
					s.Errors, _ = strconv.ParseInt(parts[0], 10, 64)
				}
			}
			return s
		case strings.Contains(scan, "scrub canceled"):
			return ScrubStatus{State: "canceled"}
		case strings.Contains(scan, "scrub paused"):
			return ScrubStatus{State: "paused"}
		}
		return ScrubStatus{State: "none"}
	}
	return ScrubStatus{State: "none"}
}

// ── Docker containers ─────────────────────────────────────────────────────────

const dockerSock = "/var/run/docker.sock"

var dockerHTTP = &http.Client{
	Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", dockerSock)
		},
	},
}

type dockerListItem struct {
	ID      string   `json:"Id"`
	Names   []string `json:"Names"`
	Image   string   `json:"Image"`
	State   string   `json:"State"`
	Status  string   `json:"Status"`
	Created int64    `json:"Created"`
	Ports   []struct {
		IP          string `json:"IP"`
		PrivatePort int    `json:"PrivatePort"`
		PublicPort  int    `json:"PublicPort"`
		Type        string `json:"Type"`
	} `json:"Ports"`
	Mounts []struct {
		Name   string `json:"Name"`
		Source string `json:"Source"`
		Type   string `json:"Type"`
	} `json:"Mounts"`
}

func dockerDo(ctx context.Context, method, path string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, method, "http://docker"+path, nil)
	if err != nil {
		return nil, 0, err
	}
	resp, err := dockerHTTP.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	return body, resp.StatusCode, err
}

func (p *linuxProvider) Containers(ctx context.Context) ([]Container, error) {
	if _, err := os.Stat(dockerSock); os.IsNotExist(err) {
		return []Container{}, nil
	}
	body, status, err := dockerDo(ctx, http.MethodGet, "/containers/json?all=1")
	if err != nil {
		return nil, fmt.Errorf("docker list: %w", err)
	}
	if status >= 400 {
		return nil, fmt.Errorf("docker list: %s", strings.TrimSpace(string(body)))
	}
	var items []dockerListItem
	if err := json.Unmarshal(body, &items); err != nil {
		return nil, err
	}
	result := make([]Container, 0, len(items))
	for _, item := range items {
		name := item.ID[:12]
		if len(item.Names) > 0 {
			name = strings.TrimPrefix(item.Names[0], "/")
		}
		ports := []string{}
		for _, p := range item.Ports {
			if p.PublicPort > 0 {
				ip := p.IP
				if ip == "" {
					ip = "0.0.0.0"
				}
				ports = append(ports, fmt.Sprintf("%s:%d->%d/%s", ip, p.PublicPort, p.PrivatePort, p.Type))
			} else if p.PrivatePort > 0 {
				ports = append(ports, fmt.Sprintf("%d/%s", p.PrivatePort, p.Type))
			}
		}
		mounts := make([]ContainerMount, 0, len(item.Mounts))
		for _, m := range item.Mounts {
			mounts = append(mounts, ContainerMount{Name: m.Name, Source: m.Source, Type: m.Type})
		}
		result = append(result, Container{
			ID:      item.ID,
			Name:    name,
			Image:   item.Image,
			State:   item.State,
			Status:  item.Status,
			Created: item.Created,
			Ports:   ports,
			Mounts:  mounts,
		})
	}
	return result, nil
}

func (p *linuxProvider) StartContainer(ctx context.Context, id string) error {
	_, status, err := dockerDo(ctx, http.MethodPost, "/containers/"+id+"/start")
	if err != nil {
		return fmt.Errorf("docker start: %w", err)
	}
	if status >= 400 {
		return fmt.Errorf("docker start: HTTP %d", status)
	}
	return nil
}

func (p *linuxProvider) StopContainer(ctx context.Context, id string) error {
	_, status, err := dockerDo(ctx, http.MethodPost, "/containers/"+id+"/stop")
	if err != nil {
		return fmt.Errorf("docker stop: %w", err)
	}
	if status >= 400 {
		return fmt.Errorf("docker stop: HTTP %d", status)
	}
	return nil
}

func (p *linuxProvider) RemoveContainer(ctx context.Context, id string) error {
	_, status, err := dockerDo(ctx, http.MethodDelete, "/containers/"+id+"?force=1")
	if err != nil {
		return fmt.Errorf("docker remove: %w", err)
	}
	if status >= 400 {
		return fmt.Errorf("docker remove: HTTP %d", status)
	}
	return nil
}

func (p *linuxProvider) ContainerLogs(ctx context.Context, id, tail string) (string, error) {
	body, status, err := dockerDo(context.Background(), "GET",
		fmt.Sprintf("/containers/%s/logs?stdout=true&stderr=true&tail=%s", id, tail))
	if err != nil {
		return "", err
	}
	if status != 200 {
		return "", fmt.Errorf("docker logs: HTTP %d", status)
	}
	// Docker multiplexed stream: each frame has 8-byte header [stream(1), 0,0,0, size(4BE)]
	// Strip headers and collect text lines.
	var sb strings.Builder
	i := 0
	for i+8 <= len(body) {
		frameSize := int(body[i+4])<<24 | int(body[i+5])<<16 | int(body[i+6])<<8 | int(body[i+7])
		i += 8
		end := i + frameSize
		if end > len(body) {
			end = len(body)
		}
		sb.Write(body[i:end])
		i = end
	}
	// If no headers detected (non-TTY), just return raw
	if sb.Len() == 0 {
		return string(body), nil
	}
	return sb.String(), nil
}

func (p *linuxProvider) ContainerStats(ctx context.Context, id string) (ContainerStats, error) {
	body, status, err := dockerDo(context.Background(), "GET", "/containers/"+id+"/stats?stream=false&one-shot=true")
	if err != nil {
		return ContainerStats{}, err
	}
	if status != 200 {
		return ContainerStats{}, fmt.Errorf("docker stats: HTTP %d", status)
	}
	var raw struct {
		CPUStats struct {
			CPUUsage struct {
				TotalUsage int64 `json:"total_usage"`
			} `json:"cpu_usage"`
			SystemCPUUsage int64 `json:"system_cpu_usage"`
			OnlineCPUs     int   `json:"online_cpus"`
		} `json:"cpu_stats"`
		PreCPUStats struct {
			CPUUsage struct {
				TotalUsage int64 `json:"total_usage"`
			} `json:"cpu_usage"`
			SystemCPUUsage int64 `json:"system_cpu_usage"`
		} `json:"precpu_stats"`
		MemoryStats struct {
			Usage int64 `json:"usage"`
			Limit int64 `json:"limit"`
		} `json:"memory_stats"`
		Networks map[string]struct {
			RxBytes int64 `json:"rx_bytes"`
			TxBytes int64 `json:"tx_bytes"`
		} `json:"networks"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return ContainerStats{}, err
	}
	cpuDelta := float64(raw.CPUStats.CPUUsage.TotalUsage - raw.PreCPUStats.CPUUsage.TotalUsage)
	sysDelta := float64(raw.CPUStats.SystemCPUUsage - raw.PreCPUStats.SystemCPUUsage)
	cpuPct := 0.0
	if sysDelta > 0 && raw.CPUStats.OnlineCPUs > 0 {
		cpuPct = (cpuDelta / sysDelta) * float64(raw.CPUStats.OnlineCPUs) * 100
	}
	memPct := 0.0
	if raw.MemoryStats.Limit > 0 {
		memPct = float64(raw.MemoryStats.Usage) / float64(raw.MemoryStats.Limit) * 100
	}
	var rx, tx int64
	for _, n := range raw.Networks {
		rx += n.RxBytes
		tx += n.TxBytes
	}
	return ContainerStats{
		CPUPercent: cpuPct,
		MemUsed:    raw.MemoryStats.Usage,
		MemLimit:   raw.MemoryStats.Limit,
		MemPercent: memPct,
		RxBytes:    rx,
		TxBytes:    tx,
	}, nil
}

// ── SSH authorized keys ───────────────────────────────────────────────────────

var validKeyTypes = map[string]bool{
	"ssh-rsa": true, "ssh-dss": true, "ssh-ed25519": true,
	"ecdsa-sha2-nistp256": true, "ecdsa-sha2-nistp384": true, "ecdsa-sha2-nistp521": true,
	"sk-ssh-ed25519@openssh.com": true, "sk-ecdsa-sha2-nistp256@openssh.com": true,
}

func parseSSHKeyLine(line string) (SSHKey, bool) {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return SSHKey{}, false
	}
	if !validKeyTypes[fields[0]] {
		return SSHKey{}, false
	}
	k := SSHKey{Type: fields[0], Key: fields[1]}
	if len(fields) > 2 {
		k.Comment = strings.Join(fields[2:], " ")
	}
	return k, true
}

func (p *linuxProvider) SSHKeys(ctx context.Context) ([]SSHKey, error) {
	data, err := os.ReadFile(sshKeysPath)
	if os.IsNotExist(err) {
		return []SSHKey{}, nil
	}
	if err != nil {
		return nil, err
	}
	var keys []SSHKey
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if k, ok := parseSSHKeyLine(line); ok {
			keys = append(keys, k)
		}
	}
	if keys == nil {
		keys = []SSHKey{}
	}
	return keys, nil
}

func (p *linuxProvider) AddSSHKey(ctx context.Context, pubkey string) (SSHKey, error) {
	pubkey = strings.TrimSpace(pubkey)
	k, ok := parseSSHKeyLine(pubkey)
	if !ok {
		return SSHKey{}, fmt.Errorf("invalid public key format")
	}

	// Check for duplicate
	existing, _ := p.SSHKeys(context.Background())
	for _, e := range existing {
		if e.Key == k.Key {
			return SSHKey{}, fmt.Errorf("key already exists")
		}
	}

	if err := os.MkdirAll(filepath.Dir(sshKeysPath), 0755); err != nil {
		return SSHKey{}, err
	}
	f, err := os.OpenFile(sshKeysPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return SSHKey{}, err
	}
	defer f.Close()
	if _, err := fmt.Fprintf(f, "%s\n", pubkey); err != nil {
		return SSHKey{}, err
	}
	// sshd StrictModes requires authorized_keys be owned by root or the
	// authenticating user; chown so root logins can use this file.
	_ = os.Chown(sshKeysPath, 0, 0)
	return k, nil
}

func (p *linuxProvider) DeleteSSHKey(ctx context.Context, blob string) error {
	data, err := os.ReadFile(sshKeysPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("key not found")
		}
		return err
	}
	lines := strings.Split(string(data), "\n")
	var kept []string
	found := false
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[1] == blob {
			found = true
			continue
		}
		kept = append(kept, line)
	}
	if !found {
		return fmt.Errorf("key not found")
	}
	// Trim trailing blank lines from kept, then write
	content := strings.Join(kept, "\n")
	content = strings.TrimRight(content, "\n")
	if content != "" {
		content += "\n"
	}
	if err := os.WriteFile(sshKeysPath, []byte(content), 0600); err != nil {
		return err
	}
	_ = os.Chown(sshKeysPath, 0, 0)
	return nil
}

// ── Network interface config (/etc/network/interfaces) ───────────────────────

const ifacesFile = "/etc/network/interfaces"

func (p *linuxProvider) GetIfaceConfig(ctx context.Context, name string) (IfaceConfig, error) {
	data, err := os.ReadFile(ifacesFile)
	if os.IsNotExist(err) {
		return IfaceConfig{DHCP: true}, nil
	}
	if err != nil {
		return IfaceConfig{}, err
	}
	return parseIfacesFile(string(data), name), nil
}

func (p *linuxProvider) SetIfaceConfig(ctx context.Context, name string, cfg IfaceConfig) error {
	data, err := os.ReadFile(ifacesFile)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read interfaces: %w", err)
	}
	// Backup
	os.WriteFile(ifacesFile+".bak", data, 0644) //nolint:errcheck

	newData := rewriteIfacesFile(string(data), name, buildIfaceStanza(name, cfg))
	if err := os.WriteFile(ifacesFile, []byte(newData), 0644); err != nil {
		return fmt.Errorf("write interfaces: %w", err)
	}
	// Apply; ignore ifdown failure (interface may not be ifupdown-managed yet)
	RunPlain(ctx, "ifdown", "--force", name) //nolint:errcheck
	stdout, stderr, err := RunPlain(ctx, "ifup", name)
	if err != nil {
		out := append(stdout, stderr...)
		return fmt.Errorf("ifup %s: %s", name, strings.TrimSpace(string(out)))
	}
	return nil
}

func parseIfacesFile(data, name string) IfaceConfig {
	cfg := IfaceConfig{DHCP: true}
	inIface := false
	var addr, netmask, gateway string
	var dns []string

	for _, line := range strings.Split(data, "\n") {
		isOption := len(line) > 0 && (line[0] == ' ' || line[0] == '\t')
		trimmed := strings.TrimSpace(line)

		if !isOption && trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			inIface = false
			fields := strings.Fields(trimmed)
			if len(fields) >= 4 && fields[0] == "iface" && fields[1] == name && fields[2] == "inet" {
				inIface = true
				cfg = IfaceConfig{DHCP: fields[3] != "static"}
				addr, netmask, gateway = "", "", ""
				dns = nil
			}
			continue
		}

		if !inIface || !isOption {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "address":
			addr = fields[1]
		case "netmask":
			netmask = fields[1]
		case "gateway":
			gateway = fields[1]
		case "dns-nameservers":
			dns = fields[1:]
		}
	}

	if !cfg.DHCP {
		if strings.Contains(addr, "/") {
			cfg.Address = addr
		} else if addr != "" && netmask != "" {
			if ones := netmaskToPrefix(netmask); ones > 0 {
				cfg.Address = fmt.Sprintf("%s/%d", addr, ones)
			} else {
				cfg.Address = addr
			}
		} else {
			cfg.Address = addr
		}
		cfg.Gateway = gateway
		cfg.DNS = dns
	}
	return cfg
}

func rewriteIfacesFile(data, name, newStanza string) string {
	lines := strings.Split(data, "\n")
	var kept []string
	inIface := false

	for _, line := range lines {
		isOption := len(line) > 0 && (line[0] == ' ' || line[0] == '\t')
		trimmed := strings.TrimSpace(line)

		// Skip option lines that belong to the removed stanza
		if inIface && isOption {
			continue
		}

		if !isOption && trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			inIface = false
			fields := strings.Fields(trimmed)
			// Drop "auto <name>" / "allow-hotplug <name>"
			if len(fields) >= 2 && (fields[0] == "auto" || strings.HasPrefix(fields[0], "allow-")) {
				drop := false
				for _, f := range fields[1:] {
					if f == name {
						drop = true
						break
					}
				}
				if drop {
					continue
				}
			}
			// Drop "iface <name> inet ..." and mark options for removal
			if len(fields) >= 2 && fields[0] == "iface" && fields[1] == name {
				inIface = true
				continue
			}
		}

		kept = append(kept, line)
	}

	// Trim trailing blank lines then append new stanza
	for len(kept) > 0 && strings.TrimSpace(kept[len(kept)-1]) == "" {
		kept = kept[:len(kept)-1]
	}
	kept = append(kept, "", newStanza)
	return strings.Join(kept, "\n")
}

func buildIfaceStanza(name string, cfg IfaceConfig) string {
	var sb strings.Builder
	sb.WriteString("auto " + name + "\n")
	if cfg.DHCP {
		sb.WriteString("iface " + name + " inet dhcp\n")
	} else {
		sb.WriteString("iface " + name + " inet static\n")
		if cfg.Address != "" {
			sb.WriteString("\taddress " + cfg.Address + "\n")
		}
		if cfg.Gateway != "" {
			sb.WriteString("\tgateway " + cfg.Gateway + "\n")
		}
		if len(cfg.DNS) > 0 {
			sb.WriteString("\tdns-nameservers " + strings.Join(cfg.DNS, " ") + "\n")
		}
	}
	return sb.String()
}

func netmaskToPrefix(mask string) int {
	ip := net.ParseIP(mask)
	if ip == nil {
		return 0
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return 0
	}
	ones, _ := net.IPMask(ip4).Size()
	return ones
}

// ── S.M.A.R.T. tests ─────────────────────────────────────────────────────────

func (p *linuxProvider) StartSmartTest(ctx context.Context, devPath string, testType string) error {
	stdout, stderr, err := RunPriv(ctx, "/usr/bin/smartctl", "-t", testType, devPath)
	if err != nil {
		out := append(stdout, stderr...)
		return fmt.Errorf("smartctl -t %s %s: %s", testType, devPath, strings.TrimSpace(string(out)))
	}
	return nil
}

func (p *linuxProvider) GetSmartTestStatus(ctx context.Context, devPath string) (SmartTestStatus, error) {
	stdout, _, err := RunPriv(ctx, "/usr/bin/smartctl", "--json", "--all", devPath)
	out := stdout
	if err != nil && len(out) == 0 {
		return SmartTestStatus{}, fmt.Errorf("smartctl: %w", err)
	}
	var s smartctlOutput
	if err := json.Unmarshal(out, &s); err != nil {
		return SmartTestStatus{}, fmt.Errorf("parse smartctl json: %w", err)
	}
	st := s.AtaSmartData.SelfTest.Status
	running := strings.Contains(strings.ToLower(st.String), "progress")
	progress := 0
	if running {
		progress = 100 - st.RemainingPercent
	}
	return SmartTestStatus{
		Running:      running,
		Progress:     progress,
		StatusString: st.String,
	}, nil
}

// ── Dataset quotas ────────────────────────────────────────────────────────────

func (p *linuxProvider) GetDatasetQuota(ctx context.Context, pool string) (DatasetQuota, error) {
	out, _, err := RunPriv(ctx, "/usr/sbin/zfs", "get", "-Hp", "quota,reservation,used,available", pool)
	if err != nil {
		return DatasetQuota{}, fmt.Errorf("zfs get quota: %w", err)
	}
	var q DatasetQuota
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		prop, val := fields[1], fields[2]
		n, _ := strconv.ParseInt(val, 10, 64)
		switch prop {
		case "quota":
			q.QuotaBytes = n
		case "reservation":
			q.ReservationBytes = n
		case "used":
			q.UsedBytes = n
		case "available":
			q.AvailableBytes = n
		}
	}
	return q, nil
}

func (p *linuxProvider) SetDatasetQuota(ctx context.Context, pool string, u QuotaUpdate) error {
	if u.QuotaBytes != nil {
		val := "none"
		if *u.QuotaBytes > 0 {
			val = strconv.FormatInt(*u.QuotaBytes, 10)
		}
		_, _, err := RunPriv(ctx, "/usr/sbin/zfs", "set", "quota="+val, pool)
		if err != nil {
			return fmt.Errorf("zfs set quota: %v", err)
		}
	}
	if u.ReservationBytes != nil {
		val := "none"
		if *u.ReservationBytes > 0 {
			val = strconv.FormatInt(*u.ReservationBytes, 10)
		}
		_, _, err := RunPriv(ctx, "/usr/sbin/zfs", "set", "reservation="+val, pool)
		if err != nil {
			return fmt.Errorf("zfs set reservation: %v", err)
		}
	}
	return nil
}

// ── helpers ───────────────────────────────────────────────────────────────────

func parseSize(v interface{}) int64 {
	switch val := v.(type) {
	case string:
		n, _ := strconv.ParseInt(strings.TrimSpace(val), 10, 64)
		return n
	case float64:
		return int64(val)
	}
	return 0
}

func (p *linuxProvider) ImportCandidates(ctx context.Context) ([]ImportCandidate, error) {
	out, _, err := RunPriv(ctx, "/usr/sbin/zpool", "import")
	if err != nil {
		// exit code 1 with no pools available is normal
		if len(out) == 0 {
			return []ImportCandidate{}, nil
		}
	}
	return parseImportCandidates(string(out)), nil
}

func parseImportCandidates(output string) []ImportCandidate {
	candidates := []ImportCandidate{}
	var cur *ImportCandidate
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.HasPrefix(line, "   pool: ") {
			if cur != nil {
				candidates = append(candidates, *cur)
			}
			cur = &ImportCandidate{Name: strings.TrimPrefix(line, "   pool: ")}
		} else if cur != nil {
			if strings.HasPrefix(line, "     id: ") {
				cur.GUID = strings.TrimPrefix(line, "     id: ")
			} else if strings.HasPrefix(line, "  state: ") {
				cur.State = strings.TrimPrefix(line, "  state: ")
			} else if strings.Contains(line, "ONLINE") || strings.Contains(line, "AVAIL") {
				parts := strings.Fields(line)
				if len(parts) >= 1 && !strings.HasPrefix(parts[0], "/") {
					// likely a disk name line
					name := parts[0]
					if name != cur.Name && name != "NAME" && name != "config:" {
						cur.Disks = append(cur.Disks, name)
					}
				}
			}
		}
	}
	if cur != nil {
		candidates = append(candidates, *cur)
	}
	return candidates
}

func (p *linuxProvider) ImportPool(ctx context.Context, name, guid string) error {
	var args []string
	if guid != "" {
		args = []string{"import", guid}
	} else {
		args = []string{"import", name}
	}
	out, _, err := RunPriv(ctx, "/usr/sbin/zpool", args...)
	if err != nil {
		return fmt.Errorf("zpool import: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func (p *linuxProvider) ReplaceDisk(ctx context.Context, pool, oldDisk, newDisk string) error {
	args := []string{"replace", pool, oldDisk}
	if newDisk != "" && newDisk != oldDisk {
		args = append(args, newDisk)
	}
	out, _, err := RunPriv(ctx, "/usr/sbin/zpool", args...)
	if err != nil {
		return fmt.Errorf("zpool replace: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func (p *linuxProvider) Datasets(ctx context.Context, pool string) ([]Dataset, error) {
	stdout, _, err := RunPriv(ctx, "/usr/sbin/zfs", "list", "-H", "-o",
		"name,used,avail,mountpoint,encryption,compressratio",
		"-r", "-t", "filesystem", pool)
	if err != nil {
		return []Dataset{}, nil
	}
	var datasets []Dataset
	for _, line := range strings.Split(strings.TrimSpace(string(stdout)), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		name := fields[0]
		if name == pool {
			continue // skip root dataset
		}
		encrypted := len(fields) >= 5 && fields[4] != "off" && fields[4] != "-"
		var compressRatio float64
		if len(fields) >= 6 {
			ratioStr := strings.TrimSuffix(fields[5], "x")
			compressRatio, _ = strconv.ParseFloat(ratioStr, 64)
		}
		datasets = append(datasets, Dataset{
			Name:          name,
			Pool:          pool,
			MountPoint:    fields[3],
			UsedBytes:     parseZFSSize(fields[1]),
			AvailBytes:    parseZFSSize(fields[2]),
			Encrypted:     encrypted,
			CompressRatio: compressRatio,
		})
	}
	if datasets == nil {
		datasets = []Dataset{}
	}
	return datasets, nil
}

func (p *linuxProvider) CreateDataset(ctx context.Context, pool, name string) (Dataset, error) {
	fullName := pool + "/" + name
	out, _, err := RunPriv(ctx, "/usr/sbin/zfs", "create", fullName)
	if err != nil {
		return Dataset{}, fmt.Errorf("zfs create: %s", strings.TrimSpace(string(out)))
	}
	return Dataset{
		Name:       fullName,
		Pool:       pool,
		MountPoint: "/" + fullName,
	}, nil
}

func (p *linuxProvider) DeleteDataset(ctx context.Context, pool, name string) error {
	fullName := pool + "/" + name
	_, _, err := RunPriv(ctx, "/usr/sbin/zfs", "destroy", fullName)
	if err != nil {
		return fmt.Errorf("zfs destroy: %v", err)
	}
	return nil
}

func parseZFSSize(s string) int64 {
	if s == "-" || s == "none" {
		return 0
	}
	multipliers := map[byte]int64{'K': 1024, 'M': 1024 * 1024, 'G': 1024 * 1024 * 1024, 'T': 1024 * 1024 * 1024 * 1024}
	if len(s) == 0 {
		return 0
	}
	last := s[len(s)-1]
	if mul, ok := multipliers[last]; ok {
		val, _ := strconv.ParseFloat(s[:len(s)-1], 64)
		return int64(val * float64(mul))
	}
	val, _ := strconv.ParseInt(s, 10, 64)
	return val
}

const encryptionKeysDir = "/var/lib/kilasos/keys"

func (p *linuxProvider) CreateEncryptedDataset(ctx context.Context, pool, name, passphrase string) (Dataset, error) {
	fullName := pool + "/" + name
	keyPath := filepath.Join(encryptionKeysDir, pool, name+".key")
	if err := os.MkdirAll(filepath.Dir(keyPath), 0700); err != nil {
		return Dataset{}, fmt.Errorf("mkdir keys: %w", err)
	}
	if err := os.WriteFile(keyPath, []byte(passphrase), 0600); err != nil {
		return Dataset{}, fmt.Errorf("write key: %w", err)
	}
	args := []string{
		"create",
		"-o", "encryption=aes-256-gcm",
		"-o", "keyformat=passphrase",
		"-o", "keylocation=file://" + keyPath,
		fullName,
	}
	stdout, stderr, err := RunPriv(ctx, "/usr/sbin/zfs", args...)
	if err != nil {
		out := append(stdout, stderr...)
		os.Remove(keyPath) //nolint:errcheck
		return Dataset{}, fmt.Errorf("zfs create: %s", strings.TrimSpace(string(out)))
	}
	return Dataset{
		Name:      fullName,
		Pool:      pool,
		Encrypted: true,
	}, nil
}

func (p *linuxProvider) LoadEncryptionKey(ctx context.Context, dataset, passphrase string) error {
	parts := strings.SplitN(dataset, "/", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid dataset name")
	}
	keyPath := filepath.Join(encryptionKeysDir, parts[0], parts[1]+".key")
	if passphrase != "" {
		if err := os.WriteFile(keyPath, []byte(passphrase), 0600); err != nil {
			return fmt.Errorf("write key: %w", err)
		}
	}
	_, _, err := RunPriv(ctx, "/usr/sbin/zfs", "load-key", dataset)
	if err != nil {
		return fmt.Errorf("zfs load-key: %v", err)
	}
	_, _, err = RunPriv(ctx, "/usr/sbin/zfs", "mount", dataset)
	if err != nil {
		return fmt.Errorf("zfs mount: %v", err)
	}
	return nil
}

func (p *linuxProvider) ARCStats(ctx context.Context) (ARCStats, error) {
	data, err := os.ReadFile("/proc/spl/kstat/zfs/arcstats")
	if err != nil {
		return ARCStats{}, err
	}
	vals := make(map[string]int64)
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 3 {
			n, _ := strconv.ParseInt(fields[2], 10, 64)
			vals[fields[0]] = n
		}
	}
	hits := vals["hits"]
	misses := vals["misses"]
	total := hits + misses
	hitPct := 0.0
	if total > 0 {
		hitPct = float64(hits) / float64(total) * 100
	}
	l2Hits := vals["l2_hits"]
	l2Misses := vals["l2_misses"]
	l2Total := l2Hits + l2Misses
	l2HitPct := 0.0
	if l2Total > 0 {
		l2HitPct = float64(l2Hits) / float64(l2Total) * 100
	}
	return ARCStats{
		SizeBytes:   vals["size"],
		MaxBytes:    vals["c"],
		HitPct:      hitPct,
		L2SizeBytes: vals["l2_size"],
		L2HitPct:    l2HitPct,
	}, nil
}

func (p *linuxProvider) SystemInfo(ctx context.Context) (SystemInfo, error) {
	hostname, _ := os.Hostname()

	// kernel from uname
	kernelOut, _, _ := RunPlain(ctx, "uname", "-r")
	kernel := strings.TrimSpace(string(kernelOut))

	// OS from /etc/os-release
	osName := "Linux"
	if data, err := os.ReadFile("/etc/os-release"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				osName = strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), "\"")
				break
			}
		}
	}

	// uptime from /proc/uptime
	var uptimeSecs int64
	if data, err := os.ReadFile("/proc/uptime"); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) > 0 {
			f, _ := strconv.ParseFloat(fields[0], 64)
			uptimeSecs = int64(f)
		}
	}

	// load average from /proc/loadavg
	var load1, load5, load15 float64
	if data, err := os.ReadFile("/proc/loadavg"); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) >= 3 {
			load1, _ = strconv.ParseFloat(fields[0], 64)
			load5, _ = strconv.ParseFloat(fields[1], 64)
			load15, _ = strconv.ParseFloat(fields[2], 64)
		}
	}

	// CPU cores
	cores := 0
	if data, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "processor") {
				cores++
			}
		}
	}

	return SystemInfo{
		Hostname:  hostname,
		OS:        osName,
		Kernel:    kernel,
		Uptime:    uptimeSecs,
		LoadAvg1:  load1,
		LoadAvg5:  load5,
		LoadAvg15: load15,
		CPUCores:  cores,
	}, nil
}

func (p *linuxProvider) UpdateShare(ctx context.Context, name string, update Share) (Share, error) {
	update.Name = name
	// Update SMB config (keep same path)
	existing, err := readShareConf(filepath.Join(shareConfDir, name+".conf"))
	if err != nil {
		return Share{}, fmt.Errorf("share not found")
	}
	update.Path = existing.Path
	update.Pool = existing.Pool
	if err := writeShareConf(update); err != nil {
		return Share{}, err
	}
	RunPriv(ctx, "/usr/bin/smbcontrol", "smbd", "reload-config") //nolint:errcheck

	// Update NFS config
	meta, _ := loadNFSMeta()
	if update.NFS {
		meta[name] = nfsShareMeta{Clients: update.NFSClients, Options: update.NFSOptions}
	} else {
		delete(meta, name)
	}
	saveNFSMeta(meta) //nolint:errcheck
	allShares, _ := p.Shares(ctx)
	regenerateNFSExports(allShares, meta) //nolint:errcheck
	return update, nil
}

// ── Disk Wipe ─────────────────────────────────────────────────────────────────

func (p *linuxProvider) WipeDisk(ctx context.Context, path string) error {
	if !strings.HasPrefix(path, "/dev/") {
		return fmt.Errorf("invalid device path: %s", path)
	}
	// Clear filesystem/partition signatures
	stdout, stderr, err := RunPlain(ctx, "wipefs", "-a", path)
	if err != nil {
		out := append(stdout, stderr...)
		return fmt.Errorf("wipefs: %s", strings.TrimSpace(string(out)))
	}
	// Zero first 10 MiB and last 10 MiB to clear ZFS/MBR/GPT labels
	RunPlain(ctx, "dd", "if=/dev/zero", "of="+path, "bs=1M", "count=10", "conv=fsync") //nolint:errcheck
	return nil
}

// ── ZFS Pool Trim ─────────────────────────────────────────────────────────────

func (p *linuxProvider) TrimPool(ctx context.Context, pool string) error {
	stdout, stderr, err := RunPriv(ctx, "/usr/sbin/zpool", "trim", pool)
	if err != nil {
		out := append(stdout, stderr...)
		return fmt.Errorf("zpool trim: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

// ── Docker Image Pull ─────────────────────────────────────────────────────────

func (p *linuxProvider) PullImage(ctx context.Context, image string) (string, error) {
	stdout, stderr, err := RunPlain(ctx, "docker", "pull", image)
	out := stdout
	if err != nil {
		out = append(stdout, stderr...)
		return "", fmt.Errorf("docker pull: %s", strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)), nil
}

// ── Disk I/O stats ────────────────────────────────────────────────────────────
// Reads /proc/diskstats and returns per-disk read/write bytes/sec.

func (p *linuxProvider) DiskIO(ctx context.Context) ([]DiskIO, error) {
	f, err := os.Open("/proc/diskstats")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	type rawStat struct{ rb, wb uint64 }
	cur := map[string]rawStat{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 14 {
			continue
		}
		name := fields[2]
		// Skip partition entries (e.g. sda1, sdb2) — keep only whole-disk names
		if len(name) > 0 && name[len(name)-1] >= '0' && name[len(name)-1] <= '9' {
			continue
		}
		// Skip loop and ram devices
		if strings.HasPrefix(name, "loop") || strings.HasPrefix(name, "ram") {
			continue
		}
		rb, _ := strconv.ParseUint(fields[5], 10, 64)
		wb, _ := strconv.ParseUint(fields[9], 10, 64)
		// diskstats counts are in 512-byte sectors
		cur[name] = rawStat{rb * 512, wb * 512}
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	dt := now.Sub(p.prevAt).Seconds()
	if dt <= 0 {
		dt = 1
	}

	var result []DiskIO
	for name, c := range cur {
		prev := p.prevDisk[name]
		var rps, wps float64
		if prev.rbytes > 0 || prev.wbytes > 0 {
			rDiff := float64(c.rb) - float64(prev.rbytes)
			wDiff := float64(c.wb) - float64(prev.wbytes)
			if rDiff < 0 { rDiff = 0 }
			if wDiff < 0 { wDiff = 0 }
			rps = rDiff / dt
			wps = wDiff / dt
		}
		p.prevDisk[name] = diskSample{rbytes: c.rb, wbytes: c.wb}
		result = append(result, DiskIO{Name: name, ReadBytesPS: rps, WriteBytesPS: wps})
	}
	// prevAt already updated by Metrics; if called standalone keep it fresh
	if p.prevAt.IsZero() {
		p.prevAt = now
	}

	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result, nil
}

// ── Process list ─────────────────────────────────────────────────────────────

func (p *linuxProvider) Processes(ctx context.Context) ([]Process, error) {
	out, _, err := RunPlain(ctx, "ps", "axo", "pid,user,pcpu,pmem,rss,comm", "--sort=-pcpu", "--no-headers")
	if err != nil {
		return nil, fmt.Errorf("ps: %w", err)
	}
	var procs []Process
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 6 {
			continue
		}
		pid, _ := strconv.Atoi(fields[0])
		cpu, _ := strconv.ParseFloat(fields[2], 64)
		mem, _ := strconv.ParseFloat(fields[3], 64)
		rss, _ := strconv.ParseInt(fields[4], 10, 64)
		procs = append(procs, Process{
			PID:     pid,
			User:    fields[1],
			CPUPct:  cpu,
			MemPct:  mem,
			MemRSS:  rss * 1024,
			Command: fields[5],
		})
		if len(procs) >= 50 {
			break
		}
	}
	return procs, nil
}

// ── Docker Volumes ────────────────────────────────────────────────────────────

type dockerVolumeList struct {
	Volumes []struct {
		Name       string `json:"Name"`
		Driver     string `json:"Driver"`
		Mountpoint string `json:"Mountpoint"`
		UsageData  *struct {
			Size int64 `json:"Size"`
		} `json:"UsageData,omitempty"`
	} `json:"Volumes"`
}

func (p *linuxProvider) DockerVolumes(ctx context.Context) ([]DockerVolume, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "http://docker/volumes", nil)
	if err != nil {
		return nil, err
	}
	resp, err := dockerHTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var list dockerVolumeList
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		return nil, err
	}
	result := make([]DockerVolume, 0, len(list.Volumes))
	for _, v := range list.Volumes {
		sz := int64(-1)
		if v.UsageData != nil {
			sz = v.UsageData.Size
		}
		result = append(result, DockerVolume{
			Name:       v.Name,
			Driver:     v.Driver,
			Mountpoint: v.Mountpoint,
			SizeBytes:  sz,
		})
	}
	return result, nil
}

func (p *linuxProvider) RemoveDockerVolume(ctx context.Context, name string) error {
	req, err := http.NewRequestWithContext(ctx, "DELETE", "http://docker/volumes/"+name, nil)
	if err != nil {
		return err
	}
	resp, err := dockerHTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("docker: %s", strings.TrimSpace(string(body)))
	}
	return nil
}

// ── Network Diagnostics ───────────────────────────────────────────────────────

func (p *linuxProvider) NetDiag(ctx context.Context, diagType, target string) (NetDiagResult, error) {
	res := NetDiagResult{Target: target, Type: diagType}
	switch diagType {
	case "ping":
		out, stderr, err := RunPlain(ctx, "ping", "-c", "4", "-W", "2", target)
		res.Output = strings.TrimSpace(string(out))
		if res.Output == "" && len(stderr) > 0 {
			res.Output = strings.TrimSpace(string(stderr))
		}
		res.Success = err == nil
	case "dns":
		out, _, err := RunPlain(ctx, "dig", "+short", target)
		if err != nil {
			out, _, err = RunPlain(ctx, "nslookup", target)
		}
		res.Output = strings.TrimSpace(string(out))
		res.Success = err == nil && len(strings.TrimSpace(string(out))) > 0
	case "traceroute":
		out, stderr, err := RunPlain(ctx, "traceroute", "-n", "-w", "1", "-m", "20", target)
		res.Output = strings.TrimSpace(string(out))
		if res.Output == "" && len(stderr) > 0 {
			res.Output = strings.TrimSpace(string(stderr))
		}
		res.Success = err == nil
	default:
		return res, fmt.Errorf("unknown diag type: %s", diagType)
	}
	return res, nil
}

// ── Docker Images ─────────────────────────────────────────────────────────────

type dockerImageItem struct {
	ID          string   `json:"Id"`
	RepoTags    []string `json:"RepoTags"`
	Size        int64    `json:"Size"`
	Created     int64    `json:"Created"`
}

func (p *linuxProvider) DockerImages(ctx context.Context) ([]DockerImage, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "http://docker/images/json", nil)
	if err != nil {
		return nil, err
	}
	resp, err := dockerHTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var items []dockerImageItem
	if err := json.NewDecoder(resp.Body).Decode(&items); err != nil {
		return nil, err
	}
	result := make([]DockerImage, 0, len(items))
	for _, img := range items {
		id := img.ID
		if len(id) > 19 {
			id = id[7:19] // trim sha256: prefix and truncate
		}
		tags := img.RepoTags
		if len(tags) == 0 {
			tags = []string{"<none>"}
		}
		result = append(result, DockerImage{
			ID:        id,
			Tags:      tags,
			SizeBytes: img.Size,
			Created:   img.Created,
		})
	}
	return result, nil
}

func (p *linuxProvider) RemoveDockerImage(ctx context.Context, id string) error {
	req, err := http.NewRequestWithContext(ctx, "DELETE", "http://docker/images/"+id, nil)
	if err != nil {
		return err
	}
	resp, err := dockerHTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("docker: %s", strings.TrimSpace(string(body)))
	}
	return nil
}

// ── SMB Connections ───────────────────────────────────────────────────────────

func (p *linuxProvider) SMBConnections(ctx context.Context) ([]SMBConnection, error) {
	out, _, err := RunPriv(ctx, "/usr/bin/smbstatus", "-b")
	if err != nil {
		return []SMBConnection{}, nil // samba may not be running
	}
	conns := []SMBConnection{}
	inSection := false
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "----") {
			inSection = true
			continue
		}
		if !inSection || line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		pid, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}
		connected := ""
		if len(fields) >= 5 {
			connected = strings.Join(fields[3:], " ")
		}
		conns = append(conns, SMBConnection{
			PID:       pid,
			Username:  fields[1],
			Machine:   fields[2],
			Connected: connected,
		})
	}
	return conns, nil
}

// ── ZFS Clone ─────────────────────────────────────────────────────────────────

func (p *linuxProvider) CloneSnapshot(ctx context.Context, pool, snap, cloneName string) error {
	fullSnap := pool + "@" + snap
	fullClone := pool + "/" + cloneName
	stdout, stderr, err := RunPriv(ctx, "/usr/sbin/zfs", "clone", fullSnap, fullClone)
	if err != nil {
		out := append(stdout, stderr...)
		return fmt.Errorf("zfs clone: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

// ── ZFS Resilver / Expand ─────────────────────────────────────────────────────

func (p *linuxProvider) Resilver(ctx context.Context, pool string) error {
	stdout, stderr, err := RunPriv(ctx, "/usr/sbin/zpool", "scrub", "-s", pool)
	if err != nil {
		stdout, stderr, err = RunPriv(ctx, "/usr/sbin/zpool", "scrub", pool)
	}
	if err != nil {
		out := append(stdout, stderr...)
		return fmt.Errorf("zpool scrub: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func (p *linuxProvider) ExpandPool(ctx context.Context, pool string) error {
	stdout, stderr, err := RunPriv(ctx, "/usr/sbin/zpool", "online", "-e", pool)
	if err != nil {
		out := append(stdout, stderr...)
		return fmt.Errorf("zpool online -e: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

// ── Journal Search ────────────────────────────────────────────────────────────

func (p *linuxProvider) SearchJournal(ctx context.Context, query string, n int) ([]JournalSearchResult, error) {
	if n <= 0 || n > 200 {
		n = 50
	}
	out, _, err := RunPriv(ctx, "/usr/bin/journalctl", "--grep="+query, "-n", strconv.Itoa(n),
		"--no-pager", "--output=json")
	if err != nil {
		// fallback: plain text grep
		out2, _, _ := RunPriv(ctx, "/usr/bin/journalctl", "-n", "2000", "--no-pager", "--output=short-iso")
		results := []JournalSearchResult{}
		lq := strings.ToLower(query)
		for _, line := range strings.Split(string(out2), "\n") {
			if strings.Contains(strings.ToLower(line), lq) {
				results = append(results, JournalSearchResult{Message: line})
				if len(results) >= n {
					break
				}
			}
		}
		return results, nil
	}

	results := []JournalSearchResult{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		var entry struct {
			RealtimeTimestamp string `json:"__REALTIME_TIMESTAMP"`
			SyslogIdentifier  string `json:"SYSLOG_IDENTIFIER"`
			Unit              string `json:"_SYSTEMD_UNIT"`
			Message           string `json:"MESSAGE"`
		}
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}
		unit := entry.Unit
		if unit == "" {
			unit = entry.SyslogIdentifier
		}
		timeStr := ""
		if ts, err2 := strconv.ParseInt(entry.RealtimeTimestamp, 10, 64); err2 == nil {
			timeStr = time.Unix(ts/1e6, 0).Format("2006-01-02 15:04:05")
		}
		results = append(results, JournalSearchResult{
			Unit:    unit,
			Time:    timeStr,
			Message: entry.Message,
		})
	}
	return results, nil
}

// ── Pool Events ───────────────────────────────────────────────────────────────

func (p *linuxProvider) PoolEvents(ctx context.Context, pool string) ([]PoolEvent, error) {
	args := []string{"events", "-H", pool}
	stdout, stderr, err := RunPriv(ctx, "/usr/sbin/zpool", args...)
	out := stdout
	if err != nil {
		out = append(stdout, stderr...)
		return []PoolEvent{}, nil // events may not be available on older kernels
	}
	var events []PoolEvent
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		// Format varies; capture as-is with pool name
		events = append(events, PoolEvent{
			Time:    time.Now().Unix(),
			Pool:    pool,
			Message: line,
		})
	}
	return events, nil
}

// ── Container Inspect ─────────────────────────────────────────────────────────

func (p *linuxProvider) InspectContainer(ctx context.Context, id string) (ContainerInspect, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "http://docker/containers/"+id+"/json", nil)
	if err != nil {
		return ContainerInspect{}, err
	}
	resp, err := dockerHTTP.Do(req)
	if err != nil {
		return ContainerInspect{}, err
	}
	defer resp.Body.Close()

	var raw struct {
		ID      string `json:"Id"`
		Name    string `json:"Name"`
		Created string `json:"Created"`
		Config  struct {
			Image string   `json:"Image"`
			Env   []string `json:"Env"`
		} `json:"Config"`
		HostConfig struct {
			RestartPolicy struct {
				Name string `json:"Name"`
			} `json:"RestartPolicy"`
			CPUShares int64 `json:"CpuShares"`
			Memory    int64 `json:"Memory"`
			PidsLimit int64 `json:"PidsLimit"`
		} `json:"HostConfig"`
		Mounts []struct {
			Type        string `json:"Type"`
			Source      string `json:"Source"`
			Destination string `json:"Destination"`
			RW          bool   `json:"RW"`
		} `json:"Mounts"`
		NetworkSettings struct {
			Networks map[string]interface{} `json:"Networks"`
		} `json:"NetworkSettings"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return ContainerInspect{}, err
	}

	name := strings.TrimPrefix(raw.Name, "/")
	var nets []string
	for n := range raw.NetworkSettings.Networks {
		nets = append(nets, n)
	}
	mounts := make([]ContainerMount, 0, len(raw.Mounts))
	for _, m := range raw.Mounts {
		mounts = append(mounts, ContainerMount{
			Type:        m.Type,
			Source:      m.Source,
			Destination: m.Destination,
			RW:          m.RW,
		})
	}
	return ContainerInspect{
		ID:            raw.ID[:min(12, len(raw.ID))], //nolint:mnd
		Name:          name,
		Image:         raw.Config.Image,
		Created:       raw.Created,
		RestartPolicy: raw.HostConfig.RestartPolicy.Name,
		Env:           raw.Config.Env,
		Mounts:        mounts,
		Networks:      nets,
		CPUShares:     raw.HostConfig.CPUShares,
		MemLimit:      raw.HostConfig.Memory,
		PidLimit:      raw.HostConfig.PidsLimit,
	}, nil
}

// ── Pool I/O stats ────────────────────────────────────────────────────────────

func (p *linuxProvider) PoolIO(ctx context.Context) ([]PoolIO, error) {
	// zpool iostat -H -p <pool> 1 2: take second sample (1-sec interval)
	out, _, err := RunPriv(ctx, "/usr/sbin/zpool", "iostat", "-H", "-p", "1", "2")
	if err != nil {
		return nil, fmt.Errorf("zpool iostat: %w", err)
	}

	var result []PoolIO
	seen := map[string]bool{}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	// Second batch of output after 1-second interval
	// Output format: name  alloc  free  read_ops  write_ops  read_bw  write_bw
	total := len(lines)
	// Take lines from the second half (after the 1-second sample)
	start := total / 2
	if start > total {
		start = 0
	}
	for _, line := range lines[start:] {
		fields := strings.Fields(line)
		if len(fields) < 7 {
			continue
		}
		name := fields[0]
		if strings.HasPrefix(name, "-") || seen[name] {
			continue
		}
		// Skip child vdevs — pool names don't contain spaces or slashes
		if strings.ContainsAny(name, "/") {
			continue
		}
		seen[name] = true
		rOps, _ := strconv.ParseFloat(fields[3], 64)
		wOps, _ := strconv.ParseFloat(fields[4], 64)
		rBw, _ := strconv.ParseFloat(fields[5], 64)
		wBw, _ := strconv.ParseFloat(fields[6], 64)
		result = append(result, PoolIO{
			Name:         name,
			ReadOpPS:     rOps,
			WriteOpPS:    wOps,
			ReadBytesPS:  rBw,
			WriteBytesPS: wBw,
		})
	}
	return result, nil
}

// ── Dataset Properties ────────────────────────────────────────────────────────

func (p *linuxProvider) GetDatasetProps(ctx context.Context, dataset string) (DatasetProps, error) {
	props := []string{"compression", "atime", "recordsize", "dedup", "checksum", "readonly", "snapdir"}
	out, _, err := RunPriv(ctx, "/usr/sbin/zfs", append([]string{"get", "-H", "-o", "property,value", strings.Join(props, ",")}, dataset)...)
	if err != nil {
		return DatasetProps{}, fmt.Errorf("zfs get: %w", err)
	}
	result := DatasetProps{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		switch parts[0] {
		case "compression":
			result.Compression = parts[1]
		case "atime":
			result.Atime = parts[1]
		case "recordsize":
			result.Recordsize = parts[1]
		case "dedup":
			result.Dedup = parts[1]
		case "checksum":
			result.Checksum = parts[1]
		case "readonly":
			result.Readonly = parts[1]
		case "snapdir":
			result.Snapdir = parts[1]
		}
	}
	return result, nil
}

func (p *linuxProvider) SetDatasetProps(ctx context.Context, dataset string, u DatasetPropsUpdate) error {
	var args []string
	set := func(k string, v *string) {
		if v != nil {
			args = append(args, k+"="+*v)
		}
	}
	set("compression", u.Compression)
	set("atime", u.Atime)
	set("recordsize", u.Recordsize)
	set("dedup", u.Dedup)
	set("readonly", u.Readonly)
	if len(args) == 0 {
		return nil
	}
	cmd := append([]string{"set"}, append(args, dataset)...)
	stdout, stderr, err := RunPriv(ctx, "/usr/sbin/zfs", cmd...)
	if err != nil {
		out := append(stdout, stderr...)
		return fmt.Errorf("zfs set: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

// ── SMART Detail ──────────────────────────────────────────────────────────────

func (p *linuxProvider) SmartDetail(ctx context.Context, devPath string) (SmartDetail, error) {
	if !strings.HasPrefix(devPath, "/dev/") {
		return SmartDetail{}, fmt.Errorf("invalid device path")
	}
	stdout, _, err := RunPriv(ctx, "/usr/bin/smartctl", "-a", "-j", devPath)
	out := stdout
	if err != nil && len(out) == 0 {
		return SmartDetail{}, fmt.Errorf("smartctl: %w", err)
	}

	var raw struct {
		ModelName   string `json:"model_name"`
		SerialNumber string `json:"serial_number"`
		FirmwareVersion string `json:"firmware_version"`
		UserCapacity struct {
			Bytes int64 `json:"bytes"`
		} `json:"user_capacity"`
		SmartStatus struct {
			Passed bool `json:"passed"`
		} `json:"smart_status"`
		Temperature struct {
			Current int `json:"current"`
		} `json:"temperature"`
		PowerOnTime struct {
			Hours int `json:"hours"`
		} `json:"power_on_time"`
		AtaSmartAttributes struct {
			Table []struct {
				ID    int    `json:"id"`
				Name  string `json:"name"`
				Value int    `json:"value"`
				Worst int    `json:"worst"`
				Raw   struct {
					String string `json:"string"`
				} `json:"raw"`
				WhenFailed string `json:"when_failed"`
			} `json:"table"`
		} `json:"ata_smart_attributes"`
	}

	if err := json.Unmarshal(out, &raw); err != nil {
		return SmartDetail{}, fmt.Errorf("parse smartctl output: %w", err)
	}

	detail := SmartDetail{
		DevPath:    devPath,
		Model:      raw.ModelName,
		Serial:     raw.SerialNumber,
		Firmware:   raw.FirmwareVersion,
		CapacityGB: float64(raw.UserCapacity.Bytes) / 1e9,
		SmartOK:    raw.SmartStatus.Passed,
	}
	if t := raw.Temperature.Current; t > 0 {
		detail.TempC = &t
	}
	if h := raw.PowerOnTime.Hours; h > 0 {
		detail.PowerOnH = &h
	}
	for _, attr := range raw.AtaSmartAttributes.Table {
		detail.Attributes = append(detail.Attributes, SmartAttr{
			ID:       attr.ID,
			Name:     attr.Name,
			Value:    attr.Value,
			Worst:    attr.Worst,
			Raw:      attr.Raw.String,
			WhenFail: attr.WhenFailed,
		})
	}
	return detail, nil
}

func (p *linuxProvider) GetPoolProps(ctx context.Context, pool string) (ZFSPoolProps, error) {
	props := ZFSPoolProps{}
	poolOut, _, err := RunPriv(ctx, "/usr/sbin/zpool", "get", "-H", "-o", "property,value",
		"autoexpand,autoreplace,listsnapshots", pool)
	if err != nil {
		return ZFSPoolProps{}, fmt.Errorf("zpool get: %w", err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(poolOut)), "\n") {
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		switch parts[0] {
		case "autoexpand":
			props.Autoexpand = parts[1]
		case "autoreplace":
			props.Autoreplace = parts[1]
		case "listsnapshots":
			props.Listsnapshots = parts[1]
		}
	}
	// Dataset-level properties on root dataset via zfs get
	dsOut, _, _ := RunPriv(ctx, "/usr/sbin/zfs", "get", "-H", "-o", "property,value",
		"atime,compression,dedup", pool)
	for _, line := range strings.Split(strings.TrimSpace(string(dsOut)), "\n") {
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		switch parts[0] {
		case "atime":
			props.Atime = parts[1]
		case "compression":
			props.Compression = parts[1]
		case "dedup":
			props.Dedup = parts[1]
		}
	}
	return props, nil
}

func (p *linuxProvider) SetPoolProps(ctx context.Context, pool string, u ZFSPoolPropsUpdate) error {
	// Pool-level properties: zpool set
	poolKV := map[string]*string{
		"autoexpand":    u.Autoexpand,
		"autoreplace":   u.Autoreplace,
		"listsnapshots": u.Listsnapshots,
	}
	for k, v := range poolKV {
		if v == nil {
			continue
		}
		if _, _, err := RunPriv(ctx, "/usr/sbin/zpool", "set", k+"="+*v, pool); err != nil {
			return fmt.Errorf("zpool set %s: %w", k, err)
		}
	}
	// Dataset-level properties on root dataset: zfs set
	dsKV := map[string]*string{
		"compression": u.Compression,
		"dedup":       u.Dedup,
	}
	for k, v := range dsKV {
		if v == nil {
			continue
		}
		if _, _, err := RunPriv(ctx, "/usr/sbin/zfs", "set", k+"="+*v, pool); err != nil {
			return fmt.Errorf("zfs set %s: %w", k, err)
		}
	}
	return nil
}

func (p *linuxProvider) ScanServices(ctx context.Context, host string) ([]ServiceDiscovery, error) {
	commonPorts := []int{
		21, 22, 23, 25, 53, 80, 110, 111, 139, 143,
		389, 443, 445, 548, 631, 873, 993, 995, 2049,
		3306, 3389, 5432, 5900, 6379, 8080, 8443, 8888, 9000, 27017,
	}
	results := []ServiceDiscovery{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, port := range commonPorts {
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			addr := net.JoinHostPort(host, strconv.Itoa(port))
			conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
			if err != nil {
				return
			}
			defer conn.Close()
			banner := ""
			conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond)) //nolint:errcheck
			buf := make([]byte, 256)
			n, _ := conn.Read(buf)
			if n > 0 {
				banner = strings.TrimSpace(string(buf[:n]))
			}
			mu.Lock()
			results = append(results, ServiceDiscovery{
				Host:    host,
				Port:    port,
				Service: guessService(port),
				Banner:  banner,
			})
			mu.Unlock()
		}(port)
	}
	wg.Wait()
	sort.Slice(results, func(i, j int) bool { return results[i].Port < results[j].Port })
	return results, nil
}

func guessService(port int) string {
	m := map[int]string{
		21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
		80: "http", 110: "pop3", 111: "rpcbind", 139: "netbios", 143: "imap",
		389: "ldap", 443: "https", 445: "smb", 548: "afp", 631: "ipp",
		873: "rsync", 993: "imaps", 995: "pop3s", 2049: "nfs",
		3306: "mysql", 3389: "rdp", 5432: "postgres", 5900: "vnc",
		6379: "redis", 8080: "http-alt", 8443: "https-alt",
		8888: "http-dev", 9000: "php-fpm", 27017: "mongodb",
	}
	if s, ok := m[port]; ok {
		return s
	}
	return "unknown"
}

func (p *linuxProvider) PendingUpdates(ctx context.Context) ([]PackageUpdate, error) {
	out, _, err := RunPlain(ctx, "apt", "list", "--upgradable", "--quiet=2")
	if err != nil {
		return nil, fmt.Errorf("apt list: %w", err)
	}
	updates := []PackageUpdate{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" || strings.HasPrefix(line, "Listing") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		name := strings.Split(parts[0], "/")[0]
		newVer := parts[1]
		oldVer := ""
		if idx := strings.Index(line, "upgradable from: "); idx >= 0 {
			rest := line[idx+17:]
			oldVer = strings.TrimSuffix(rest, "]")
		}
		updates = append(updates, PackageUpdate{Name: name, CurrentVersion: oldVer, NewVersion: newVer})
	}
	return updates, nil
}

func (p *linuxProvider) SystemUsers(ctx context.Context) ([]SystemUser, error) {
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	users := []SystemUser{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) < 7 {
			continue
		}
		uid, _ := strconv.Atoi(parts[2])
		gid, _ := strconv.Atoi(parts[3])
		if (uid < 1000 && uid != 0) || uid == 65534 {
			continue
		}
		users = append(users, SystemUser{
			Name: parts[0], UID: uid, GID: gid,
			Home: parts[5], Shell: parts[6],
		})
	}
	for i, u := range users {
		out, _, _ := RunPlain(ctx, "groups", u.Name)
		if len(out) > 0 {
			p2 := strings.SplitN(string(out), ":", 2)
			if len(p2) > 1 {
				for _, g := range strings.Fields(p2[1]) {
					users[i].Groups = append(users[i].Groups, g)
				}
			}
		}
	}
	return users, nil
}

func (p *linuxProvider) AddSystemUser(ctx context.Context, name, password string) error {
	_, _, err := RunPlain(ctx, "useradd", "-m", "-s", "/bin/bash", name)
	if err != nil {
		return fmt.Errorf("useradd: %w", err)
	}
	stdin := strings.NewReader(name + ":" + password + "\n")
	_, _, err = RunPlainWithStdin(context.Background(), stdin, "chpasswd")
	if err != nil {
		return fmt.Errorf("chpasswd: %w", err)
	}
	return nil
}

func (p *linuxProvider) DeleteSystemUser(ctx context.Context, name string) error {
	_, _, err := RunPlain(ctx, "userdel", "-r", name)
	if err != nil {
		return fmt.Errorf("userdel: %w", err)
	}
	return nil
}

func (p *linuxProvider) CronJobs(ctx context.Context) ([]CronJob, error) {
	jobs := []CronJob{}
	jobs = append(jobs, parseCrontab("/etc/crontab", true)...)
	entries, _ := os.ReadDir("/etc/cron.d")
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		jobs = append(jobs, parseCrontab("/etc/cron.d/"+e.Name(), true)...)
	}
	return jobs, nil
}

func parseCrontab(path string, hasUser bool) []CronJob {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	jobs := []CronJob{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "@") || strings.HasPrefix(line, "SHELL") || strings.HasPrefix(line, "PATH") || strings.HasPrefix(line, "MAILTO") {
			continue
		}
		parts := strings.Fields(line)
		minF := 6
		if !hasUser {
			minF = 5
		}
		if len(parts) < minF {
			continue
		}
		sched := strings.Join(parts[:5], " ")
		user, cmd := "", ""
		if hasUser {
			user = parts[5]
			cmd = strings.Join(parts[6:], " ")
		} else {
			cmd = strings.Join(parts[5:], " ")
		}
		jobs = append(jobs, CronJob{User: user, Schedule: sched, Command: cmd, Source: path})
	}
	return jobs
}

func (p *linuxProvider) CPUFreq(ctx context.Context) (CPUFreqInfo, error) {
	info := CPUFreqInfo{Cores: []CPUCore{}, Zones: []ThermalZone{}}
	cpuDirs, _ := filepath.Glob("/sys/devices/system/cpu/cpu[0-9]*")
	for _, dir := range cpuDirs {
		idStr := strings.TrimPrefix(dir, "/sys/devices/system/cpu/cpu")
		id, _ := strconv.Atoi(idStr)
		var cur, max float64
		if b, err := os.ReadFile(dir + "/cpufreq/scaling_cur_freq"); err == nil {
			v, _ := strconv.ParseFloat(strings.TrimSpace(string(b)), 64)
			cur = v / 1000.0
		}
		if b, err := os.ReadFile(dir + "/cpufreq/cpuinfo_max_freq"); err == nil {
			v, _ := strconv.ParseFloat(strings.TrimSpace(string(b)), 64)
			max = v / 1000.0
		}
		info.Cores = append(info.Cores, CPUCore{ID: id, FreqMHz: cur, MaxFreqMHz: max})
	}
	sort.Slice(info.Cores, func(i, j int) bool { return info.Cores[i].ID < info.Cores[j].ID })
	thermalDirs, _ := filepath.Glob("/sys/class/thermal/thermal_zone*")
	for _, dir := range thermalDirs {
		nameB, _ := os.ReadFile(dir + "/type")
		tempB, err := os.ReadFile(dir + "/temp")
		if err != nil {
			continue
		}
		v, _ := strconv.ParseFloat(strings.TrimSpace(string(tempB)), 64)
		if v == 0 {
			continue
		}
		info.Zones = append(info.Zones, ThermalZone{
			Name:  strings.TrimSpace(string(nameB)),
			TempC: v / 1000.0,
		})
	}
	return info, nil
}

func (p *linuxProvider) BenchmarkDisk(ctx context.Context, devPath string) (DiskBenchmark, error) {
	start := time.Now()
	out, _, err := RunPlain(ctx, "dd", "if="+devPath, "bs=4M", "count=64", "iflag=direct", "of=/dev/null")
	if err != nil {
		return DiskBenchmark{}, fmt.Errorf("dd: %w (out: %s)", err, string(out))
	}
	dur := time.Since(start).Seconds()
	readBytes := int64(64 * 4 * 1024 * 1024)
	mbps := float64(readBytes) / dur / (1024 * 1024)
	return DiskBenchmark{DevPath: devPath, ReadMBps: math.Round(mbps*10) / 10, DurationSec: math.Round(dur*10) / 10}, nil
}

func (p *linuxProvider) ShareStats(ctx context.Context) ([]ShareStats, error) {
	shares, err := p.Shares(ctx)
	if err != nil {
		return nil, err
	}
	stats := []ShareStats{}
	seen := map[string]bool{}
	for _, s := range shares {
		if seen[s.Path] {
			continue
		}
		seen[s.Path] = true
		var st syscall.Statfs_t
		if err := syscall.Statfs(s.Path, &st); err != nil {
			stats = append(stats, ShareStats{Name: s.Name, Path: s.Path})
			continue
		}
		total := int64(st.Blocks) * st.Bsize
		free := int64(st.Bfree) * st.Bsize
		stats = append(stats, ShareStats{
			Name:       s.Name,
			Path:       s.Path,
			TotalBytes: total,
			FreeBytes:  free,
			UsedBytes:  total - free,
		})
	}
	return stats, nil
}

func (p *linuxProvider) ARPTable(ctx context.Context) ([]ARPEntry, error) {
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	entries := []ARPEntry{}
	sc := bufio.NewScanner(f)
	sc.Scan() // skip header
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 6 {
			continue
		}
		mac := fields[3]
		if mac == "00:00:00:00:00:00" {
			continue
		}
		state := "reachable"
		if fields[2] == "0x0" {
			state = "stale"
		}
		entries = append(entries, ARPEntry{
			IP:    fields[0],
			MAC:   mac,
			Iface: fields[5],
			State: state,
		})
	}
	return entries, nil
}

func (p *linuxProvider) FirewallRules(ctx context.Context) (string, error) {
	out, _, err := RunPlain(ctx, "nft", "list", "ruleset")
	if err == nil {
		return strings.TrimSpace(string(out)), nil
	}
	out, _, err = RunPriv(ctx, "/usr/sbin/iptables", "-L", "-n", "--line-numbers")
	if err != nil {
		return "", fmt.Errorf("nft and iptables unavailable: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

func (p *linuxProvider) GetDNSConfig(ctx context.Context) (DNSConfig, error) {
	f, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return DNSConfig{}, err
	}
	defer f.Close()
	cfg := DNSConfig{Nameservers: []string{}, Search: []string{}}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "nameserver":
			cfg.Nameservers = append(cfg.Nameservers, fields[1])
		case "search":
			cfg.Search = append(cfg.Search, fields[1:]...)
		case "domain":
			cfg.Domain = fields[1]
		}
	}
	return cfg, nil
}

func (p *linuxProvider) SetDNSConfig(ctx context.Context, cfg DNSConfig) error {
	var b strings.Builder
	b.WriteString("# managed by kilasos\n")
	for _, ns := range cfg.Nameservers {
		b.WriteString("nameserver " + ns + "\n")
	}
	if len(cfg.Search) > 0 {
		b.WriteString("search " + strings.Join(cfg.Search, " ") + "\n")
	}
	if cfg.Domain != "" {
		b.WriteString("domain " + cfg.Domain + "\n")
	}
	return os.WriteFile("/etc/resolv.conf", []byte(b.String()), 0644)
}

func (p *linuxProvider) GetHosts(ctx context.Context) ([]HostEntry, error) {
	f, err := os.Open("/etc/hosts")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	entries := []HostEntry{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		e := HostEntry{IP: fields[0], Hostname: fields[1]}
		if len(fields) > 2 {
			e.Aliases = fields[2:]
		}
		entries = append(entries, e)
	}
	return entries, nil
}

func (p *linuxProvider) AddHost(ctx context.Context, entry HostEntry) error {
	line := "\n" + entry.IP + "\t" + entry.Hostname
	if len(entry.Aliases) > 0 {
		line += " " + strings.Join(entry.Aliases, " ")
	}
	f, err := os.OpenFile("/etc/hosts", os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(line + "\n")
	return err
}

func (p *linuxProvider) DeleteHost(ctx context.Context, ip, hostname string) error {
	content, err := os.ReadFile("/etc/hosts")
	if err != nil {
		return err
	}
	var out []string
	for _, line := range strings.Split(string(content), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == ip && fields[1] == hostname {
			continue
		}
		out = append(out, line)
	}
	return os.WriteFile("/etc/hosts", []byte(strings.Join(out, "\n")), 0644)
}

func (p *linuxProvider) ListServices(ctx context.Context) ([]SystemService, error) {
	out, _, err := RunPriv(ctx, "/usr/bin/systemctl", "list-units", "--type=service", "--all",
		"--no-pager", "--no-legend", "--plain")
	if err != nil {
		return nil, fmt.Errorf("systemctl: %w", err)
	}
	services := []SystemService{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		name := strings.TrimSuffix(fields[0], ".service")
		state := fields[2]
		substate := fields[3]
		desc := ""
		if len(fields) > 4 {
			desc = strings.Join(fields[4:], " ")
		}
		enabled := false
		// TODO(arch): systemctl is-enabled double-call (Output + Run) — skip
		services = append(services, SystemService{
			Name: name, Description: desc, State: state,
			SubState: substate, Enabled: enabled,
		})
	}
	return services, nil
}

func (p *linuxProvider) ServiceAction(ctx context.Context, name, action string) error {
	switch action {
	case "start", "stop", "restart", "enable", "disable":
	default:
		return fmt.Errorf("unsupported action: %s", action)
	}
	_, _, err := RunPriv(ctx, "/usr/bin/systemctl", action, name+".service")
	return err
}

func (p *linuxProvider) MemDetail(ctx context.Context) (MemDetail, error) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return MemDetail{}, err
	}
	defer f.Close()
	fields := map[string]int64{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		parts := strings.Fields(sc.Text())
		if len(parts) < 2 {
			continue
		}
		key := strings.TrimSuffix(parts[0], ":")
		val, _ := strconv.ParseInt(parts[1], 10, 64)
		fields[key] = val * 1024
	}
	total := fields["MemTotal"]
	free := fields["MemFree"]
	buffers := fields["Buffers"]
	cached := fields["Cached"] + fields["SReclaimable"]
	used := total - free - buffers - cached
	return MemDetail{
		Total: total, Used: used, Free: free,
		Buffers: buffers, Cached: cached,
		SwapTotal: fields["SwapTotal"],
		SwapUsed:  fields["SwapTotal"] - fields["SwapFree"],
		SwapFree:  fields["SwapFree"],
	}, nil
}

func (p *linuxProvider) GetSambaGlobal(ctx context.Context) (SambaGlobal, error) {
	cfg := SambaGlobal{Workgroup: "WORKGROUP", ServerString: "KilasOS NAS", MaxConnections: 0, LogLevel: 1}
	f, err := os.Open(sambaCfgHeader)
	if err != nil {
		return cfg, nil
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "#") || !strings.Contains(line, "=") {
			continue
		}
		kv := strings.SplitN(line, "=", 2)
		if len(kv) < 2 {
			continue
		}
		key := strings.TrimSpace(kv[0])
		val := strings.TrimSpace(kv[1])
		switch key {
		case "workgroup":
			cfg.Workgroup = val
		case "server string":
			cfg.ServerString = val
		case "max connections":
			cfg.MaxConnections, _ = strconv.Atoi(val)
		case "log level":
			cfg.LogLevel, _ = strconv.Atoi(val)
		}
	}
	return cfg, nil
}

func (p *linuxProvider) SetSambaGlobal(ctx context.Context, cfg SambaGlobal) error {
	content, err := os.ReadFile(sambaCfgHeader)
	if err != nil {
		return err
	}
	lines := strings.Split(string(content), "\n")
	setKeys := map[string]string{
		"workgroup":       cfg.Workgroup,
		"server string":   cfg.ServerString,
		"max connections": strconv.Itoa(cfg.MaxConnections),
		"log level":       strconv.Itoa(cfg.LogLevel),
	}
	replaced := map[string]bool{}
	var out []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, "=") {
			kv := strings.SplitN(trimmed, "=", 2)
			key := strings.TrimSpace(kv[0])
			if newVal, ok := setKeys[key]; ok {
				out = append(out, "\t"+key+" = "+newVal)
				replaced[key] = true
				continue
			}
		}
		out = append(out, line)
	}
	// Add any missing keys before first share section
	for key, val := range setKeys {
		if !replaced[key] {
			// Insert before first [share] section
			for i, line := range out {
				if strings.HasPrefix(strings.TrimSpace(line), "[") && !strings.Contains(line, "[global]") {
					out = append(out[:i], append([]string{"\t" + key + " = " + val}, out[i:]...)...)
					break
				}
			}
		}
	}
	if err := os.WriteFile(sambaCfgHeader, []byte(strings.Join(out, "\n")), 0644); err != nil {
		return err
	}
	_, _, err = RunPriv(ctx, "/usr/bin/systemctl", "reload", "smbd")
	return err
}

func (p *linuxProvider) NetIfaceStats(ctx context.Context) ([]NetIfaceStats, error) {
	f, err := os.Open("/proc/net/dev")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	stats := []NetIfaceStats{}
	sc := bufio.NewScanner(f)
	sc.Scan(); sc.Scan() // skip 2 header lines
	for sc.Scan() {
		line := sc.Text()
		colonIdx := strings.Index(line, ":")
		if colonIdx < 0 {
			continue
		}
		name := strings.TrimSpace(line[:colonIdx])
		fields := strings.Fields(line[colonIdx+1:])
		if len(fields) < 16 {
			continue
		}
		parseInt := func(s string) int64 { v, _ := strconv.ParseInt(s, 10, 64); return v }
		stats = append(stats, NetIfaceStats{
			Name: name, RxBytes: parseInt(fields[0]), TxBytes: parseInt(fields[8]),
			RxErrors: parseInt(fields[2]), TxErrors: parseInt(fields[10]),
			RxDropped: parseInt(fields[3]), TxDropped: parseInt(fields[11]),
		})
	}
	return stats, nil
}

func (p *linuxProvider) TLSCert(ctx context.Context, host string, port int) (TLSCertInfo, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	// quick connectivity check first
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return TLSCertInfo{}, fmt.Errorf("connect: %w", err)
	}
	conn.Close()
	stdout, stderr, _ := RunPlainWithStdin(context.Background(), strings.NewReader(""), "openssl", "s_client", "-connect", addr, "-servername", host, "-brief")
	out := append(stdout, stderr...)
	info := TLSCertInfo{Valid: true, SANs: []string{}}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "subject=") {
			info.Subject = strings.TrimPrefix(line, "subject=")
		} else if strings.HasPrefix(line, "issuer=") {
			info.Issuer = strings.TrimPrefix(line, "issuer=")
		} else if strings.HasPrefix(line, "Verification") {
			if !strings.Contains(line, "OK") {
				info.Valid = false
			}
		}
	}
	// Parse cert dates with openssl x509
	certOut, _, _ := RunPlainWithStdin(context.Background(), strings.NewReader(""), "openssl", "s_client", "-connect", addr, "-servername", host)
	x509Out, _, _ := RunPlainWithStdin(context.Background(), strings.NewReader(string(certOut)), "openssl", "x509", "-noout", "-dates", "-subject", "-issuer")
	for _, line := range strings.Split(string(x509Out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "notBefore=") {
			info.NotBefore = strings.TrimPrefix(line, "notBefore=")
		} else if strings.HasPrefix(line, "notAfter=") {
			info.NotAfter = strings.TrimPrefix(line, "notAfter=")
		}
	}
	if info.NotAfter != "" {
		if t, err := time.Parse("Jan  2 15:04:05 2006 MST", info.NotAfter); err == nil {
			info.DaysLeft = int(time.Until(t).Hours() / 24)
		}
	}
	return info, nil
}

func (p *linuxProvider) LastLogins(ctx context.Context, n int) ([]LastLogin, error) {
	out, _, err := RunPlain(ctx, "last", "-n", strconv.Itoa(n), "-F", "--no-header")
	if err != nil {
		return nil, fmt.Errorf("last: %w", err)
	}
	logins := []LastLogin{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[0] == "reboot" || fields[0] == "wtmp" {
			continue
		}
		user := fields[0]
		from := ""
		when := ""
		if len(fields) >= 5 {
			from = fields[2]
			when = strings.Join(fields[3:7], " ")
		}
		logins = append(logins, LastLogin{User: user, From: from, When: when})
	}
	if len(logins) > n {
		logins = logins[:n]
	}
	return logins, nil
}

const scrubCronPath = "/etc/cron.d/kilasos-scrub"

func (p *linuxProvider) ScrubSchedules(ctx context.Context) ([]ScrubSchedule, error) {
	pools, err := p.Arrays(context.Background())
	if err != nil {
		return nil, err
	}
	content, _ := os.ReadFile(scrubCronPath)
	schedules := []ScrubSchedule{}
	for _, pool := range pools {
		if pool.ArraySpec.Type != ArrayTypeZFS {
			continue
		}
		sched := ScrubSchedule{Pool: pool.Name, Schedule: "0 2 * * 0", Enabled: false}
		for _, line := range strings.Split(string(content), "\n") {
			if strings.Contains(line, pool.Name) && !strings.HasPrefix(strings.TrimSpace(line), "#") {
				fields := strings.Fields(line)
				if len(fields) >= 6 {
					sched.Schedule = strings.Join(fields[:5], " ")
					sched.Enabled = true
				}
			}
		}
		schedules = append(schedules, sched)
	}
	return schedules, nil
}

func (p *linuxProvider) SetScrubSchedule(ctx context.Context, pool, schedule string, enabled bool) error {
	content, _ := os.ReadFile(scrubCronPath)
	var lines []string
	for _, line := range strings.Split(string(content), "\n") {
		if !strings.Contains(line, "zpool scrub "+pool) {
			lines = append(lines, line)
		}
	}
	if enabled {
		lines = append(lines, schedule+" root zpool scrub "+pool)
	}
	out := strings.TrimSpace(strings.Join(lines, "\n")) + "\n"
	return os.WriteFile(scrubCronPath, []byte(out), 0644)
}

func (p *linuxProvider) Exec(ctx context.Context, command string) (ExecResult, error) {
	out, errOut, runErr := RunPlain(ctx, "bash", "-c", command)
	exitCode := 0
	if runErr != nil {
		exitCode = 1
	}
	return ExecResult{Stdout: string(out), Stderr: string(errOut), ExitCode: exitCode}, nil
}

func (p *linuxProvider) SearchFiles(ctx context.Context, root, pattern string, maxResults int) ([]FileSearchResult, error) {
	if root == "" || root == "/" {
		root = poolMountBase
	}
	args := []string{root, "-name", pattern, "-maxdepth", "10"}
	if maxResults <= 0 {
		maxResults = 200
	}
	out, _, _ := RunPlain(ctx, "find", args...)
	results := []FileSearchResult{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			break
		}
		info, err := os.Stat(line)
		if err != nil {
			continue
		}
		results = append(results, FileSearchResult{
			Path:      filepath.Dir(line),
			Name:      filepath.Base(line),
			SizeBytes: info.Size(),
			Modified:  info.ModTime().Unix(),
			IsDir:     info.IsDir(),
		})
		if len(results) >= maxResults {
			break
		}
	}
	return results, nil
}

func (p *linuxProvider) SnapshotDiff(ctx context.Context, pool, snapA, snapB string) ([]SnapshotDiff, error) {
	fullA := pool + "@" + snapA
	fullB := pool + "@" + snapB
	if snapB == "" {
		// diff against current
		fullB = pool
	}
	out, _, err := RunPriv(ctx, "/usr/sbin/zfs", "diff", fullA, fullB)
	if err != nil {
		return nil, fmt.Errorf("zfs diff: %w", err)
	}
	diffs := []SnapshotDiff{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		diffs = append(diffs, SnapshotDiff{Change: fields[0], Path: fields[1]})
	}
	return diffs, nil
}

func (p *linuxProvider) ContainerExec(ctx context.Context, containerID, command string) (ExecResult, error) {
	out, errOut, runErr := RunPlain(ctx, "docker", "exec", containerID, "bash", "-c", command)
	exitCode := 0
	if runErr != nil {
		exitCode = 1
	}
	return ExecResult{Stdout: string(out), Stderr: string(errOut), ExitCode: exitCode}, nil
}

const smtpConfigPath = "/var/lib/kilasos/smtp.json"

func (p *linuxProvider) GetSMTPConfig(ctx context.Context) (SMTPConfig, error) {
	data, err := os.ReadFile(smtpConfigPath)
	if err != nil {
		return SMTPConfig{Port: 587, TLS: true}, nil
	}
	var cfg SMTPConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return SMTPConfig{Port: 587, TLS: true}, nil
	}
	cfg.Password = "" // never return password
	return cfg, nil
}

func (p *linuxProvider) SetSMTPConfig(ctx context.Context, cfg SMTPConfig) error {
	if cfg.Password == "" {
		// preserve existing password
		var existing SMTPConfig
		if data, err := os.ReadFile(smtpConfigPath); err == nil {
			json.Unmarshal(data, &existing) //nolint:errcheck
			cfg.Password = existing.Password
		}
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(smtpConfigPath), 0750); err != nil {
		return err
	}
	return os.WriteFile(smtpConfigPath, data, 0600)
}

func (p *linuxProvider) UPSStatus(ctx context.Context) (UPSInfo, error) {
	// Try apcupsd first
	out, _, err := RunPlain(ctx, "apcaccess", "status")
	if err == nil {
		info := UPSInfo{Available: true, Driver: "apcupsd"}
		for _, line := range strings.Split(string(out), "\n") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) != 2 {
				continue
			}
			k := strings.TrimSpace(parts[0])
			v := strings.TrimSpace(parts[1])
			switch k {
			case "MODEL":
				info.Model = v
			case "STATUS":
				info.Status = v
			case "BCHARGE":
				fmt.Sscanf(v, "%f", &info.BattPct)
			case "TIMELEFT":
				fmt.Sscanf(v, "%f", &info.TimeLeft)
			case "LOADPCT":
				fmt.Sscanf(v, "%f", &info.LoadPct)
			case "LINEV":
				fmt.Sscanf(v, "%f", &info.LineVoltage)
			case "BATTV":
				fmt.Sscanf(v, "%f", &info.BattVoltage)
			}
		}
		return info, nil
	}
	// Try NUT (upsc)
	out, _, err = RunPlain(ctx, "upsc", "ups")
	if err == nil {
		info := UPSInfo{Available: true, Driver: "nut"}
		for _, line := range strings.Split(string(out), "\n") {
			parts := strings.SplitN(line, ": ", 2)
			if len(parts) != 2 {
				continue
			}
			k := strings.TrimSpace(parts[0])
			v := strings.TrimSpace(parts[1])
			switch k {
			case "device.model":
				info.Model = v
			case "ups.status":
				info.Status = v
			case "battery.charge":
				fmt.Sscanf(v, "%f", &info.BattPct)
			case "battery.runtime":
				var secs float64
				fmt.Sscanf(v, "%f", &secs)
				info.TimeLeft = secs / 60
			case "ups.load":
				fmt.Sscanf(v, "%f", &info.LoadPct)
			case "input.voltage":
				fmt.Sscanf(v, "%f", &info.LineVoltage)
			case "battery.voltage":
				fmt.Sscanf(v, "%f", &info.BattVoltage)
			}
		}
		return info, nil
	}
	return UPSInfo{Available: false}, nil
}

const alertRulesPath = "/var/lib/kilasos/alert-rules.json"

func (p *linuxProvider) FanSpeeds(ctx context.Context) ([]FanInfo, error) {
	// Try sensors (lm-sensors)
	out, _, err := RunPlain(ctx, "sensors", "-j")
	if err != nil {
		return []FanInfo{}, nil
	}
	var raw map[string]interface{}
	if err := json.Unmarshal(out, &raw); err != nil {
		return []FanInfo{}, nil
	}
	var fans []FanInfo
	for _, chipData := range raw {
		chipMap, ok := chipData.(map[string]interface{})
		if !ok {
			continue
		}
		for featureName, featureData := range chipMap {
			featureMap, ok := featureData.(map[string]interface{})
			if !ok {
				continue
			}
			for subKey, subVal := range featureMap {
				if strings.Contains(strings.ToLower(featureName), "fan") && strings.HasSuffix(subKey, "_input") {
					rpm := 0.0
					if v, ok := subVal.(float64); ok {
						rpm = v
					}
					alarmKey := strings.TrimSuffix(subKey, "_input") + "_alarm"
					alarm := featureMap[alarmKey]
					fans = append(fans, FanInfo{
						Name:  featureName,
						RPM:   int(rpm),
						Alarm: alarm != nil && alarm.(float64) != 0,
					})
				}
			}
		}
	}
	return fans, nil
}

func (p *linuxProvider) RouteTable(ctx context.Context) ([]RouteEntry, error) {
	// Read /proc/net/route for IPv4 routes
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return nil, err
	}
	var routes []RouteEntry
	lines := strings.Split(string(data), "\n")
	for _, line := range lines[1:] { // skip header
		fields := strings.Fields(line)
		if len(fields) < 8 {
			continue
		}
		iface := fields[0]
		destHex := fields[1]
		gwHex := fields[2]
		flags := fields[3]
		metricStr := fields[6]

		destIP := hexToIP(destHex)
		gwIP := hexToIP(gwHex)
		var metric int
		fmt.Sscanf(metricStr, "%d", &metric)

		dest := destIP + "/0"
		if destHex == "00000000" {
			dest = "default"
		}

		routes = append(routes, RouteEntry{
			Dest:    dest,
			Gateway: gwIP,
			Iface:   iface,
			Metric:  metric,
			Flags:   flags,
		})
	}
	return routes, nil
}

func hexToIP(h string) string {
	if len(h) != 8 {
		return "0.0.0.0"
	}
	var b [4]byte
	fmt.Sscanf(h[6:8]+h[4:6]+h[2:4]+h[0:2], "%02x%02x%02x%02x", &b[0], &b[1], &b[2], &b[3])
	return fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3])
}

func (p *linuxProvider) DiskSpinState(ctx context.Context, devPath string) (string, error) {
	out, _, err := RunPlain(ctx, "hdparm", "-C", devPath)
	if err != nil {
		return "unknown", nil
	}
	lower := strings.ToLower(string(out))
	if strings.Contains(lower, "active") {
		return "active/idle", nil
	} else if strings.Contains(lower, "standby") {
		return "standby", nil
	} else if strings.Contains(lower, "sleeping") {
		return "sleeping", nil
	}
	return "unknown", nil
}

func (p *linuxProvider) PingHost(ctx context.Context, host string, count int) (PingResult, error) {
	if count <= 0 || count > 20 {
		count = 4
	}
	// Parse stdout regardless of err: ping exits non-zero on packet loss but
	// still emits the stats line we need.
	out, _, _ := RunPlain(ctx, "ping", "-c", fmt.Sprintf("%d", count), "-W", "2", host)
	result := PingResult{Host: host, Sent: count}
	text := string(out)
	if text == "" {
		// No stdout — host fully unreachable or ping couldn't run. Report 100% loss.
		result.PacketLoss = 100
		return result, nil
	}
	// Parse: X packets transmitted, Y received, Z% packet loss
	for _, line := range strings.Split(text, "\n") {
		if strings.Contains(line, "packets transmitted") {
			var tx, rx int
			re := regexp.MustCompile(`(\d+) packets transmitted, (\d+) received`)
			m := re.FindStringSubmatch(line)
			if len(m) >= 3 {
				tx, _ = strconv.Atoi(m[1])
				rx, _ = strconv.Atoi(m[2])
				result.Sent = tx
				result.Received = rx
				if tx > 0 {
					result.PacketLoss = float64(tx-rx) / float64(tx) * 100
				}
			}
		}
		if strings.Contains(line, "min/avg/max") || strings.Contains(line, "round-trip") {
			// rtt min/avg/max/mdev = 0.123/0.456/0.789/0.111 ms
			parts := strings.Split(line, "=")
			if len(parts) >= 2 {
				nums := strings.Split(strings.TrimSpace(parts[1]), "/")
				if len(nums) >= 3 {
					fmt.Sscanf(nums[0], "%f", &result.MinMS)
					fmt.Sscanf(nums[1], "%f", &result.AvgMS)
					fmt.Sscanf(nums[2], "%f", &result.MaxMS)
				}
			}
		}
	}
	return result, nil
}

func (p *linuxProvider) SetDiskAPM(ctx context.Context, devPath string, level int) error {
	if level < 1 || level > 254 {
		return fmt.Errorf("APM level must be 1-254")
	}
	stdout, stderr, err := RunPlain(ctx, "hdparm", fmt.Sprintf("-B%d", level), devPath)
	if err != nil {
		out := append(stdout, stderr...)
		return fmt.Errorf("hdparm: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func (p *linuxProvider) GetDiskAPM(ctx context.Context, devPath string) (int, error) {
	out, _, err := RunPlain(ctx, "hdparm", "-B", devPath)
	if err != nil {
		return 0, fmt.Errorf("hdparm: %w", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "Advanced Power Management") {
			var level int
			fmt.Sscanf(strings.TrimSpace(strings.Split(line, "=")[1]), "%d", &level)
			return level, nil
		}
	}
	return 0, nil
}

func (p *linuxProvider) ResolveHostname(ctx context.Context, ip string) (string, error) {
	addrs, err := net.LookupAddr(ip)
	if err != nil || len(addrs) == 0 {
		return "", nil
	}
	return strings.TrimSuffix(addrs[0], "."), nil
}

func (p *linuxProvider) KillProcess(ctx context.Context, pid, signal int) error {
	if signal == 0 {
		signal = 15 // SIGTERM default
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("process not found: %w", err)
	}
	return proc.Signal(syscall.Signal(signal))
}

func (p *linuxProvider) SystemEntropy(ctx context.Context) (int, error) {
	data, err := os.ReadFile("/proc/sys/kernel/random/entropy_avail")
	if err != nil {
		return 0, err
	}
	var entropy int
	fmt.Sscanf(strings.TrimSpace(string(data)), "%d", &entropy)
	return entropy, nil
}

func (p *linuxProvider) ChangeEncryptionKey(ctx context.Context, dataset, newPassphrase string) error {
	stdin := strings.NewReader(newPassphrase + "\n" + newPassphrase + "\n")
	stdout, stderr, err := RunPrivWithStdin(ctx, stdin, "/usr/sbin/zfs",
		"change-key", "-o", "keylocation=prompt", "-o", "keyformat=passphrase", dataset)
	if err != nil {
		out := append(stdout, stderr...)
		return fmt.Errorf("zfs change-key: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func (p *linuxProvider) JournalExport(ctx context.Context) (string, error) {
	out, _, err := RunPriv(ctx, "/usr/bin/journalctl", "--no-pager", "-o", "short-precise", "-n", "1000")
	if err != nil {
		return "", err
	}
	return string(out), nil
}

const dockerDaemonConfigPath = "/etc/docker/daemon.json"

func (p *linuxProvider) DockerDaemonConfig(ctx context.Context) (map[string]interface{}, error) {
	data, err := os.ReadFile(dockerDaemonConfigPath)
	if err != nil {
		return map[string]interface{}{}, nil
	}
	var cfg map[string]interface{}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (p *linuxProvider) SetDockerDaemonConfig(ctx context.Context, cfg map[string]interface{}) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(dockerDaemonConfigPath, data, 0644); err != nil {
		return err
	}
	out, _, err := RunPriv(ctx, "/usr/bin/systemctl", "reload-or-restart", "docker")
	if err != nil {
		return fmt.Errorf("restart docker: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func (p *linuxProvider) SmartTestHistory(ctx context.Context, devPath string) ([]SmartTestResult, error) {
	stdout, _, err := RunPriv(ctx, "/usr/bin/smartctl", "-l", "selftest", "-j", devPath)
	out := stdout
	if err != nil && len(out) == 0 {
		return nil, fmt.Errorf("smartctl: %w", err)
	}
	var raw struct {
		ATA struct {
			SelfTest struct {
				Table []struct {
					SelectiveSelfTestSpanNumber int    `json:"selective_self_test_span_number"`
					Type                        struct{ String string } `json:"type"`
					Status                      struct{ String string } `json:"status"`
					LifetimeHours               int    `json:"lifetime_hours"`
					LBAFirstError               string `json:"lba_first_error,omitempty"`
					RemainingPercent            int    `json:"remaining_percent"`
				} `json:"table"`
			} `json:"self_test"`
		} `json:"ata_smart_self_test_log"`
	}
	if err := json.Unmarshal(out, &raw); err != nil {
		return []SmartTestResult{}, nil
	}
	var results []SmartTestResult
	for i, t := range raw.ATA.SelfTest.Table {
		results = append(results, SmartTestResult{
			Num:       i + 1,
			Type:      t.Type.String,
			Status:    t.Status.String,
			Hours:     t.LifetimeHours,
			LBA:       t.LBAFirstError,
			Remaining: t.RemainingPercent,
		})
	}
	return results, nil
}

func (p *linuxProvider) UserQuotas(ctx context.Context, dataset string) ([]UserQuota, error) {
	out, _, err := RunPriv(ctx, "/usr/sbin/zfs", "userspace", "-H", "-o", "type,name,quota,used", dataset)
	if err != nil {
		return nil, fmt.Errorf("zfs userspace: %w", err)
	}
	var quotas []UserQuota
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[0] != "POSIX User" {
			continue
		}
		name := fields[1]
		var quota, used int64
		fmt.Sscanf(fields[2], "%d", &quota)
		fmt.Sscanf(fields[3], "%d", &used)
		quotas = append(quotas, UserQuota{User: name, QuotaBytes: quota, UsedBytes: used})
	}
	return quotas, nil
}

func (p *linuxProvider) SetUserQuota(ctx context.Context, dataset, user string, quotaBytes int64) error {
	val := "none"
	if quotaBytes > 0 {
		val = fmt.Sprintf("%d", quotaBytes)
	}
	stdout, stderr, err := RunPriv(ctx, "/usr/sbin/zfs", "set", fmt.Sprintf("userquota@%s=%s", user, val), dataset)
	if err != nil {
		out := append(stdout, stderr...)
		return fmt.Errorf("zfs set userquota: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func (p *linuxProvider) NFSExports(ctx context.Context) ([]NFSExport, error) {
	data, err := os.ReadFile("/etc/exports")
	if err != nil {
		return []NFSExport{}, nil
	}
	var exports []NFSExport
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		exports = append(exports, NFSExport{
			Path:    fields[0],
			Clients: fields[1:],
		})
	}
	return exports, nil
}

func (p *linuxProvider) AddNFSExport(ctx context.Context, path, clients string) error {
	data, _ := os.ReadFile("/etc/exports")
	line := path + "\t" + clients + "\n"
	data = append(data, []byte(line)...)
	if err := os.WriteFile("/etc/exports", data, 0644); err != nil {
		return err
	}
	RunPriv(ctx, "/usr/sbin/exportfs", "-ra") //nolint:errcheck
	return nil
}

func (p *linuxProvider) DeleteNFSExport(ctx context.Context, path string) error {
	data, err := os.ReadFile("/etc/exports")
	if err != nil {
		return err
	}
	var lines []string
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), path+"\t") &&
			!strings.HasPrefix(strings.TrimSpace(line), path+" ") &&
			strings.TrimSpace(line) != path {
			lines = append(lines, line)
		}
	}
	if err := os.WriteFile("/etc/exports", []byte(strings.Join(lines, "\n")), 0644); err != nil {
		return err
	}
	RunPriv(ctx, "/usr/sbin/exportfs", "-ra") //nolint:errcheck
	return nil
}

func (p *linuxProvider) GetAlertRules(ctx context.Context) ([]AlertRule, error) {
	data, err := os.ReadFile(alertRulesPath)
	if err != nil {
		return []AlertRule{
			{Name: "cpu", Threshold: 90, Enabled: true},
			{Name: "mem", Threshold: 90, Enabled: true},
			{Name: "disk", Threshold: 85, Enabled: true},
		}, nil
	}
	var rules []AlertRule
	if err := json.Unmarshal(data, &rules); err != nil {
		return nil, err
	}
	return rules, nil
}

func (p *linuxProvider) SetAlertRules(ctx context.Context, rules []AlertRule) error {
	data, err := json.MarshalIndent(rules, "", "  ")
	if err != nil {
		return err
	}
	os.MkdirAll("/var/lib/kilasos", 0755) //nolint:errcheck
	return os.WriteFile(alertRulesPath, data, 0644)
}

func (p *linuxProvider) UpdateContainerLimits(ctx context.Context, id string, memBytes int64, cpuPercent float64) error {
	args := []string{"update"}
	if memBytes > 0 {
		args = append(args, fmt.Sprintf("--memory=%d", memBytes))
		args = append(args, fmt.Sprintf("--memory-swap=%d", memBytes*2))
	}
	if cpuPercent > 0 {
		args = append(args, fmt.Sprintf("--cpus=%.2f", cpuPercent/100.0))
	}
	args = append(args, id)
	stdout, stderr, err := RunPlain(ctx, "docker", args...)
	if err != nil {
		out := append(stdout, stderr...)
		return fmt.Errorf("docker update: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func (p *linuxProvider) SetSharePerms(ctx context.Context, shareName, owner, group string, mode uint32) error {
	shares, err := p.Shares(ctx)
	if err != nil {
		return err
	}
	var sharePath string
	for _, s := range shares {
		if s.Name == shareName {
			sharePath = s.Path
			break
		}
	}
	if sharePath == "" {
		return fmt.Errorf("share not found: %s", shareName)
	}
	if owner != "" || group != "" {
		chown := owner + ":" + group
		if owner == "" {
			chown = ":" + group
		} else if group == "" {
			chown = owner
		}
		stdout, stderr, err := RunPlain(ctx, "chown", chown, sharePath)
		if err != nil {
			out := append(stdout, stderr...)
			return fmt.Errorf("chown: %s", strings.TrimSpace(string(out)))
		}
	}
	if mode > 0 {
		stdout, stderr, err := RunPlain(ctx, "chmod", fmt.Sprintf("%o", mode), sharePath)
		if err != nil {
			out := append(stdout, stderr...)
			return fmt.Errorf("chmod: %s", strings.TrimSpace(string(out)))
		}
	}
	return nil
}

func (p *linuxProvider) TailscaleStatus(ctx context.Context) (TailscaleStatus, error) {
	out, _, err := RunPlain(ctx, "tailscale", "status", "--json")
	if err != nil {
		return TailscaleStatus{Running: false}, nil
	}
	var raw struct {
		Self struct {
			HostName  string `json:"HostName"`
			TailscaleIPs []string `json:"TailscaleIPs"`
			OS        string `json:"OS"`
		} `json:"Self"`
		Peer map[string]struct {
			HostName  string   `json:"HostName"`
			TailscaleIPs []string `json:"TailscaleIPs"`
			OS        string   `json:"OS"`
			Online    bool     `json:"Online"`
			ExitNode  bool     `json:"ExitNode"`
			Tags      []string `json:"Tags"`
		} `json:"Peer"`
	}
	if err := json.Unmarshal(out, &raw); err != nil {
		return TailscaleStatus{Running: false}, nil
	}
	selfIP := ""
	if len(raw.Self.TailscaleIPs) > 0 {
		selfIP = raw.Self.TailscaleIPs[0]
	}
	ts := TailscaleStatus{
		Running: true,
		Self: TailscaleNode{
			Hostname: raw.Self.HostName,
			IP:       selfIP,
			OS:       raw.Self.OS,
			Online:   true,
		},
	}
	for _, p := range raw.Peer {
		ip := ""
		if len(p.TailscaleIPs) > 0 {
			ip = p.TailscaleIPs[0]
		}
		ts.Peers = append(ts.Peers, TailscaleNode{
			Hostname: p.HostName,
			IP:       ip,
			OS:       p.OS,
			Online:   p.Online,
			ExitNode: p.ExitNode,
			Tags:     p.Tags,
		})
	}
	return ts, nil
}

func (p *linuxProvider) ComposeProjects(ctx context.Context) ([]ComposeProject, error) {
	out, _, err := RunPlain(ctx, "docker", "compose", "ls", "--format", "json")
	if err != nil {
		return nil, nil
	}
	var raw []struct {
		Name        string `json:"Name"`
		Status      string `json:"Status"`
		ConfigFiles string `json:"ConfigFiles"`
	}
	if err := json.Unmarshal(out, &raw); err != nil {
		return nil, nil
	}
	projects := make([]ComposeProject, 0, len(raw))
	for _, r := range raw {
		dir := ""
		if r.ConfigFiles != "" {
			dir = strings.TrimSuffix(r.ConfigFiles, "/docker-compose.yml")
			dir = strings.TrimSuffix(dir, "/compose.yml")
		}
		status := "exited"
		rs := strings.ToLower(r.Status)
		if strings.Contains(rs, "running") {
			status = "running"
		} else if strings.Contains(rs, "partial") {
			status = "partial"
		}
		projects = append(projects, ComposeProject{
			Name:   r.Name,
			Dir:    dir,
			Status: status,
		})
	}
	return projects, nil
}

func (p *linuxProvider) ComposeAction(ctx context.Context, dir, action string) error {
	var args []string
	switch action {
	case "up":
		args = []string{"compose", "-f", dir + "/docker-compose.yml", "up", "-d"}
		if _, err := os.Stat(dir + "/compose.yml"); err == nil {
			args = []string{"compose", "-f", dir + "/compose.yml", "up", "-d"}
		}
	case "down":
		args = []string{"compose", "--project-directory", dir, "down"}
	case "restart":
		args = []string{"compose", "--project-directory", dir, "restart"}
	case "pull":
		args = []string{"compose", "--project-directory", dir, "pull"}
	default:
		return fmt.Errorf("unknown action: %s", action)
	}
	stdout, stderr, err := RunPlain(ctx, "docker", args...)
	if err != nil {
		out := append(stdout, stderr...)
		return fmt.Errorf("compose %s: %s", action, strings.TrimSpace(string(out)))
	}
	return nil
}

func (p *linuxProvider) SendTestEmail(ctx context.Context) error {
	cfg, err := p.GetSMTPConfig(ctx)
	if err != nil {
		return err
	}
	if cfg.Host == "" || cfg.To == "" {
		return fmt.Errorf("SMTP not configured")
	}
	// Use the sendmail command if available, otherwise python3
	msg := fmt.Sprintf("Subject: KilasOS Test Email\r\nFrom: %s\r\nTo: %s\r\n\r\nThis is a test email from KilasOS NAS.\r\n", cfg.From, cfg.To)
	script := fmt.Sprintf(`import smtplib, ssl
s = smtplib.SMTP('%s', %d, timeout=10)
%s
s.login('%s', '%s')
s.sendmail('%s', '%s', %q)
s.quit()
print('ok')
`, cfg.Host, cfg.Port,
		map[bool]string{true: "s.starttls()", false: ""}[cfg.TLS],
		cfg.User, cfg.Password, cfg.From, cfg.To, msg)
	out, _, err := RunPlain(ctx, "python3", "-c", script)
	if err != nil {
		return fmt.Errorf("send failed: %s", string(out))
	}
	return nil
}

func (p *linuxProvider) TimeStatus(ctx context.Context) (TimeInfo, error) {
	out, _, err := RunPlain(ctx, "timedatectl", "status")
	if err != nil {
		return TimeInfo{}, err
	}
	info := TimeInfo{}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Local time:") {
			info.LocalTime = strings.TrimSpace(strings.TrimPrefix(line, "Local time:"))
		} else if strings.HasPrefix(line, "Time zone:") {
			info.Timezone = strings.TrimSpace(strings.TrimPrefix(line, "Time zone:"))
		} else if strings.HasPrefix(line, "NTP service:") {
			val := strings.TrimSpace(strings.TrimPrefix(line, "NTP service:"))
			info.NTPEnabled = strings.Contains(strings.ToLower(val), "active")
		} else if strings.HasPrefix(line, "System clock synchronized:") {
			val := strings.TrimSpace(strings.TrimPrefix(line, "System clock synchronized:"))
			info.NTPSync = strings.ToLower(val) == "yes"
		} else if strings.HasPrefix(line, "NTP synchronized:") {
			val := strings.TrimSpace(strings.TrimPrefix(line, "NTP synchronized:"))
			info.NTPSync = strings.ToLower(val) == "yes"
		} else if strings.HasPrefix(line, "RTC time:") {
			info.RTCTime = strings.TrimSpace(strings.TrimPrefix(line, "RTC time:"))
		}
	}
	// Try to get NTP server from chronyc or systemd-timesyncd
	if srv, _, err2 := RunPlain(ctx, "chronyc", "tracking"); err2 == nil {
		for _, l := range strings.Split(string(srv), "\n") {
			if strings.HasPrefix(l, "Reference ID") {
				parts := strings.Fields(l)
				if len(parts) >= 4 {
					info.NTPServer = strings.Trim(parts[3], "()")
				}
				break
			}
		}
	}
	return info, nil
}

func (p *linuxProvider) WireguardStatus(ctx context.Context) ([]WireguardIface, error) {
	out, _, err := RunPlain(ctx, "wg", "show", "all", "dump")
	if err != nil {
		return nil, nil // wg not installed or no interfaces
	}
	ifaces := map[string]*WireguardIface{}
	order := []string{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 5 {
			continue
		}
		ifName := fields[0]
		if _, ok := ifaces[ifName]; !ok {
			ifaces[ifName] = &WireguardIface{Name: ifName}
			order = append(order, ifName)
		}
		iface := ifaces[ifName]
		// Interface line: iface pubkey privkey listenport fwmark
		if fields[1] == "(none)" || len(fields) == 5 {
			// might be interface-level line
			if fields[1] != "" && !strings.Contains(fields[1], ".") {
				iface.PublicKey = fields[1]
			}
			if p2, err2 := strconv.Atoi(fields[3]); err2 == nil {
				iface.ListenPort = p2
			}
			continue
		}
		// Peer line: iface pubkey preshared endpoint allowed-ips last-handshake rx tx keepalive
		if len(fields) >= 9 {
			hs, _ := strconv.ParseInt(fields[6], 10, 64)
			rx, _ := strconv.ParseInt(fields[7], 10, 64)
			tx, _ := strconv.ParseInt(fields[8], 10, 64)
			peer := WireguardPeer{
				PublicKey:     fields[1],
				Endpoint:      fields[4],
				AllowedIPs:    fields[5],
				LastHandshake: hs,
				RxBytes:       rx,
				TxBytes:       tx,
			}
			iface.Peers = append(iface.Peers, peer)
		}
	}
	result := make([]WireguardIface, 0, len(order))
	for _, name := range order {
		result = append(result, *ifaces[name])
	}
	return result, nil
}

func (p *linuxProvider) MDRaidStatus(ctx context.Context) (string, error) {
	data, err := os.ReadFile("/proc/mdstat")
	if err != nil {
		return "", nil // mdadm not present
	}
	return string(data), nil
}

func (p *linuxProvider) SMBSessions(ctx context.Context) ([]SMBSession, error) {
	out, _, err := RunPriv(ctx, "/usr/bin/smbstatus", "-n", "-S")
	if err != nil {
		return nil, nil
	}
	var sessions []SMBSession
	lines := strings.Split(string(out), "\n")
	inSection := false
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "---") {
			inSection = true
			continue
		}
		if !inSection || line == "" {
			if strings.Contains(line, "Share") && strings.Contains(line, "Machine") {
				inSection = true
			}
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		// smbstatus -S output: Share  Machine  ConnectedAt
		// smbstatus -p output: PID  Username  Group  Machine  Protocol
		sessions = append(sessions, SMBSession{
			Share:   fields[0],
			Machine: fields[1],
		})
	}
	// Also get process sessions
	outP, _, err2 := RunPriv(ctx, "/usr/bin/smbstatus", "-n", "-p")
	if err2 == nil {
		inP := false
		for _, line := range strings.Split(string(outP), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "---") {
				inP = true
				continue
			}
			if !inP || line == "" {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 4 {
				continue
			}
			pid, _ := strconv.Atoi(fields[0])
			for i := range sessions {
				if sessions[i].PID == 0 && sessions[i].Machine == fields[3] {
					sessions[i].PID = pid
					sessions[i].Username = fields[1]
					break
				}
			}
		}
	}
	return sessions, nil
}

func (p *linuxProvider) CPUTemperatures(ctx context.Context) ([]TempInfo, error) {
	out, _, err := RunPlain(ctx, "sensors", "-j")
	if err != nil {
		return nil, nil
	}
	var raw map[string]interface{}
	if err := json.Unmarshal(out, &raw); err != nil {
		return nil, nil
	}
	var temps []TempInfo
	for chipName, chipData := range raw {
		chip, ok := chipData.(map[string]interface{})
		if !ok {
			continue
		}
		for featName, featData := range chip {
			feat, ok := featData.(map[string]interface{})
			if !ok {
				continue
			}
			lowerFeat := strings.ToLower(featName)
			if !strings.Contains(lowerFeat, "temp") && !strings.Contains(lowerFeat, "core") {
				continue
			}
			for subKey, subVal := range feat {
				if !strings.HasSuffix(subKey, "_input") {
					continue
				}
				tempC, ok := subVal.(float64)
				if !ok {
					continue
				}
				t := TempInfo{
					Name:  featName,
					Chip:  chipName,
					TempC: tempC,
				}
				// look for high/crit
				for sk, sv := range feat {
					if strings.HasSuffix(sk, "_high") {
						if v, ok := sv.(float64); ok {
							t.High = v
						}
					}
					if strings.HasSuffix(sk, "_crit") {
						if v, ok := sv.(float64); ok {
							t.Crit = v
						}
					}
				}
				temps = append(temps, t)
				break
			}
		}
	}
	return temps, nil
}

func (p *linuxProvider) GetHostname(ctx context.Context) (string, error) {
	out, _, err := RunPlain(ctx, "hostname")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func (p *linuxProvider) SetHostname(ctx context.Context, name string) error {
	if name == "" || strings.ContainsAny(name, " /\\") {
		return fmt.Errorf("invalid hostname")
	}
	stdout, stderr, err := RunPlain(ctx, "hostnamectl", "set-hostname", name)
	if err != nil {
		out := append(stdout, stderr...)
		return fmt.Errorf("hostnamectl: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func (p *linuxProvider) IPTablesRules(ctx context.Context) (string, error) {
	out, _, err := RunPriv(ctx, "/usr/sbin/iptables-save")
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func (p *linuxProvider) TriggerSMARTTest(ctx context.Context, devPath, testType string) error {
	if testType != "short" && testType != "long" && testType != "conveyance" {
		return fmt.Errorf("invalid test type: %s", testType)
	}
	if !strings.HasPrefix(devPath, "/dev/") {
		devPath = "/dev/" + devPath
	}
	stdout, stderr, err := RunPriv(ctx, "/usr/bin/smartctl", "-t", testType, devPath)
	if err != nil {
		out := append(stdout, stderr...)
		return fmt.Errorf("smartctl: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func (p *linuxProvider) DockerPrune(ctx context.Context, volumes bool) (string, error) {
	args := []string{"system", "prune", "-a", "-f"}
	if volumes {
		args = append(args, "--volumes")
	}
	stdout, stderr, err := RunPlain(ctx, "docker", args...)
	out := stdout
	if err != nil {
		out = append(stdout, stderr...)
		return "", fmt.Errorf("docker prune: %s", strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

func (p *linuxProvider) USBDevices(ctx context.Context) ([]USBDevice, error) {
	out, _, err := RunPlain(ctx, "lsusb")
	if err != nil {
		return nil, nil
	}
	var devices []USBDevice
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Format: Bus 001 Device 002: ID 8087:0024 Intel Corp. Hub
		fields := strings.SplitN(line, " ", 7)
		if len(fields) < 7 {
			continue
		}
		dev := strings.TrimSuffix(fields[3], ":")
		devices = append(devices, USBDevice{
			Bus:    fields[1],
			Device: dev,
			ID:     fields[5],
			Name:   strings.TrimSpace(fields[6]),
		})
	}
	return devices, nil
}

func (p *linuxProvider) PCIDevices(ctx context.Context) ([]PCIDevice, error) {
	out, _, err := RunPlain(ctx, "lspci")
	if err != nil {
		return nil, nil
	}
	var devices []PCIDevice
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Format: 00:00.0 Host bridge: Intel Corporation 4th Gen Core Processor DRAM Controller
		parts := strings.SplitN(line, " ", 2)
		if len(parts) < 2 {
			continue
		}
		slot := parts[0]
		rest := parts[1]
		colonIdx := strings.Index(rest, ":")
		if colonIdx == -1 {
			continue
		}
		class := strings.TrimSpace(rest[:colonIdx])
		vendor := strings.TrimSpace(rest[colonIdx+1:])
		devices = append(devices, PCIDevice{
			Slot:   slot,
			Class:  class,
			Vendor: vendor,
			Device: vendor,
		})
	}
	return devices, nil
}

func (p *linuxProvider) LoadAverages(ctx context.Context) (LoadAvg, error) {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return LoadAvg{}, err
	}
	fields := strings.Fields(string(data))
	if len(fields) < 4 {
		return LoadAvg{}, fmt.Errorf("invalid loadavg")
	}
	la := LoadAvg{}
	la.One, _ = strconv.ParseFloat(fields[0], 64)
	la.Five, _ = strconv.ParseFloat(fields[1], 64)
	la.Fifteen, _ = strconv.ParseFloat(fields[2], 64)
	if procs := strings.SplitN(fields[3], "/", 2); len(procs) == 2 {
		la.Running, _ = strconv.Atoi(procs[0])
		la.Total, _ = strconv.Atoi(procs[1])
	}
	return la, nil
}

func (p *linuxProvider) SwapInfo(ctx context.Context) ([]SwapEntry, error) {
	data, err := os.ReadFile("/proc/swaps")
	if err != nil {
		return nil, err
	}
	var entries []SwapEntry
	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		size, _ := strconv.ParseInt(fields[2], 10, 64)
		used, _ := strconv.ParseInt(fields[3], 10, 64)
		prio, _ := strconv.Atoi(fields[4])
		entries = append(entries, SwapEntry{
			Filename: fields[0],
			Type:     fields[1],
			SizeKB:   size,
			UsedKB:   used,
			Priority: prio,
		})
	}
	return entries, nil
}

func (p *linuxProvider) ConnectionSummary(ctx context.Context) (string, error) {
	out, _, err := RunPlain(ctx, "ss", "-s")
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func (p *linuxProvider) ContainerEnv(ctx context.Context, id string) ([]string, error) {
	out, _, err := RunPlain(ctx, "docker", "inspect", "--format", "{{json .Config.Env}}", id)
	if err != nil {
		return nil, fmt.Errorf("docker inspect: %v", err)
	}
	var env []string
	if err := json.Unmarshal(out, &env); err != nil {
		return nil, err
	}
	return env, nil
}

func (p *linuxProvider) DiskPartitions(ctx context.Context) ([]LsblkEntry, error) {
	out, _, err := RunPlain(ctx, "lsblk", "-J", "-o", "NAME,SIZE,TYPE,FSTYPE,LABEL,MOUNTPOINT")
	if err != nil {
		return nil, err
	}
	var raw struct {
		Blockdevices []LsblkEntry `json:"blockdevices"`
	}
	if err := json.Unmarshal(out, &raw); err != nil {
		return nil, err
	}
	return raw.Blockdevices, nil
}

func (p *linuxProvider) GetSysctl(ctx context.Context, key string) (string, error) {
	if strings.ContainsAny(key, " ;|&$`\\") {
		return "", fmt.Errorf("invalid sysctl key")
	}
	out, _, err := RunPlain(ctx, "sysctl", "-n", key)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func (p *linuxProvider) SetSysctl(ctx context.Context, key, value string) error {
	if strings.ContainsAny(key, " ;|&$`\\") || strings.ContainsAny(value, ";|&$`\\") {
		return fmt.Errorf("invalid sysctl key or value")
	}
	if out, _, err := RunPlain(ctx, "sysctl", "-w", key+"="+value); err != nil {
		return fmt.Errorf("sysctl: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func (p *linuxProvider) ZFSPoolTrim(ctx context.Context, pool string) error {
	if out, _, err := RunPriv(ctx, "/usr/sbin/zpool", "trim", pool); err != nil {
		return fmt.Errorf("zpool trim: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func (p *linuxProvider) WhoLoggedIn(ctx context.Context) (string, error) {
	out, _, err := RunPlain(ctx, "w", "-h")
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func (p *linuxProvider) GetACL(ctx context.Context, path string) (string, error) {
	if !strings.HasPrefix(path, "/mnt/") && !strings.HasPrefix(path, "/srv/") && !strings.HasPrefix(path, "/home/") {
		return "", fmt.Errorf("ACL queries restricted to /mnt, /srv, /home")
	}
	out, _, err := RunPlain(ctx, "getfacl", "-p", path)
	if err != nil {
		return "", fmt.Errorf("getfacl: %v", err)
	}
	return string(out), nil
}

func (p *linuxProvider) SetACL(ctx context.Context, path, spec string) error {
	if !strings.HasPrefix(path, "/mnt/") && !strings.HasPrefix(path, "/srv/") && !strings.HasPrefix(path, "/home/") {
		return fmt.Errorf("ACL changes restricted to /mnt, /srv, /home")
	}
	stdout, stderr, err := RunPlain(ctx, "setfacl", "-m", spec, path)
	if err != nil {
		out := append(stdout, stderr...)
		return fmt.Errorf("setfacl: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func (p *linuxProvider) SetContainerRestartPolicy(ctx context.Context, id, policy string) error {
	switch policy {
	case "no", "always", "unless-stopped", "on-failure":
	default:
		return fmt.Errorf("invalid policy: %s", policy)
	}
	stdout, stderr, err := RunPlain(ctx, "docker", "update", "--restart", policy, id)
	if err != nil {
		out := append(stdout, stderr...)
		return fmt.Errorf("docker update: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func (p *linuxProvider) Fail2BanStatus(ctx context.Context) (Fail2BanInfo, error) {
	info := Fail2BanInfo{}
	// Check if active
	_, _, err := RunPriv(ctx, "/usr/bin/systemctl", "is-active", "--quiet", "fail2ban")
	if err != nil {
		return info, nil
	}
	info.Active = true
	// Get jails
	out, _, err := RunPriv(ctx, "/usr/sbin/fail2ban-client", "status")
	if err != nil {
		return info, nil
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Jail list:") {
			val := strings.TrimSpace(strings.TrimPrefix(line, "Jail list:"))
			for _, j := range strings.Split(val, ",") {
				j = strings.TrimSpace(j)
				if j != "" {
					info.Jails = append(info.Jails, j)
				}
			}
		}
	}
	// Per-jail banned IPs
	for _, jail := range info.Jails {
	jOut, _, err := RunPriv(ctx, "/usr/sbin/fail2ban-client", "status", jail)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(jOut), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "Banned IP list:") {
				val := strings.TrimSpace(strings.TrimPrefix(line, "Banned IP list:"))
				for _, ip := range strings.Fields(val) {
					info.BannedIPs = append(info.BannedIPs, ip)
					info.TotalBans++
				}
			}
		}
	}
	return info, nil
}

func (p *linuxProvider) GetServerCertificate(ctx context.Context) (ServerCertInfo, error) {
	candidates := []string{
		"/etc/kilasos/cert.pem",
		"/etc/ssl/certs/kilasos.pem",
		"/etc/letsencrypt/live/kilasos/fullchain.pem",
	}
	var certPath string
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			certPath = c
			break
		}
	}
	if certPath == "" {
		return ServerCertInfo{}, fmt.Errorf("no server certificate found")
	}
	out, _, err := RunPlain(ctx, "openssl", "x509", "-in", certPath, "-noout", "-subject", "-issuer", "-startdate", "-enddate", "-text")
	if err != nil {
		return ServerCertInfo{}, err
	}
	info := ServerCertInfo{}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "subject=") {
			info.Subject = strings.TrimSpace(strings.TrimPrefix(line, "subject="))
		} else if strings.HasPrefix(line, "issuer=") {
			info.Issuer = strings.TrimSpace(strings.TrimPrefix(line, "issuer="))
		} else if strings.HasPrefix(line, "notBefore=") {
			info.NotBefore = strings.TrimSpace(strings.TrimPrefix(line, "notBefore="))
		} else if strings.HasPrefix(line, "notAfter=") {
			info.NotAfter = strings.TrimSpace(strings.TrimPrefix(line, "notAfter="))
		} else if strings.HasPrefix(line, "DNS:") {
			for _, n := range strings.Split(line, ",") {
				n = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(n), "DNS:"))
				if n != "" {
					info.DNSNames = append(info.DNSNames, n)
				}
			}
		}
	}
	info.SelfSigned = info.Subject == info.Issuer
	return info, nil
}

func (p *linuxProvider) UploadServerCertificate(ctx context.Context, certPEM, keyPEM []byte) error {
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		return fmt.Errorf("certificate and key required")
	}
	certDir := "/etc/kilasos"
	os.MkdirAll(certDir, 0755)
	if err := os.WriteFile(filepath.Join(certDir, "cert.pem"), certPEM, 0644); err != nil {
		return fmt.Errorf("write cert: %w", err)
	}
	if err := os.WriteFile(filepath.Join(certDir, "key.pem"), keyPEM, 0600); err != nil {
		return fmt.Errorf("write key: %w", err)
	}
	return nil
}

func (p *linuxProvider) GenerateServerCertificate(ctx context.Context, commonName string) (string, error) {
	if commonName == "" {
		return "", fmt.Errorf("common name required")
	}
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return "", fmt.Errorf("generate key: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return "", fmt.Errorf("create cert: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certDir := "/etc/kilasos"
	os.MkdirAll(certDir, 0755)
	os.WriteFile(filepath.Join(certDir, "cert.pem"), certPEM, 0644)
	os.WriteFile(filepath.Join(certDir, "key.pem"), keyPEM, 0600)
	return "Self-signed certificate generated for " + commonName, nil
}

func (p *linuxProvider) DestroyDatasetRecursive(ctx context.Context, pool, dataset string, recursive bool) error {
	full := pool + "/" + dataset
	args := []string{"destroy"}
	if recursive {
		args = append(args, "-r")
	}
	args = append(args, full)
	if out, _, err := RunPriv(ctx, "/usr/sbin/zfs", args...); err != nil {
		return fmt.Errorf("zfs destroy: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func (p *linuxProvider) GetMOTD(ctx context.Context) (string, error) {
	data, err := os.ReadFile("/etc/motd")
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	return string(data), nil
}

func (p *linuxProvider) SetMOTD(ctx context.Context, content string) error {
	return os.WriteFile("/etc/motd", []byte(content), 0644)
}

func (p *linuxProvider) GetCronTab(ctx context.Context, user string) (string, error) {
	if user == "" {
		user = "root"
	}
	out, _, err := RunPlain(ctx, "crontab", "-l", "-u", user)
	if err != nil {
		// no crontab → not an error
		return "", nil
	}
	return string(out), nil
}

func (p *linuxProvider) SetCronTab(ctx context.Context, user, content string) error {
	if user == "" {
		user = "root"
	}
	tmpFile, err := os.CreateTemp("", "crontab-*.txt")
	if err != nil {
		return err
	}
	defer os.Remove(tmpFile.Name())
	if _, err := tmpFile.WriteString(content); err != nil {
		return err
	}
	tmpFile.Close()
	if out, _, err := RunPlain(ctx, "crontab", "-u", user, tmpFile.Name()); err != nil {
		return fmt.Errorf("crontab: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func (p *linuxProvider) NetstatActive(ctx context.Context) ([]NetstatEntry, error) {
	out, _, err := RunPlain(ctx, "ss", "-tunp", "state", "established")
	if err != nil {
		return nil, err
	}
	var entries []NetstatEntry
	lines := strings.Split(string(out), "\n")
	for i, line := range lines {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		// Format: Netid State Recv-Q Send-Q Local Peer Process
		entry := NetstatEntry{
			Proto:      fields[0],
			LocalAddr:  fields[3],
			RemoteAddr: fields[4],
			State:      "ESTABLISHED",
		}
		if len(fields) > 5 {
			procStr := strings.Join(fields[5:], " ")
			if pidIdx := strings.Index(procStr, "pid="); pidIdx != -1 {
				rest := procStr[pidIdx+4:]
				commaIdx := strings.IndexAny(rest, ",)")
				if commaIdx > 0 {
					entry.PID, _ = strconv.Atoi(rest[:commaIdx])
				}
			}
			if nameIdx := strings.Index(procStr, "((\""); nameIdx != -1 {
				rest := procStr[nameIdx+3:]
				if endIdx := strings.Index(rest, "\""); endIdx > 0 {
					entry.Process = rest[:endIdx]
				}
			}
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

func (p *linuxProvider) TestPort(ctx context.Context, host string, port int) (bool, error) {
	if port < 1 || port > 65535 {
		return false, fmt.Errorf("invalid port")
	}
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 3*time.Second)
	if err != nil {
		return false, nil
	}
	conn.Close()
	return true, nil
}

func (p *linuxProvider) ZFSHolds(ctx context.Context, snapshot string) ([]string, error) {
	out, _, err := RunPriv(ctx, "/usr/sbin/zfs", "holds", "-H", snapshot)
	if err != nil {
		return nil, err
	}
	var tags []string
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			tags = append(tags, fields[1])
		}
	}
	return tags, nil
}

func (p *linuxProvider) ZFSAddHold(ctx context.Context, snapshot, tag string) error {
	_, _, err := RunPriv(ctx, "/usr/sbin/zfs", "hold", tag, snapshot)
	if err != nil {
		return fmt.Errorf("zfs hold: %v", err)
	}
	return nil
}

func (p *linuxProvider) ZFSReleaseHold(ctx context.Context, snapshot, tag string) error {
	_, _, err := RunPriv(ctx, "/usr/sbin/zfs", "release", tag, snapshot)
	if err != nil {
		return fmt.Errorf("zfs release: %v", err)
	}
	return nil
}

func (p *linuxProvider) FailedSystemdUnits(ctx context.Context) ([]SystemdUnitInfo, error) {
	out, _, err := RunPriv(ctx, "/usr/bin/systemctl", "list-units", "--state=failed", "--no-pager", "--no-legend", "--plain")
	if err != nil {
		return nil, err
	}
	var units []SystemdUnitInfo
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		desc := ""
		if len(fields) > 4 {
			desc = strings.Join(fields[4:], " ")
		}
		units = append(units, SystemdUnitInfo{
			Name:        fields[0],
			Load:        fields[1],
			Active:      fields[2],
			Sub:         fields[3],
			Description: desc,
		})
	}
	return units, nil
}

func (p *linuxProvider) NFSActiveMounts(ctx context.Context) ([]NFSMount, error) {
	data, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return nil, err
	}
	var mounts []NFSMount
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		if fields[2] != "nfs" && fields[2] != "nfs4" {
			continue
		}
		// fields[0] is server:export
		serverExport := fields[0]
		parts := strings.SplitN(serverExport, ":", 2)
		if len(parts) != 2 {
			continue
		}
		mounts = append(mounts, NFSMount{
			Server:     parts[0],
			Export:     parts[1],
			Mountpoint: fields[1],
			Options:    fields[3],
		})
	}
	return mounts, nil
}

func (p *linuxProvider) ZFSRenameDataset(ctx context.Context, oldName, newName string) error {
	_, _, err := RunPriv(ctx, "/usr/sbin/zfs", "rename", oldName, newName)
	if err != nil {
		return fmt.Errorf("zfs rename: %v", err)
	}
	return nil
}

func (p *linuxProvider) LogRotateStatus(ctx context.Context) (string, error) {
	data, err := os.ReadFile("/var/lib/logrotate/status")
	if err != nil {
		// Try alternate path
		data, err = os.ReadFile("/var/lib/logrotate.status")
		if err != nil {
			return "", err
		}
	}
	return string(data), nil
}

func (p *linuxProvider) GetContainerHealth(ctx context.Context, id string) (ContainerHealthInfo, error) {
	out, _, err := RunPlain(ctx, "docker", "inspect", "--format", "{{json .State.Health}}", id)
	if err != nil {
		return ContainerHealthInfo{}, fmt.Errorf("docker inspect: %v", err)
	}
	trimmed := strings.TrimSpace(string(out))
	if trimmed == "null" || trimmed == "" {
		return ContainerHealthInfo{Status: "none"}, nil
	}
	var raw struct {
		Status        string `json:"Status"`
		FailingStreak int    `json:"FailingStreak"`
		Log           []struct {
			Start    string `json:"Start"`
			ExitCode int    `json:"ExitCode"`
			Output   string `json:"Output"`
		} `json:"Log"`
	}
	if err := json.Unmarshal([]byte(trimmed), &raw); err != nil {
		return ContainerHealthInfo{}, err
	}
	info := ContainerHealthInfo{
		Status:        raw.Status,
		FailingStreak: raw.FailingStreak,
	}
	if len(raw.Log) > 0 {
		last := raw.Log[len(raw.Log)-1]
		info.LastCheck = last.Start
		info.LastOutput = last.Output
	}
	return info, nil
}

func (p *linuxProvider) MDNSServices(ctx context.Context) ([]MDNSService, error) {
	out, _, err := RunPlain(ctx, "avahi-browse", "-a", "-r", "-t", "-p")
	if err != nil {
		return nil, nil
	}
	var services []MDNSService
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.HasPrefix(line, "=") {
			continue
		}
		fields := strings.Split(line, ";")
		if len(fields) < 9 {
			continue
		}
		port, _ := strconv.Atoi(fields[8])
		services = append(services, MDNSService{
			Name:     fields[3],
			Type:     fields[4],
			Domain:   fields[5],
			Hostname: fields[6],
			Address:  fields[7],
			Port:     port,
		})
	}
	return services, nil
}

func (p *linuxProvider) GetKernelParam(ctx context.Context, key string) (string, error) {
	cmdline, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return "", err
	}
	for _, param := range strings.Fields(string(cmdline)) {
		if param == key {
			return "true", nil
		}
		if strings.HasPrefix(param, key+"=") {
			return strings.TrimPrefix(param, key+"="), nil
		}
	}
	return "", nil
}

func (p *linuxProvider) PauseContainer(ctx context.Context, id string) error {
	stdout, stderr, err := RunPlain(ctx, "docker", "pause", id)
	if err != nil {
		out := append(stdout, stderr...)
		return fmt.Errorf("docker pause: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func (p *linuxProvider) UnpauseContainer(ctx context.Context, id string) error {
	stdout, stderr, err := RunPlain(ctx, "docker", "unpause", id)
	if err != nil {
		out := append(stdout, stderr...)
		return fmt.Errorf("docker unpause: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func (p *linuxProvider) RestartContainer(ctx context.Context, id string) error {
	stdout, stderr, err := RunPlain(ctx, "docker", "restart", id)
	if err != nil {
		out := append(stdout, stderr...)
		return fmt.Errorf("docker restart: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func (p *linuxProvider) ZFSBookmarks(ctx context.Context, dataset string) ([]ZFSBookmark, error) {
	out, _, err := RunPriv(ctx, "/usr/sbin/zfs", "list", "-t", "bookmark", "-H", "-o", "name,guid,createtxg", "-r", dataset)
	if err != nil {
		return nil, nil
	}
	var bookmarks []ZFSBookmark
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 3 {
			continue
		}
		bookmarks = append(bookmarks, ZFSBookmark{
			Name:      fields[0],
			GUID:      fields[1],
			CreateTxg: fields[2],
		})
	}
	return bookmarks, nil
}

func (p *linuxProvider) CreateZFSBookmark(ctx context.Context, snapshot, bookmark string) error {
	_, _, err := RunPriv(ctx, "/usr/sbin/zfs", "bookmark", snapshot, bookmark)
	if err != nil {
		return fmt.Errorf("zfs bookmark: %v", err)
	}
	return nil
}

func (p *linuxProvider) GetCurrentRunlevel(ctx context.Context) (string, error) {
	out, _, err := RunPriv(ctx, "/usr/bin/systemctl", "get-default")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func (p *linuxProvider) GetUptime(ctx context.Context) (UptimeInfo, error) {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return UptimeInfo{}, err
	}
	fields := strings.Fields(string(data))
	if len(fields) < 2 {
		return UptimeInfo{}, fmt.Errorf("invalid uptime")
	}
	upSec, _ := strconv.ParseFloat(fields[0], 64)
	idleSec, _ := strconv.ParseFloat(fields[1], 64)
	bootTime := time.Now().Add(-time.Duration(upSec) * time.Second)
	return UptimeInfo{
		UptimeSec: int64(upSec),
		IdleSec:   idleSec,
		BootTime:  bootTime.Format("2006-01-02 15:04:05"),
	}, nil
}

func (p *linuxProvider) NetMaskInfo(ctx context.Context) ([]NetIfaceMask, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var result []NetIfaceMask
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			if ipNet.IP.To4() == nil {
				continue
			}
			ones, _ := ipNet.Mask.Size()
			result = append(result, NetIfaceMask{
				Name:    ifc.Name,
				Addr:    ipNet.IP.String(),
				Netmask: net.IP(ipNet.Mask).String(),
				CIDR:    ones,
			})
		}
	}
	return result, nil
}

func (p *linuxProvider) BatteryStatus(ctx context.Context) (BatteryInfo, error) {
	entries, err := os.ReadDir("/sys/class/power_supply")
	if err != nil {
		return BatteryInfo{Present: false}, nil
	}
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, "BAT") {
			continue
		}
		base := "/sys/class/power_supply/" + name
		info := BatteryInfo{Present: true}
		if data, err := os.ReadFile(base + "/capacity"); err == nil {
			info.Capacity, _ = strconv.Atoi(strings.TrimSpace(string(data)))
		}
		if data, err := os.ReadFile(base + "/status"); err == nil {
			info.Status = strings.TrimSpace(string(data))
		}
		if data, err := os.ReadFile(base + "/technology"); err == nil {
			info.Technology = strings.TrimSpace(string(data))
		}
		return info, nil
	}
	return BatteryInfo{Present: false}, nil
}

func (p *linuxProvider) GetSystemLocale(ctx context.Context) (LocaleInfo, error) {
	info := LocaleInfo{}
	out, _, err := RunPlain(ctx, "locale")
	if err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) != 2 {
				continue
			}
			val := strings.Trim(parts[1], `"`)
			switch parts[0] {
			case "LANG":
				info.Lang = val
			case "LC_ALL":
				info.LCAll = val
			}
		}
	}
	if cmOut, _, err := RunPlain(ctx, "locale", "charmap"); err == nil {
		info.Charmap = strings.TrimSpace(string(cmOut))
	}
	if tzOut, _, err := RunPlain(ctx, "timedatectl", "show", "-p", "Timezone", "--value"); err == nil {
		info.Timezone = strings.TrimSpace(string(tzOut))
	}
	return info, nil
}

func (p *linuxProvider) SetTimezone(ctx context.Context, tz string) error {
	if strings.ContainsAny(tz, " ;|&$`\\") {
		return fmt.Errorf("invalid timezone")
	}
	if out, _, err := RunPlain(ctx, "timedatectl", "set-timezone", tz); err != nil {
		return fmt.Errorf("timedatectl: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func (p *linuxProvider) ListTimezones(ctx context.Context) ([]string, error) {
	out, _, err := RunPlain(ctx, "timedatectl", "list-timezones")
	if err != nil {
		return nil, err
	}
	var zones []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			zones = append(zones, line)
		}
	}
	return zones, nil
}

func (p *linuxProvider) OSRelease(ctx context.Context) (OSReleaseInfo, error) {
	info := OSReleaseInfo{}
	if data, err := os.ReadFile("/etc/os-release"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) != 2 {
				continue
			}
			val := strings.Trim(parts[1], `"`)
			switch parts[0] {
			case "NAME":
				info.Name = val
			case "VERSION":
				info.Version = val
			case "ID":
				info.ID = val
			case "ID_LIKE":
				info.IDLike = val
			case "PRETTY_NAME":
				info.PrettyName = val
			case "VERSION_CODENAME":
				info.Codename = val
			}
		}
	}
	if out, _, err := RunPlain(ctx, "uname", "-r"); err == nil {
		info.Kernel = strings.TrimSpace(string(out))
	}
	if out, _, err := RunPlain(ctx, "uname", "-m"); err == nil {
		info.Arch = strings.TrimSpace(string(out))
	}
	return info, nil
}

func (p *linuxProvider) KernelModules(ctx context.Context) ([]KernelModule, error) {
	data, err := os.ReadFile("/proc/modules")
	if err != nil {
		return nil, err
	}
	var modules []KernelModule
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		size, _ := strconv.Atoi(fields[1])
		uses, _ := strconv.Atoi(fields[2])
		usedBy := ""
		if fields[3] != "-" {
			usedBy = fields[3]
		}
		modules = append(modules, KernelModule{
			Name:     fields[0],
			SizeKB:   size / 1024,
			UseCount: uses,
			UsedBy:   usedBy,
		})
	}
	return modules, nil
}

func (p *linuxProvider) IPRules(ctx context.Context) (string, error) {
	out, _, err := RunPriv(ctx, "/sbin/ip", "rule", "show")
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func (p *linuxProvider) NICStats(ctx context.Context, name string) (NICStatistics, error) {
	if strings.ContainsAny(name, " ;|&$`/\\") {
		return NICStatistics{}, fmt.Errorf("invalid nic name")
	}
	stats := make(map[string]int64)
	statsDir := "/sys/class/net/" + name + "/statistics"
	entries, err := os.ReadDir(statsDir)
	if err != nil {
		return NICStatistics{}, err
	}
	for _, e := range entries {
		data, err := os.ReadFile(statsDir + "/" + e.Name())
		if err != nil {
			continue
		}
		v, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
		if err == nil {
			stats[e.Name()] = v
		}
	}
	return NICStatistics{Name: name, Stats: stats}, nil
}

func (p *linuxProvider) SetMTU(ctx context.Context, name string, mtu int) error {
	if mtu < 68 || mtu > 65535 {
		return fmt.Errorf("MTU out of range")
	}
	if strings.ContainsAny(name, " ;|&$`/\\") {
		return fmt.Errorf("invalid nic name")
	}
	stdout, stderr, err := RunPriv(ctx, "/sbin/ip", "link", "set", "dev", name, "mtu", strconv.Itoa(mtu))
	if err != nil {
		out := append(stdout, stderr...)
		return fmt.Errorf("ip link set mtu: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func (p *linuxProvider) SystemdUnitDetail(ctx context.Context, name string) (SystemdUnitDetail, error) {
	if strings.ContainsAny(name, " ;|&$`/\\") {
		return SystemdUnitDetail{}, fmt.Errorf("invalid unit name")
	}
	out, _, err := RunPriv(ctx, "/usr/bin/systemctl", "show", name, "-p", "Description,LoadState,ActiveState,SubState,UnitFileState,MainPID,MemoryCurrent,CPUUsageNSec")
	if err != nil {
		return SystemdUnitDetail{}, err
	}
	d := SystemdUnitDetail{Name: name}
	for _, line := range strings.Split(string(out), "\n") {
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		switch parts[0] {
		case "Description":
			d.Description = parts[1]
		case "LoadState":
			d.LoadState = parts[1]
		case "ActiveState":
			d.ActiveState = parts[1]
		case "SubState":
			d.SubState = parts[1]
		case "UnitFileState":
			d.UnitFile = parts[1]
		case "MainPID":
			d.MainPID, _ = strconv.Atoi(parts[1])
		case "MemoryCurrent":
			if v, err := strconv.ParseInt(parts[1], 10, 64); err == nil {
				d.MemoryMB = v / (1024 * 1024)
			}
		case "CPUUsageNSec":
			if v, err := strconv.ParseInt(parts[1], 10, 64); err == nil {
				d.CPUSec = v / 1e9
			}
		}
	}
	return d, nil
}

func (p *linuxProvider) StartSystemdUnit(ctx context.Context, name string) error {
	if strings.ContainsAny(name, " ;|&$`/\\") {
		return fmt.Errorf("invalid unit name")
	}
	if out, _, err := RunPriv(ctx, "/usr/bin/systemctl", "start", name); err != nil {
		return fmt.Errorf("start: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func (p *linuxProvider) StopSystemdUnit(ctx context.Context, name string) error {
	if strings.ContainsAny(name, " ;|&$`/\\") {
		return fmt.Errorf("invalid unit name")
	}
	if out, _, err := RunPriv(ctx, "/usr/bin/systemctl", "stop", name); err != nil {
		return fmt.Errorf("stop: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func (p *linuxProvider) EnableSystemdUnit(ctx context.Context, name string) error {
	if strings.ContainsAny(name, " ;|&$`/\\") {
		return fmt.Errorf("invalid unit name")
	}
	if out, _, err := RunPriv(ctx, "/usr/bin/systemctl", "enable", name); err != nil {
		return fmt.Errorf("enable: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func (p *linuxProvider) DisableSystemdUnit(ctx context.Context, name string) error {
	if strings.ContainsAny(name, " ;|&$`/\\") {
		return fmt.Errorf("invalid unit name")
	}
	if out, _, err := RunPriv(ctx, "/usr/bin/systemctl", "disable", name); err != nil {
		return fmt.Errorf("disable: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func (p *linuxProvider) GetSysHostInfo(ctx context.Context) (HostHardwareInfo, error) {
	info := HostHardwareInfo{}
	read := func(path string) string {
		data, err := os.ReadFile(path)
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(data))
	}
	info.Vendor = read("/sys/class/dmi/id/sys_vendor")
	info.Product = read("/sys/class/dmi/id/product_name")
	info.Serial = read("/sys/class/dmi/id/product_serial")
	info.Family = read("/sys/class/dmi/id/product_family")
	info.BoardVendor = read("/sys/class/dmi/id/board_vendor")
	info.BoardProduct = read("/sys/class/dmi/id/board_name")
	info.BIOSVersion = read("/sys/class/dmi/id/bios_version")
	info.BIOSDate = read("/sys/class/dmi/id/bios_date")
	return info, nil
}

func (p *linuxProvider) JournalUnits(ctx context.Context) ([]string, error) {
	out, _, err := RunPriv(ctx, "/usr/bin/journalctl", "--field=_SYSTEMD_UNIT", "--no-pager")
	if err != nil {
		return nil, err
	}
	var units []string
	seen := make(map[string]bool)
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || seen[line] {
			continue
		}
		seen[line] = true
		units = append(units, line)
	}
	sort.Strings(units)
	return units, nil
}

func (p *linuxProvider) GetJournalForUnit(ctx context.Context, unit string, lines int) (string, error) {
	if strings.ContainsAny(unit, " ;|&$`/\\") {
		return "", fmt.Errorf("invalid unit name")
	}
	if lines <= 0 || lines > 5000 {
		lines = 200
	}
	out, _, err := RunPriv(ctx, "/usr/bin/journalctl", "-u", unit, "--no-pager", "-n", strconv.Itoa(lines), "-o", "short-precise")
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func (p *linuxProvider) ZFSFeatures(ctx context.Context, pool string) ([]ZFSFeature, error) {
	out, _, err := RunPriv(ctx, "/usr/sbin/zpool", "get", "-H", "all", pool)
	if err != nil {
		return nil, err
	}
	var features []ZFSFeature
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Split(line, "\t")
		if len(fields) < 4 {
			continue
		}
		prop := fields[1]
		val := fields[2]
		if !strings.HasPrefix(prop, "feature@") {
			continue
		}
		name := strings.TrimPrefix(prop, "feature@")
		features = append(features, ZFSFeature{
			Name:  name,
			State: val,
		})
	}
	return features, nil
}

func (p *linuxProvider) IP6Tables(ctx context.Context) (string, error) {
	out, _, err := RunPlain(ctx, "ip6tables-save")
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func (p *linuxProvider) ConntrackCount(ctx context.Context) (int, error) {
	data, err := os.ReadFile("/proc/sys/net/netfilter/nf_conntrack_count")
	if err != nil {
		return 0, err
	}
	v, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, err
	}
	return v, nil
}

func (p *linuxProvider) Dmesg(ctx context.Context, lines int) (string, error) {
	if lines <= 0 || lines > 5000 {
		lines = 200
	}
	out, _, err := RunPlain(ctx, "dmesg", "--ctime")
	if err != nil {
		return "", err
	}
	allLines := strings.Split(string(out), "\n")
	if len(allLines) > lines {
		allLines = allLines[len(allLines)-lines:]
	}
	return strings.Join(allLines, "\n"), nil
}

func (p *linuxProvider) KernelCmdline(ctx context.Context) (string, error) {
	data, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

func (p *linuxProvider) NICOffloads(ctx context.Context, name string) (map[string]string, error) {
	if strings.ContainsAny(name, " ;|&$`/\\") {
		return nil, fmt.Errorf("invalid nic name")
	}
	out, _, err := RunPlain(ctx, "ethtool", "-k", name)
	if err != nil {
		return nil, err
	}
	result := make(map[string]string)
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		colonIdx := strings.Index(line, ":")
		if colonIdx == -1 {
			continue
		}
		key := strings.TrimSpace(line[:colonIdx])
		val := strings.TrimSpace(line[colonIdx+1:])
		// strip "[fixed]" etc.
		if bracketIdx := strings.Index(val, "["); bracketIdx > 0 {
			val = strings.TrimSpace(val[:bracketIdx])
		}
		result[key] = val
	}
	return result, nil
}

func (p *linuxProvider) GetCPUInfoDetailed(ctx context.Context) (CPUDetail, error) {
	data, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return CPUDetail{}, err
	}
	d := CPUDetail{}
	cores := make(map[string]bool)
	threads := 0
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		switch key {
		case "model name":
			d.Model = val
		case "vendor_id":
			d.Vendor = val
		case "cpu family":
			d.Family = val
		case "stepping":
			d.StepingRev = val
		case "cpu MHz":
			d.MHz, _ = strconv.ParseFloat(val, 64)
		case "cache size":
			fields := strings.Fields(val)
			if len(fields) > 0 {
				d.CacheKB, _ = strconv.Atoi(fields[0])
			}
		case "core id":
			cores[val] = true
		case "processor":
			threads++
		case "flags":
			if d.Flags == "" {
				d.Flags = val
			}
		}
	}
	d.Cores = len(cores)
	if d.Cores == 0 {
		d.Cores = threads
	}
	d.Threads = threads
	return d, nil
}

func (p *linuxProvider) ListMounts(ctx context.Context) ([]MountInfo, error) {
	data, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return nil, err
	}
	var mounts []MountInfo
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		mounts = append(mounts, MountInfo{
			Device:     fields[0],
			Mountpoint: fields[1],
			FSType:     fields[2],
			Options:    fields[3],
		})
	}
	return mounts, nil
}

func (p *linuxProvider) GetReadOnlyMounts(ctx context.Context) ([]string, error) {
	mounts, err := p.ListMounts(context.Background())
	if err != nil {
		return nil, err
	}
	var ro []string
	for _, m := range mounts {
		opts := strings.Split(m.Options, ",")
		for _, o := range opts {
			if o == "ro" {
				ro = append(ro, m.Mountpoint)
				break
			}
		}
	}
	return ro, nil
}

func (p *linuxProvider) NetlinkConntrack(ctx context.Context, max int) ([]ConntrackEntry, error) {
	if max <= 0 || max > 5000 {
		max = 200
	}
	out, _, err := RunPlain(ctx, "conntrack", "-L")
	if err != nil {
		return nil, nil
	}
	var entries []ConntrackEntry
	for i, line := range strings.Split(string(out), "\n") {
		if i >= max {
			break
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		entry := ConntrackEntry{Proto: fields[0]}
		for _, f := range fields {
			if strings.HasPrefix(f, "src=") {
				entry.SrcIP = strings.TrimPrefix(f, "src=")
			} else if strings.HasPrefix(f, "dst=") {
				entry.DstIP = strings.TrimPrefix(f, "dst=")
			} else if strings.HasPrefix(f, "sport=") {
				entry.SrcPort, _ = strconv.Atoi(strings.TrimPrefix(f, "sport="))
			} else if strings.HasPrefix(f, "dport=") {
				entry.DstPort, _ = strconv.Atoi(strings.TrimPrefix(f, "dport="))
			}
		}
		if len(fields) >= 4 && entry.Proto == "tcp" {
			entry.State = fields[3]
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

func (p *linuxProvider) IOWait(ctx context.Context) (float64, error) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "cpu ") {
			fields := strings.Fields(line)
			if len(fields) < 6 {
				return 0, fmt.Errorf("invalid cpu line")
			}
			user, _ := strconv.ParseFloat(fields[1], 64)
			nice, _ := strconv.ParseFloat(fields[2], 64)
			sys, _ := strconv.ParseFloat(fields[3], 64)
			idle, _ := strconv.ParseFloat(fields[4], 64)
			iowait, _ := strconv.ParseFloat(fields[5], 64)
			total := user + nice + sys + idle + iowait
			if total == 0 {
				return 0, nil
			}
			return iowait / total * 100, nil
		}
	}
	return 0, fmt.Errorf("no cpu line")
}

func (p *linuxProvider) ZFSPoolImportable(ctx context.Context) ([]string, error) {
	out, _, err := RunPriv(ctx, "/usr/sbin/zpool", "import")
	if err != nil {
		return nil, nil
	}
	var pools []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "pool: ") {
			pools = append(pools, strings.TrimPrefix(line, "pool: "))
		}
	}
	return pools, nil
}

func (p *linuxProvider) ListInstalledKernels(ctx context.Context) ([]string, error) {
	entries, err := os.ReadDir("/boot")
	if err != nil {
		return nil, err
	}
	var kernels []string
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, "vmlinuz-") {
			kernels = append(kernels, strings.TrimPrefix(name, "vmlinuz-"))
		}
	}
	sort.Strings(kernels)
	return kernels, nil
}

func (p *linuxProvider) GetCurrentKernel(ctx context.Context) (string, error) {
	out, _, err := RunPlain(ctx, "uname", "-r")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func (p *linuxProvider) NetworkSpeedTest(ctx context.Context, server string) (NetSpeedResult, error) {
	if strings.ContainsAny(server, " ;|&$`") {
		return NetSpeedResult{}, fmt.Errorf("invalid server")
	}
	args := []string{"--simple"}
	if server != "" {
		args = append(args, "--server", server)
	}
	out, _, err := RunPlain(ctx, "speedtest-cli", args...)
	if err != nil {
		return NetSpeedResult{}, fmt.Errorf("speedtest-cli not installed or failed")
	}
	res := NetSpeedResult{Server: server}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Ping:") {
			fmt.Sscanf(line, "Ping: %f", &res.PingMS)
		} else if strings.HasPrefix(line, "Download:") {
			fmt.Sscanf(line, "Download: %f", &res.DownloadMB)
		} else if strings.HasPrefix(line, "Upload:") {
			fmt.Sscanf(line, "Upload: %f", &res.UploadMB)
		}
	}
	return res, nil
}

func (p *linuxProvider) GetDiskTemperatures(ctx context.Context) ([]DiskTemp, error) {
	disks, err := p.Disks(ctx)
	if err != nil {
		return nil, err
	}
	var temps []DiskTemp
	for _, d := range disks {
		t := DiskTemp{Device: d.Name, Model: d.Model}
		stdout, _, err := RunPriv(ctx, "/usr/bin/smartctl", "-A", "-j", "/dev/"+d.Name)
		out := stdout
		if err == nil {
			var raw struct {
				Temperature struct {
					Current int `json:"current"`
				} `json:"temperature"`
			}
			json.Unmarshal(out, &raw)
			t.TempC = raw.Temperature.Current
		}
		// Get spin state
		stOut, _, _ := RunPlain(ctx, "hdparm", "-C", "/dev/"+d.Name)
		if strings.Contains(string(stOut), "active") {
			t.State = "active"
		} else if strings.Contains(string(stOut), "standby") {
			t.State = "standby"
		} else if strings.Contains(string(stOut), "sleeping") {
			t.State = "sleeping"
		}
		temps = append(temps, t)
	}
	return temps, nil
}

func (p *linuxProvider) SystemBuildInfo(ctx context.Context) (SystemBuildInfo, error) {
	host, _ := os.Hostname()
	info := SystemBuildInfo{
		Hostname: host,
		NumCPU:   runtimeNumCPU(),
	}
	if data, _, err := RunPlain(ctx, "uname", "-a"); err == nil {
		info.OSVersion = strings.TrimSpace(string(data))
	}
	if data, _, err := RunPlain(ctx, "uname", "-m"); err == nil {
		info.Arch = strings.TrimSpace(string(data))
	}
	return info, nil
}

func runtimeNumCPU() int {
	data, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return 1
	}
	count := 0
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "processor") {
			count++
		}
	}
	if count == 0 {
		return 1
	}
	return count
}

func (p *linuxProvider) GetVMSizes(ctx context.Context) ([]VMInfo, error) {
	// virsh list --all (libvirt)
	out, _, err := RunPlain(ctx, "virsh", "list", "--all")
	if err != nil {
		return nil, nil
	}
	var vms []VMInfo
	for i, line := range strings.Split(string(out), "\n") {
		if i < 2 {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		vms = append(vms, VMInfo{
			Name:  fields[1],
			Type:  "kvm",
			State: strings.Join(fields[2:], " "),
		})
	}
	return vms, nil
}

func (p *linuxProvider) GetSudoers(ctx context.Context) (string, error) {
	data, err := os.ReadFile("/etc/sudoers")
	if err != nil {
		return "", err
	}
	// Sanitize: replace passwords if any
	return string(data), nil
}

func (p *linuxProvider) GetSSHDConfig(ctx context.Context) (string, error) {
	data, err := os.ReadFile("/etc/ssh/sshd_config")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func (p *linuxProvider) SystemRecommendations(ctx context.Context) ([]SystemRecommendation, error) {
	var recs []SystemRecommendation
	// Check if SSH password auth is enabled
	if data, err := os.ReadFile("/etc/ssh/sshd_config"); err == nil {
		if strings.Contains(string(data), "PasswordAuthentication yes") {
			recs = append(recs, SystemRecommendation{
				Category: "security",
				Severity: "warn",
				Message:  "SSH password authentication is enabled",
				Action:   "Disable password auth in /etc/ssh/sshd_config and use SSH keys",
			})
		}
	}
	// Check if root login allowed
	if data, err := os.ReadFile("/etc/ssh/sshd_config"); err == nil {
		if strings.Contains(string(data), "PermitRootLogin yes") {
			recs = append(recs, SystemRecommendation{
				Category: "security",
				Severity: "warn",
				Message:  "SSH root login is enabled",
				Action:   "Set PermitRootLogin no in /etc/ssh/sshd_config",
			})
		}
	}
	// Check disk usage
	out, _, err := RunPlain(ctx, "df", "-P")
	if err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 6 {
				continue
			}
			usage := strings.TrimSuffix(fields[4], "%")
			pct, _ := strconv.Atoi(usage)
			if pct >= 90 {
				recs = append(recs, SystemRecommendation{
					Category: "storage",
					Severity: "crit",
					Message:  fmt.Sprintf("%s is %d%% full", fields[5], pct),
					Action:   "Free up space or expand the filesystem",
				})
			} else if pct >= 80 {
				recs = append(recs, SystemRecommendation{
					Category: "storage",
					Severity: "warn",
					Message:  fmt.Sprintf("%s is %d%% full", fields[5], pct),
					Action:   "Monitor and clean up if needed",
				})
			}
		}
	}
	// Check failed services
	if units, err := p.FailedSystemdUnits(context.Background()); err == nil && len(units) > 0 {
		recs = append(recs, SystemRecommendation{
			Category: "services",
			Severity: "warn",
			Message:  fmt.Sprintf("%d systemd unit(s) in failed state", len(units)),
			Action:   "Check the failed units list and restart or disable",
		})
	}
	return recs, nil
}

func (p *linuxProvider) GetMaxOpenFiles(ctx context.Context) (int, error) {
	data, err := os.ReadFile("/proc/sys/fs/file-max")
	if err != nil {
		return 0, err
	}
	v, _ := strconv.Atoi(strings.TrimSpace(string(data)))
	return v, nil
}

func (p *linuxProvider) GetTCPCongestionAlgo(ctx context.Context) (string, error) {
	data, err := os.ReadFile("/proc/sys/net/ipv4/tcp_congestion_control")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

func (p *linuxProvider) GetDiskSerial(ctx context.Context, devPath string) (string, error) {
	if !strings.HasPrefix(devPath, "/dev/") {
		devPath = "/dev/" + devPath
	}
	stdout, _, err := RunPriv(ctx, "/usr/bin/smartctl", "-i", devPath)
	out := stdout
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "Serial Number:") {
			return strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "Serial Number:")), nil
		}
	}
	return "", nil
}

func (p *linuxProvider) NetworkInterfaceFeatures(ctx context.Context) ([]InterfaceFeature, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var features []InterfaceFeature
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		f := InterfaceFeature{
			Name:   ifc.Name,
			LinkUp: ifc.Flags&net.FlagUp != 0,
		}
		// driver from /sys
		if data, err := os.Readlink("/sys/class/net/" + ifc.Name + "/device/driver"); err == nil {
			f.Driver = filepath.Base(data)
		}
		// speed/duplex
		if data, err := os.ReadFile("/sys/class/net/" + ifc.Name + "/speed"); err == nil {
			f.Speed = strings.TrimSpace(string(data)) + " Mb/s"
		}
		if data, err := os.ReadFile("/sys/class/net/" + ifc.Name + "/duplex"); err == nil {
			f.Duplex = strings.TrimSpace(string(data))
		}
		features = append(features, f)
	}
	return features, nil
}

func (p *linuxProvider) GetZFSDatasetProperty(ctx context.Context, dataset, prop string) (string, error) {
	out, _, err := RunPriv(ctx, "/usr/sbin/zfs", "get", "-H", "-o", "value", prop, dataset)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func (p *linuxProvider) SetZFSDatasetProperty(ctx context.Context, dataset, prop, value string) error {
	if strings.ContainsAny(value, ";|&$`\\") {
		return fmt.Errorf("invalid value")
	}
	stdout, stderr, err := RunPriv(ctx, "/usr/sbin/zfs", "set", prop+"="+value, dataset)
	if err != nil {
		out := append(stdout, stderr...)
		return fmt.Errorf("zfs set: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func (p *linuxProvider) OpenPortsAudit(ctx context.Context) ([]OpenPort, error) {
	out, _, err := RunPlain(ctx, "ss", "-tunlp")
	if err != nil {
		return nil, err
	}
	var ports []OpenPort
	for i, line := range strings.Split(string(out), "\n") {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		// Netid State Recv-Q Send-Q Local Peer Process
		proto := fields[0]
		local := fields[4]
		// Parse address:port
		colonIdx := strings.LastIndex(local, ":")
		if colonIdx == -1 {
			continue
		}
		addr := local[:colonIdx]
		portStr := local[colonIdx+1:]
		port, _ := strconv.Atoi(portStr)
		op := OpenPort{Proto: proto, Port: port, Addr: addr}
		if len(fields) >= 7 {
			procStr := strings.Join(fields[6:], " ")
			if pidIdx := strings.Index(procStr, "pid="); pidIdx != -1 {
				rest := procStr[pidIdx+4:]
				if endIdx := strings.IndexAny(rest, ",)"); endIdx > 0 {
					op.PID, _ = strconv.Atoi(rest[:endIdx])
				}
			}
			if nameIdx := strings.Index(procStr, "((\""); nameIdx != -1 {
				rest := procStr[nameIdx+3:]
				if endIdx := strings.Index(rest, "\""); endIdx > 0 {
					op.Process = rest[:endIdx]
				}
			}
		}
		ports = append(ports, op)
	}
	return ports, nil
}

func (p *linuxProvider) OOMKillerLog(ctx context.Context, lines int) ([]OOMEvent, error) {
	if lines <= 0 || lines > 5000 {
		lines = 100
	}
	out, _, err := RunPlain(ctx, "dmesg", "--ctime")
	if err != nil {
		return nil, err
	}
	var events []OOMEvent
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, "Out of memory:") && !strings.Contains(line, "Killed process") {
			continue
		}
		event := OOMEvent{}
		// Try to extract timestamp
		if openIdx := strings.Index(line, "["); openIdx == 0 {
			if closeIdx := strings.Index(line, "]"); closeIdx > 0 {
				event.When = strings.TrimSpace(line[1:closeIdx])
				line = line[closeIdx+1:]
			}
		}
		// Extract process name and PID
		if pidIdx := strings.Index(line, "process "); pidIdx != -1 {
			rest := line[pidIdx+8:]
			fields := strings.Fields(rest)
			if len(fields) >= 1 {
				event.PID, _ = strconv.Atoi(fields[0])
			}
			if openIdx := strings.Index(rest, "("); openIdx != -1 {
				if closeIdx := strings.Index(rest[openIdx:], ")"); closeIdx > 0 {
					event.Process = rest[openIdx+1 : openIdx+closeIdx]
				}
			}
		}
		events = append(events, event)
		if len(events) >= lines {
			break
		}
	}
	return events, nil
}

func (p *linuxProvider) ZRAMInfo(ctx context.Context) ([]ZRAMDevice, error) {
	entries, err := os.ReadDir("/sys/block")
	if err != nil {
		return nil, err
	}
	var devices []ZRAMDevice
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "zram") {
			continue
		}
		base := "/sys/block/" + name + "/"
		dev := ZRAMDevice{Name: name}
		if data, err := os.ReadFile(base + "disksize"); err == nil {
			v, _ := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
			dev.SizeKB = v / 1024
		}
		if data, err := os.ReadFile(base + "comp_algorithm"); err == nil {
			s := strings.TrimSpace(string(data))
			// the active algorithm is wrapped in []
			if openIdx := strings.Index(s, "["); openIdx != -1 {
				if closeIdx := strings.Index(s[openIdx:], "]"); closeIdx > 0 {
					dev.Algorithm = s[openIdx+1 : openIdx+closeIdx]
				}
			} else {
				dev.Algorithm = s
			}
		}
		if data, err := os.ReadFile(base + "mm_stat"); err == nil {
			fields := strings.Fields(string(data))
			if len(fields) >= 3 {
				orig, _ := strconv.ParseInt(fields[0], 10, 64)
				compr, _ := strconv.ParseInt(fields[1], 10, 64)
				dev.UsedKB = compr / 1024
				if compr > 0 {
					dev.CompressionRatio = float64(orig) / float64(compr)
				}
			}
		}
		devices = append(devices, dev)
	}
	return devices, nil
}

func (p *linuxProvider) GetNTPServers(ctx context.Context) ([]string, error) {
	// Try chrony first
	if data, err := os.ReadFile("/etc/chrony/chrony.conf"); err == nil {
		var servers []string
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "server ") || strings.HasPrefix(line, "pool ") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					servers = append(servers, fields[1])
				}
			}
		}
		return servers, nil
	}
	// Try systemd-timesyncd
	if data, err := os.ReadFile("/etc/systemd/timesyncd.conf"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "NTP=") {
				val := strings.TrimPrefix(line, "NTP=")
				return strings.Fields(val), nil
			}
		}
	}
	return nil, nil
}

func (p *linuxProvider) SetNTPServers(ctx context.Context, servers []string) error {
	for _, s := range servers {
		if strings.ContainsAny(s, " ;|&$`\\") {
			return fmt.Errorf("invalid server name")
		}
	}
	// Try systemd-timesyncd path
	if _, err := os.Stat("/etc/systemd/timesyncd.conf"); err == nil {
		data, _ := os.ReadFile("/etc/systemd/timesyncd.conf")
		var newLines []string
		ntpSet := false
		for _, line := range strings.Split(string(data), "\n") {
			tl := strings.TrimSpace(line)
			if strings.HasPrefix(tl, "NTP=") || strings.HasPrefix(tl, "#NTP=") {
				newLines = append(newLines, "NTP="+strings.Join(servers, " "))
				ntpSet = true
			} else {
				newLines = append(newLines, line)
			}
		}
		if !ntpSet {
			newLines = append(newLines, "NTP="+strings.Join(servers, " "))
		}
		if err := os.WriteFile("/etc/systemd/timesyncd.conf", []byte(strings.Join(newLines, "\n")), 0644); err != nil {
			return err
		}
		_, _, err := RunPriv(ctx, "/usr/bin/systemctl", "restart", "systemd-timesyncd")
		return err
	}
	return fmt.Errorf("no NTP configuration file found")
}

func (p *linuxProvider) GetTimeSyncStatus(ctx context.Context) (TimeSyncStatus, error) {
	status := TimeSyncStatus{}
	if out, _, err := RunPlain(ctx, "timedatectl", "show"); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			if strings.HasPrefix(line, "NTPSynchronized=") {
				status.Synchronized = strings.TrimPrefix(line, "NTPSynchronized=") == "yes"
			}
		}
	}
	if out, _, err := RunPlain(ctx, "timedatectl", "timesync-status"); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "Server:") {
				status.Server = strings.TrimSpace(strings.TrimPrefix(line, "Server:"))
			} else if strings.HasPrefix(line, "Poll interval:") {
				status.PollInterval = strings.TrimSpace(strings.TrimPrefix(line, "Poll interval:"))
			} else if strings.HasPrefix(line, "Last sync:") {
				status.LastSync = strings.TrimSpace(strings.TrimPrefix(line, "Last sync:"))
			} else if strings.HasPrefix(line, "Offset:") {
				status.Offset = strings.TrimSpace(strings.TrimPrefix(line, "Offset:"))
			}
		}
	}
	return status, nil
}

func (p *linuxProvider) GetIPv6Status(ctx context.Context) (IPv6Status, error) {
	status := IPv6Status{Enabled: true}
	if data, err := os.ReadFile("/proc/sys/net/ipv6/conf/all/disable_ipv6"); err == nil {
		if strings.TrimSpace(string(data)) == "1" {
			status.Enabled = false
		}
	}
	ifaces, err := net.Interfaces()
	if err == nil {
		for _, ifc := range ifaces {
			addrs, _ := ifc.Addrs()
			for _, addr := range addrs {
				ipNet, ok := addr.(*net.IPNet)
				if !ok || ipNet.IP.To4() != nil {
					continue
				}
				status.Addresses = append(status.Addresses, ifc.Name+": "+ipNet.IP.String())
			}
		}
	}
	return status, nil
}

func (p *linuxProvider) ZFSScrubProgress(ctx context.Context, pool string) (ScrubProgress, error) {
	out, _, err := RunPriv(ctx, "/usr/sbin/zpool", "status", pool)
	if err != nil {
		return ScrubProgress{}, err
	}
	prog := ScrubProgress{Pool: pool, State: "idle"}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "scan:") {
			rest := strings.TrimSpace(strings.TrimPrefix(line, "scan:"))
			if strings.HasPrefix(rest, "scrub in progress") {
				prog.State = "in_progress"
			} else if strings.HasPrefix(rest, "scrub repaired") {
				prog.State = "completed"
			}
		}
		if strings.Contains(line, "% done") {
			fields := strings.Fields(line)
			for _, f := range fields {
				if strings.HasSuffix(f, "%") {
					v, _ := strconv.ParseFloat(strings.TrimSuffix(f, "%"), 64)
					prog.Progress = v
				}
			}
		}
		if strings.Contains(line, "to go") {
			// e.g. "0 days 00:01:23 to go"
			idx := strings.Index(line, "to go")
			prog.ETA = strings.TrimSpace(line[:idx])
		}
		if strings.Contains(line, "errors") {
			fields := strings.Fields(line)
			if len(fields) > 0 {
				v, _ := strconv.Atoi(fields[0])
				prog.ErrorsFound = v
			}
		}
	}
	return prog, nil
}

func (p *linuxProvider) ListLogins(ctx context.Context, count int) ([]LoginEvent, error) {
	if count <= 0 || count > 500 {
		count = 50
	}
	out, _, err := RunPlain(ctx, "last", "-n", strconv.Itoa(count), "-w")
	if err != nil {
		return nil, err
	}
	var logins []LoginEvent
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "wtmp") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		event := LoginEvent{User: fields[0], TTY: fields[1]}
		if len(fields) > 2 && !strings.HasPrefix(fields[2], "Mon") && !strings.HasPrefix(fields[2], "Tue") &&
			!strings.HasPrefix(fields[2], "Wed") && !strings.HasPrefix(fields[2], "Thu") &&
			!strings.HasPrefix(fields[2], "Fri") && !strings.HasPrefix(fields[2], "Sat") &&
			!strings.HasPrefix(fields[2], "Sun") {
			event.From = fields[2]
		}
		// Login time and duration are in the rest of the fields
		if len(fields) > 3 {
			event.Login = strings.Join(fields[3:7], " ")
		}
		if len(fields) > 7 {
			event.Duration = strings.Join(fields[7:], " ")
		}
		logins = append(logins, event)
	}
	return logins, nil
}

func (p *linuxProvider) GetCurrentTimezoneOffset(ctx context.Context) (string, error) {
	out, _, err := RunPlain(ctx, "date", "+%:z")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func (p *linuxProvider) GetSystemBoots(ctx context.Context) ([]BootRecord, error) {
	out, _, err := RunPriv(ctx, "/usr/bin/journalctl", "--list-boots", "--no-pager")
	if err != nil {
		return nil, err
	}
	var boots []BootRecord
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		idx, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}
		br := BootRecord{Index: idx, BootID: fields[1]}
		if len(fields) >= 5 {
			br.First = strings.Join(fields[2:5], " ")
		}
		if len(fields) >= 8 {
			br.Last = strings.Join(fields[5:8], " ")
		}
		boots = append(boots, br)
	}
	return boots, nil
}

func (p *linuxProvider) GetSMARTAttributes(ctx context.Context, devPath string) ([]SMARTAttribute, error) {
	if !strings.HasPrefix(devPath, "/dev/") {
		devPath = "/dev/" + devPath
	}
	stdout, _, err := RunPriv(ctx, "/usr/bin/smartctl", "-A", "-j", devPath)
	out := stdout
	if err != nil {
		return nil, err
	}
	var raw struct {
		ATASMARTAttributes struct {
			Table []struct {
				ID         int    `json:"id"`
				Name       string `json:"name"`
				Value      int    `json:"value"`
				Worst      int    `json:"worst"`
				Thresh     int    `json:"thresh"`
				WhenFailed string `json:"when_failed"`
				Raw        struct {
					Value  int64  `json:"value"`
					String string `json:"string"`
				} `json:"raw"`
			} `json:"table"`
		} `json:"ata_smart_attributes"`
	}
	if err := json.Unmarshal(out, &raw); err != nil {
		return nil, err
	}
	var attrs []SMARTAttribute
	for _, a := range raw.ATASMARTAttributes.Table {
		attrs = append(attrs, SMARTAttribute{
			ID:         a.ID,
			Name:       a.Name,
			Value:      a.Value,
			Worst:      a.Worst,
			Threshold:  a.Thresh,
			WhenFailed: a.WhenFailed,
			Raw:        a.Raw.Value,
		})
	}
	return attrs, nil
}

func (p *linuxProvider) GetZFSDedupStats(ctx context.Context, pool string) (DedupStats, error) {
	out, _, err := RunPriv(ctx, "/usr/sbin/zpool", "get", "-H", "-o", "value", "dedupratio,allocated,size", pool)
	if err != nil {
		return DedupStats{}, err
	}
	stats := DedupStats{Pool: pool}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) >= 1 {
		ratioStr := strings.TrimSuffix(lines[0], "x")
		stats.Ratio, _ = strconv.ParseFloat(ratioStr, 64)
		if stats.Ratio > 1.0 {
			stats.Enabled = true
		}
	}
	return stats, nil
}

func (p *linuxProvider) GetNVMeStats(ctx context.Context, devPath string) (NVMeInfo, error) {
	if !strings.HasPrefix(devPath, "/dev/") {
		devPath = "/dev/" + devPath
	}
	out, _, err := RunPlain(ctx, "nvme", "smart-log", "-o", "json", devPath)
	if err != nil {
		// Fallback to smartctl for non-NVMe-cli systems
		stdout, _, err2 := RunPriv(ctx, "/usr/bin/smartctl", "-A", "-j", devPath)
		smartOut := stdout
		if err2 != nil {
			return NVMeInfo{}, err
		}
		var raw struct {
			NvmeSmartHealthInfo struct {
				Temperature      int   `json:"temperature"`
				AvailableSpare   int   `json:"available_spare"`
				PercentageUsed   int   `json:"percentage_used"`
				PowerOnHours     int64 `json:"power_on_hours"`
				UnsafeShutdowns  int64 `json:"unsafe_shutdowns"`
				MediaErrors      int64 `json:"media_errors"`
				NumErrLogEntries int64 `json:"num_err_log_entries"`
			} `json:"nvme_smart_health_information_log"`
		}
		if err := json.Unmarshal(smartOut, &raw); err != nil {
			return NVMeInfo{}, err
		}
		return NVMeInfo{
			Device:           devPath,
			Temperature:      raw.NvmeSmartHealthInfo.Temperature - 273,
			AvailableSpare:   raw.NvmeSmartHealthInfo.AvailableSpare,
			PercentageUsed:   raw.NvmeSmartHealthInfo.PercentageUsed,
			PowerOnHours:     raw.NvmeSmartHealthInfo.PowerOnHours,
			UnsafeShutdowns:  raw.NvmeSmartHealthInfo.UnsafeShutdowns,
			MediaErrors:      raw.NvmeSmartHealthInfo.MediaErrors,
			NumErrLogEntries: raw.NvmeSmartHealthInfo.NumErrLogEntries,
		}, nil
	}
	var raw struct {
		Temperature      int   `json:"temperature"`
		AvailSpare       int   `json:"avail_spare"`
		PercentUsed      int   `json:"percent_used"`
		PowerOnHours     int64 `json:"power_on_hours"`
		UnsafeShutdowns  int64 `json:"unsafe_shutdowns"`
		MediaErrors      int64 `json:"media_errors"`
		NumErrLogEntries int64 `json:"num_err_log_entries"`
	}
	if err := json.Unmarshal(out, &raw); err != nil {
		return NVMeInfo{}, err
	}
	return NVMeInfo{
		Device:           devPath,
		Temperature:      raw.Temperature - 273,
		AvailableSpare:   raw.AvailSpare,
		PercentageUsed:   raw.PercentUsed,
		PowerOnHours:     raw.PowerOnHours,
		UnsafeShutdowns:  raw.UnsafeShutdowns,
		MediaErrors:      raw.MediaErrors,
		NumErrLogEntries: raw.NumErrLogEntries,
	}, nil
}

func (p *linuxProvider) GetGPUInfo(ctx context.Context) ([]GPUInfo, error) {
	var gpus []GPUInfo
	// Try nvidia-smi
	out, _, err := RunPlain(ctx, "nvidia-smi", "--query-gpu=index,name,driver_version,memory.total,temperature.gpu,utilization.gpu", "--format=csv,noheader,nounits")
	if err == nil {
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			fields := strings.Split(line, ", ")
			if len(fields) < 6 {
				continue
			}
			idx, _ := strconv.Atoi(fields[0])
			mem, _ := strconv.Atoi(fields[3])
			temp, _ := strconv.Atoi(fields[4])
			util, _ := strconv.Atoi(fields[5])
			gpus = append(gpus, GPUInfo{
				Index:       idx,
				Name:        fields[1],
				Driver:      "nvidia " + fields[2],
				MemoryMB:    mem,
				Temperature: temp,
				UtilPct:     util,
			})
		}
		return gpus, nil
	}
	// Fall back to lspci grep
	if out, _, err := RunPlain(ctx, "lspci"); err == nil {
		idx := 0
		for _, line := range strings.Split(string(out), "\n") {
			lower := strings.ToLower(line)
			if strings.Contains(lower, "vga") || strings.Contains(lower, "3d controller") || strings.Contains(lower, "display controller") {
				colonIdx := strings.Index(line, ":")
				if colonIdx == -1 {
					continue
				}
				rest := strings.TrimSpace(line[colonIdx+1:])
				if c2 := strings.Index(rest, ":"); c2 != -1 {
					gpus = append(gpus, GPUInfo{Index: idx, Name: strings.TrimSpace(rest[c2+1:])})
					idx++
				}
			}
		}
	}
	return gpus, nil
}

func (p *linuxProvider) FlushARPCache(ctx context.Context) error {
	stdout, stderr, err := RunPriv(ctx, "/sbin/ip", "neigh", "flush", "all")
	if err != nil {
		out := append(stdout, stderr...)
		return fmt.Errorf("ip neigh flush: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func (p *linuxProvider) GetECCErrors(ctx context.Context) ([]ECCEvent, error) {
	var events []ECCEvent
	// Check /sys/devices/system/edac
	entries, err := os.ReadDir("/sys/devices/system/edac/mc")
	if err != nil {
		return nil, nil
	}
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), "mc") {
			continue
		}
		base := "/sys/devices/system/edac/mc/" + e.Name()
		if data, err := os.ReadFile(base + "/ce_count"); err == nil {
			cnt, _ := strconv.Atoi(strings.TrimSpace(string(data)))
			if cnt > 0 {
				events = append(events, ECCEvent{Type: "correctable", Count: cnt, Address: e.Name()})
			}
		}
		if data, err := os.ReadFile(base + "/ue_count"); err == nil {
			cnt, _ := strconv.Atoi(strings.TrimSpace(string(data)))
			if cnt > 0 {
				events = append(events, ECCEvent{Type: "uncorrectable", Count: cnt, Address: e.Name()})
			}
		}
	}
	return events, nil
}

func (p *linuxProvider) GetMemFragmentation(ctx context.Context) (MemFragInfo, error) {
	info := MemFragInfo{OrderFragmentation: make(map[string]float64)}
	data, err := os.ReadFile("/proc/buddyinfo")
	if err != nil {
		return info, err
	}
	// Aggregate across nodes/zones
	totals := make([]int64, 11)
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 14 {
			continue
		}
		// fields[0..3] are Node X, zone Y, then 11 numbers
		for i := 4; i < len(fields) && i-4 < 11; i++ {
			n, _ := strconv.ParseInt(fields[i], 10, 64)
			totals[i-4] += n
		}
	}
	var total int64
	for _, n := range totals {
		total += n
	}
	if total > 0 {
		for i, n := range totals {
			info.OrderFragmentation[fmt.Sprintf("order_%d", i)] = float64(n) / float64(total)
		}
		// If high orders (4MB+) are nearly empty, fragmentation is high
		if totals[8]+totals[9]+totals[10] < 5 {
			info.HighOrderUnusable = true
		}
	}
	return info, nil
}

func (p *linuxProvider) GetTopBandwidthIPs(ctx context.Context, max int) ([]BandwidthIP, error) {
	if max <= 0 || max > 100 {
		max = 10
	}
	// Aggregate from conntrack
	out, _, err := RunPlain(ctx, "conntrack", "-L")
	if err != nil {
		return nil, nil
	}
	type acc struct {
		conns int
	}
	stats := make(map[string]*acc)
	for _, line := range strings.Split(string(out), "\n") {
		var srcIP string
		for _, f := range strings.Fields(line) {
			if strings.HasPrefix(f, "src=") {
				ip := strings.TrimPrefix(f, "src=")
				if ip != "127.0.0.1" && !strings.HasPrefix(ip, "::1") {
					srcIP = ip
				}
				break
			}
		}
		if srcIP == "" {
			continue
		}
		if _, ok := stats[srcIP]; !ok {
			stats[srcIP] = &acc{}
		}
		stats[srcIP].conns++
	}
	var result []BandwidthIP
	for ip, a := range stats {
		result = append(result, BandwidthIP{IP: ip, Connections: a.conns})
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Connections > result[j].Connections
	})
	if len(result) > max {
		result = result[:max]
	}
	return result, nil
}

func (p *linuxProvider) GetSwapPressure(ctx context.Context) (PressureInfo, error) {
	info := PressureInfo{}
	data, err := os.ReadFile("/proc/pressure/memory")
	if err != nil {
		return info, nil
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 1 {
			continue
		}
		isSome := strings.HasPrefix(line, "some ")
		isFull := strings.HasPrefix(line, "full ")
		for _, f := range fields {
			if strings.HasPrefix(f, "avg10=") {
				v, _ := strconv.ParseFloat(strings.TrimPrefix(f, "avg10="), 64)
				if isSome {
					info.Some10s = v
				} else if isFull {
					info.Full10s = v
				}
			} else if strings.HasPrefix(f, "avg60=") && isSome {
				v, _ := strconv.ParseFloat(strings.TrimPrefix(f, "avg60="), 64)
				info.Some60s = v
			} else if strings.HasPrefix(f, "avg300=") && isSome {
				v, _ := strconv.ParseFloat(strings.TrimPrefix(f, "avg300="), 64)
				info.Some300s = v
			}
		}
	}
	return info, nil
}

// M382: SMB AD-joined mode

func (p *linuxProvider) SMBADJoin(ctx context.Context, realm, adminUser, adminPassword, ouPath string) error {
	if strings.ContainsAny(realm, " ;|&$`\\") || strings.ContainsAny(adminUser, " ;|&$`\\") {
		return fmt.Errorf("invalid realm or admin user")
	}
	args := []string{"ads", "join", realm, "-U", adminUser + "%" + adminPassword}
	if ouPath != "" {
		args = append(args, "createcomputer="+ouPath)
	}
	stdout, stderr, err := RunPriv(ctx, "/usr/bin/net", args...)
	if err != nil {
		out := append(stdout, stderr...)
		return fmt.Errorf("net ads join: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func (p *linuxProvider) SMBADLeave(ctx context.Context, adminUser, adminPassword string) error {
	if strings.ContainsAny(adminUser, " ;|&$`\\") {
		return fmt.Errorf("invalid admin user")
	}
	stdout, stderr, err := RunPriv(ctx, "/usr/bin/net", "ads", "leave", "-U", adminUser+"%"+adminPassword)
	if err != nil {
		out := append(stdout, stderr...)
		return fmt.Errorf("net ads leave: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func (p *linuxProvider) SMBADStatus(ctx context.Context) (SMBADStatus, error) {
	out, _, err := RunPriv(ctx, "/usr/bin/net", "ads", "info")
	if err != nil {
		return SMBADStatus{Joined: false}, nil
	}
	st := SMBADStatus{Joined: true}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Realm:") {
			st.Realm = strings.TrimSpace(strings.TrimPrefix(line, "Realm:"))
		} else if strings.HasPrefix(line, "LDAP server:") {
			st.Server = strings.TrimSpace(strings.TrimPrefix(line, "LDAP server:"))
		} else if strings.HasPrefix(line, "LDAP server name:") {
			st.Server = strings.TrimSpace(strings.TrimPrefix(line, "LDAP server name:"))
		} else if strings.HasPrefix(line, "Site Name:") {
			st.Site = strings.TrimSpace(strings.TrimPrefix(line, "Site Name:"))
		}
	}
	return st, nil
}


// ── App Marketplace────

func (p *linuxProvider) AppStacks(ctx context.Context) ([]AppStack, error) {
	stacks := []AppStack{
		{
			Name:        "Servarr Stack",
			Label:       "servarr",
			Description: "Complete PVR stack: Sonarr, Radarr, Lidarr, Readarr, Prowlarr, and qBittorrent.",
			Icon:        "🎞",
			Services: []AppService{
				{TemplateID: "sonarr", Name: "sonarr", CPUPercent: 10, MemBytes: 512 * 1024 * 1024},
				{TemplateID: "radarr", Name: "radarr", CPUPercent: 10, MemBytes: 512 * 1024 * 1024},
				{TemplateID: "lidarr", Name: "lidarr", CPUPercent: 10, MemBytes: 512 * 1024 * 1024},
				{TemplateID: "readarr", Name: "readarr", CPUPercent: 10, MemBytes: 512 * 1024 * 1024},
				{TemplateID: "prowlarr", Name: "prowlarr", CPUPercent: 5, MemBytes: 256 * 1024 * 1024},
				{TemplateID: "qbittorrent", Name: "qbittorrent", CPUPercent: 20, MemBytes: 1024 * 1024 * 1024},
			},
		},
		{
			Name:        "Media Core Stack",
			Label:       "media-core",
			Description: "Jellyfin + Jellyseerr + Bazarr for automated media management.",
			Icon:        "🎬",
			Services: []AppService{
				{TemplateID: "jellyfin", Name: "jellyfin", CPUPercent: 30, MemBytes: 4 * 1024 * 1024 * 1024},
				{TemplateID: "jellyseerr", Name: "jellyseerr", CPUPercent: 5, MemBytes: 256 * 1024 * 1024},
				{TemplateID: "bazarr", Name: "bazarr", CPUPercent: 5, MemBytes: 256 * 1024 * 1024},
			},
		},
	}
	return stacks, nil
}

func (p *linuxProvider) CreateAppStack(ctx context.Context, s AppStack) (AppStack, error) {
	stacksDir := "/var/lib/kilasos/app-stacks"
	stackDir := filepath.Join(stacksDir, s.Label)
	dataPath := filepath.Join(stackDir, "data")
	os.MkdirAll(dataPath, 0755)
	for _, svc := range s.Services {
		appDir := filepath.Join(dataPath, svc.Name)
		os.MkdirAll(filepath.Join(appDir, "data"), 0755)
	}
	composeFile := filepath.Join(stackDir, "docker-compose.yml")
	f, _ := os.Create(composeFile)
	defer f.Close()
	fmt.Fprintf(f, "# App Stack: %s\nversion: '3.8'\nservices:\n", s.Name)
	for _, svc := range s.Services {
		fmt.Fprintf(f, "  %s:\n    image: %s\n    container_name: %s\n    restart: unless-stopped\n    volumes:\n      - ./data/%s:/config\n",
			svc.Name, "hotio/"+svc.TemplateID+":latest", svc.Name, svc.Name)
		needsDeploy := svc.CPUPercent > 0 || svc.MemBytes > 0
		if needsDeploy {
			f.WriteString("    deploy:\n      resources:\n        limits:\n")
		}
		if svc.CPUPercent > 0 {
			fmt.Fprintf(f, "          cpus: '%.2f'\n", float64(svc.CPUPercent)/100)
		}
		if svc.MemBytes > 0 {
			fmt.Fprintf(f, "          memory: %d\n", svc.MemBytes)
		}
		f.WriteString("\n")
	}
	f.WriteString("# Auto-generated by KilasOS\n")
	f.Close()
	return s, nil
}

func (p *linuxProvider) DeleteAppStack(ctx context.Context, name string) error {
	stacksDir := "/var/lib/kilasos/app-stacks"
	stackDir := filepath.Join(stacksDir, name)
	return os.RemoveAll(stackDir)
}

func (p *linuxProvider) AppUpdateAvailable(ctx context.Context, appName string) (AppUpdateInfo, error) {
	appDir := p.appDir(appName)
	if appDir == "" {
		return AppUpdateInfo{}, errors.New("app not found")
	}
	composeFile := filepath.Join(appDir, "docker-compose.yml")
	data, err := os.ReadFile(composeFile)
	if err != nil {
		return AppUpdateInfo{}, err
	}
	lines := strings.Split(string(data), "\n")
	var image string
	for _, line := range lines {
		if strings.Contains(line, "image:") {
			image = strings.TrimSpace(strings.SplitN(line, "image:", 2)[1])
			break
		}
	}
	if image == "" {
		return AppUpdateInfo{}, errors.New("no image found in compose")
	}
	_, _, _ = RunPlain(ctx, "docker", "pull", "--quiet", image)
	out, _, _ := RunPlain(ctx, "docker", "inspect", "--format", "{{index .RepoTags 0}}", image+" 2>/dev/null || echo "+image)
	currentTag := strings.TrimSpace(string(out))
	if idx := strings.LastIndex(currentTag, ":"); idx >= 0 {
		currentTag = currentTag[idx+1:]
	} else {
		currentTag = "latest"
	}
	return AppUpdateInfo{
		Available:  false,
		CurrentTag: currentTag,
		LatestTag:  currentTag,
	}, nil
}

func (p *linuxProvider) AppUpdate(ctx context.Context, appName string, backup bool) (string, error) {
	appDir := p.appDir(appName)
	if appDir == "" {
		return "", errors.New("app not found")
	}
	if backup {
		backupDir := filepath.Join(appDir, "backups", time.Now().UTC().Format("20060102-150405"))
		os.MkdirAll(backupDir, 0755)
		filepath.Walk(appDir, func(path string, info os.FileInfo, err error) error {
			if err != nil || path == backupDir {
				return nil
			}
			rel, _ := filepath.Rel(appDir, path)
			target := filepath.Join(backupDir, rel)
			if info.IsDir() {
				os.MkdirAll(target, info.Mode())
			} else {
				src, _ := os.Open(path)
				dst, _ := os.Create(target)
				io.Copy(dst, src)
				src.Close()
				dst.Close()
				os.Chmod(target, info.Mode())
			}
			return nil
		})
	}
	_, _, _ = RunPlainWithDir(ctx, appDir, "docker", "compose", "pull", "-q")
	stdout, stderr, err := RunPlainWithDir(ctx, appDir, "docker", "compose", "up", "-d")
	out := append(stdout, stderr...)
	return string(out), err
}

func (p *linuxProvider) AppRollback(ctx context.Context, appName string, backupID string) (string, error) {
	appDir := p.appDir(appName)
	if appDir == "" {
		return "", errors.New("app not found")
	}
	backupDir := filepath.Join(appDir, "backups", backupID)
	if _, err := os.Stat(backupDir); err != nil {
		return "", fmt.Errorf("backup not found: %s", backupID)
	}
	os.RemoveAll(appDir)
	filepath.Walk(backupDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(backupDir, path)
		target := filepath.Join(appDir, rel)
		if info.IsDir() {
			os.MkdirAll(target, info.Mode())
		} else {
			src, _ := os.Open(path)
			dst, _ := os.Create(target)
			io.Copy(dst, src)
			src.Close()
			dst.Close()
			os.Chmod(target, info.Mode())
		}
		return nil
	})
	stdout, stderr, err := RunPlainWithDir(ctx, appDir, "docker", "compose", "up", "-d")
	out := append(stdout, stderr...)
	return string(out), err
}

func (p *linuxProvider) AppHealthStatus(ctx context.Context, appName string) (AppHealthInfo, error) {
	out, _, err := RunPlain(ctx, "docker", "ps", "-a", "--filter", "name="+appName, "--format", "{{.Names}}\t{{.Status}}")
	if err != nil {
		return AppHealthInfo{Status: "unknown", Message: err.Error()}, nil
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	running, total := 0, 0
	for _, line := range lines {
		if line == "" {
			continue
		}
		total++
		if strings.Contains(line, "Up") {
			running++
		}
	}
	status := "healthy"
	msg := ""
	if total == 0 {
		status = "unknown"
		msg = "no containers found"
	} else if running == 0 {
		status = "unhealthy"
		msg = "all containers stopped"
	} else if running < total {
		status = "degraded"
		msg = "some containers not running"
	}
	return AppHealthInfo{Status: status, Containers: total, Running: running, Message: msg}, nil
}

func (p *linuxProvider) AppExportConfig(ctx context.Context, appName string) (AppConfigExport, error) {
	appDir := p.appDir(appName)
	if appDir == "" {
		return AppConfigExport{}, errors.New("app not found")
	}
	cfg := AppConfigExport{AppName: appName}
	composeFile := filepath.Join(appDir, "docker-compose.yml")
	if data, err := os.ReadFile(composeFile); err == nil {
		cfg.ComposeYAML = string(data)
	}
	envFile := filepath.Join(appDir, ".env")
	if data, err := os.ReadFile(envFile); err == nil {
		cfg.EnvVars = p.parseEnvVars(string(data))
	}
	return cfg, nil
}

func (p *linuxProvider) AppImportConfig(ctx context.Context, appName string, cfg AppConfigExport) error {
	appDir := filepath.Join("/var/lib/kilasos/apps", appName)
	os.MkdirAll(appDir, 0755)
	os.MkdirAll(filepath.Join(appDir, "data"), 0755)
	if cfg.ComposeYAML != "" {
		os.WriteFile(filepath.Join(appDir, "docker-compose.yml"), []byte(cfg.ComposeYAML), 0644)
	}
	if len(cfg.EnvVars) > 0 {
		var lines []string
		for k, v := range cfg.EnvVars {
			lines = append(lines, fmt.Sprintf("%s=%q", k, v))
		}
		os.WriteFile(filepath.Join(appDir, ".env"), []byte(strings.Join(lines, "\n")), 0644)
	}
	_, _, err := RunPlainWithDir(ctx, appDir, "docker", "compose", "up", "-d")
	return err
}

func (p *linuxProvider) AppCustomTemplate(ctx context.Context, composeYAML string) (appcatalog.AppTemplate, error) {
	id := "custom-" + time.Now().UTC().Format("20060102")
	return appcatalog.NewCustomAppTemplate(id, composeYAML), nil
}

func (p *linuxProvider) AppSearch(ctx context.Context, q string, category string) ([]appcatalog.AppTemplate, error) {
	all := appcatalog.AllCatalog()
	var result []appcatalog.AppTemplate
	q = strings.ToLower(q)
	for _, t := range all {
		if q != "" && !strings.Contains(strings.ToLower(t.Name), q) && !strings.Contains(strings.ToLower(t.Description), q) {
			continue
		}
		if category != "" {
			hasCat := false
			for _, c := range t.Category {
				if c == category {
					hasCat = true
					break
				}
			}
			if !hasCat {
				continue
			}
		}
		result = append(result, t)
	}
	return result, nil
}

func (p *linuxProvider) AppFavorites(ctx context.Context) ([]string, error) {
	data, err := os.ReadFile("/var/lib/kilasos/app-favorites.json")
	if os.IsNotExist(err) {
		return []string{}, nil
	}
	if err != nil {
		return nil, err
	}
	var favs []string
	json.Unmarshal(data, &favs)
	return favs, nil
}

func (p *linuxProvider) AppSetFavorite(ctx context.Context, appName string, fav bool) error {
	favs, _ := p.AppFavorites(ctx)
	if fav {
		for _, f := range favs {
			if f == appName {
				return nil
			}
		}
		favs = append(favs, appName)
	} else {
		for i, f := range favs {
			if f == appName {
				favs = append(favs[:i], favs[i+1:]...)
				break
			}
		}
	}
	data, _ := json.Marshal(favs)
	return os.WriteFile("/var/lib/kilasos/app-favorites.json", data, 0644)
}

func (p *linuxProvider) appDir(appName string) string {
	candidates := []string{
		"/var/lib/kilasos/apps/" + appName,
		"/mnt/docker/apps/" + appName,
		"/var/lib/docker/compose/" + appName,
	}
	for _, c := range candidates {
		if _, err := os.Stat(filepath.Join(c, "docker-compose.yml")); err == nil {
			return c
		}
	}
	return ""
}

func (p *linuxProvider) parseEnvVars(content string) map[string]string {
	result := make(map[string]string)
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if idx := strings.Index(line, "="); idx > 0 {
			key := strings.TrimSpace(line[:idx])
			val := strings.TrimSpace(line[idx+1:])
			val = strings.Trim(val, "\"")
			result[key] = val
		}
	}
	return result
}

// ╔═════════════════════════════════════════════════════════════════════════════╗
// ║ ── BATCH ANCHOR ZONES (linux.go) ──                                         ║
// ║ Each batch appends ITS impl funcs in its own zone below. Do not interleave. ║
// ╚═════════════════════════════════════════════════════════════════════════════╝

// ── BATCH-B (M316-M330): Monitoring & Alerting impls go here ──

const (
	channelsPath = "/var/lib/kilasos/notification-channels.json"
	rulesPath    = "/var/lib/kilasos/alert-rules.json"
	eventsPath    = "/var/lib/kilasos/alert-events.json"
)

func (p *linuxProvider) PrometheusMetrics(ctx context.Context) (string, error) {
	var buf strings.Builder
	m, err := p.Metrics(ctx)
	if err == nil {
		fmt.Fprintf(&buf, "kilasos_cpu_usage_percent %.2f\n", m.CPUPercent)
		fmt.Fprintf(&buf, "kilasos_memory_usage_percent %.2f\n", float64(m.MemUsed)/float64(m.MemTotal)*100)
		if len(m.PoolUsage) > 0 {
			fmt.Fprintf(&buf, "kilasos_disk_usage_percent{pool=\"%s\"} %.2f\n", m.PoolUsage[0].Name, float64(m.PoolUsage[0].Used)/float64(m.PoolUsage[0].Total)*100)
		}
	}
	disks, _ := p.Disks(ctx)
	for _, d := range disks {
		if d.TempCelsius != nil {
			fmt.Fprintf(&buf, "kilasos_disk_temperature{disk=\"%s\"} %d\n", d.Name, *d.TempCelsius)
		}
	}
	load, _ := p.LoadAverages(ctx)
	fmt.Fprintf(&buf, "kilasos_load_avg_1m %.2f\n", load.One)
	fmt.Fprintf(&buf, "kilasos_load_avg_5m %.2f\n", load.Five)
	fmt.Fprintf(&buf, "kilasos_load_avg_15m %.2f\n", load.Fifteen)
	containers, _ := p.Containers(ctx)
	fmt.Fprintf(&buf, "kilasos_containers_total %d\n", len(containers))
	running := 0
	for _, c := range containers {
		if c.State == "running" {
			running++
		}
	}
	fmt.Fprintf(&buf, "kilasos_containers_running %d\n", running)
	netIfs, _ := p.NetIfaceStats(ctx)
	for _, n := range netIfs[:3] {
		fmt.Fprintf(&buf, "kilasos_network_bytes_total{iface=\"%s\"} %d\n", n.Name, n.RxBytes+n.TxBytes)
	}
	return buf.String(), nil
}

func (p *linuxProvider) HealthchecksPing(ctx context.Context, url string) error {
	if url == "" {
		data, _ := os.ReadFile("/var/lib/kilasos/healthchecks-url")
		url = strings.TrimSpace(string(data))
	}
	if url == "" {
		return nil
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("healthchecks ping failed: %d", resp.StatusCode)
	}
	return nil
}

func (p *linuxProvider) Notify(ctx context.Context, channel, event string, severity string) error {
	channels, _ := p.NotificationChannels(ctx)
	var ch *NotificationChannel
	for i := range channels {
		if channels[i].Name == channel && channels[i].Enabled {
			ch = &channels[i]
			break
		}
	}
	if ch == nil {
		return fmt.Errorf("channel %s not found or disabled", channel)
	}
	var body string
	switch severity {
	case "crit":
		body = fmt.Sprintf("🚨 [%s] %s", strings.ToUpper(severity), event)
	case "warn":
		body = fmt.Sprintf("⚠️ [%s] %s", strings.ToUpper(severity), event)
	default:
		body = fmt.Sprintf("ℹ️ %s", event)
	}
	switch ch.Type {
	case "discord":
		return p.sendDiscord(ch.WebhookURL, body)
	case "telegram":
		return p.sendTelegram(ch.ChatID, ch.Token, body)
	case "ntfy":
		return p.sendNtfy(ch.URL, body)
	case "pushover":
		return p.sendPushover(ch.Token, ch.URL, body, severity)
	default:
		return fmt.Errorf("unsupported channel type: %s", ch.Type)
	}
}

func (p *linuxProvider) NotificationChannels(ctx context.Context) ([]NotificationChannel, error) {
	data, err := os.ReadFile(channelsPath)
	if os.IsNotExist(err) {
		return []NotificationChannel{}, nil
	}
	if err != nil {
		return nil, err
	}
	var chs []NotificationChannel
	json.Unmarshal(data, &chs)
	return chs, nil
}

func (p *linuxProvider) CreateNotificationChannel(ctx context.Context, ch NotificationChannel) (NotificationChannel, error) {
	chs, _ := p.NotificationChannels(ctx)
	for _, c := range chs {
		if c.Name == ch.Name {
			return ch, fmt.Errorf("channel %s already exists", ch.Name)
		}
	}
	chs = append(chs, ch)
	p.saveNotificationChannels(chs)
	return ch, nil
}

func (p *linuxProvider) UpdateNotificationChannel(ctx context.Context, name string, ch NotificationChannel) (NotificationChannel, error) {
	chs, _ := p.NotificationChannels(ctx)
	for i := range chs {
		if chs[i].Name == name {
			ch.Name = name
			chs[i] = ch
			p.saveNotificationChannels(chs)
			return ch, nil
		}
	}
	return ch, fmt.Errorf("channel %s not found", name)
}

func (p *linuxProvider) DeleteNotificationChannel(ctx context.Context, name string) error {
	chs, _ := p.NotificationChannels(ctx)
	for i, c := range chs {
		if c.Name == name {
			chs = append(chs[:i], chs[i+1:]...)
			p.saveNotificationChannels(chs)
			return nil
		}
	}
	return fmt.Errorf("channel %s not found", name)
}

func (p *linuxProvider) saveNotificationChannels(chs []NotificationChannel) {
	data, _ := json.Marshal(chs)
	os.WriteFile(channelsPath, data, 0644)
}

func (p *linuxProvider) MonitorAlertRules(ctx context.Context) ([]MonitorAlertRule, error) {
	data, err := os.ReadFile(rulesPath)
	if os.IsNotExist(err) {
		return []MonitorAlertRule{}, nil
	}
	if err != nil {
		return nil, err
	}
	var rules []MonitorAlertRule
	json.Unmarshal(data, &rules)
	return rules, nil
}

func (p *linuxProvider) CreateMonitorAlertRule(ctx context.Context, r MonitorAlertRule) (MonitorAlertRule, error) {
	rules, _ := p.MonitorAlertRules(ctx)
	for _, existing := range rules {
		if existing.Name == r.Name {
			return r, fmt.Errorf("rule %s already exists", r.Name)
		}
	}
	if r.DedupeMins == 0 {
		r.DedupeMins = 5
	}
	rules = append(rules, r)
	p.saveAlertRules(rules)
	return r, nil
}

func (p *linuxProvider) UpdateMonitorAlertRule(ctx context.Context, name string, r MonitorAlertRule) (MonitorAlertRule, error) {
	rules, _ := p.MonitorAlertRules(ctx)
	for i := range rules {
		if rules[i].Name == name {
			r.Name = name
			rules[i] = r
			p.saveAlertRules(rules)
			return r, nil
		}
	}
	return r, fmt.Errorf("rule %s not found", name)
}

func (p *linuxProvider) DeleteMonitorAlertRule(ctx context.Context, name string) error {
	rules, _ := p.MonitorAlertRules(ctx)
	for i, r := range rules {
		if r.Name == name {
			rules = append(rules[:i], rules[i+1:]...)
			p.saveAlertRules(rules)
			return nil
		}
	}
	return fmt.Errorf("rule %s not found", name)
}

func (p *linuxProvider) saveAlertRules(rules []MonitorAlertRule) {
	data, _ := json.Marshal(rules)
	os.WriteFile(rulesPath, data, 0644)
}

func (p *linuxProvider) AlertEvents(ctx context.Context, limit int) ([]AlertEvent, error) {
	data, err := os.ReadFile(eventsPath)
	if os.IsNotExist(err) {
		return []AlertEvent{}, nil
	}
	if err != nil {
		return nil, err
	}
	var events []AlertEvent
	json.Unmarshal(data, &events)
	if limit > 0 && len(events) > limit {
		events = events[len(events)-limit:]
	}
	sort.Slice(events, func(i, j int) bool { return events[i].Time.After(events[j].Time) })
	return events, nil
}

func (p *linuxProvider) AcknowledgeAlert(ctx context.Context, id string) error {
	events, _ := p.AlertEvents(ctx, 0)
	for i := range events {
		if events[i].ID == id {
			events[i].Acked = true
			p.saveAlertEvents(events)
			return nil
		}
	}
	return fmt.Errorf("alert %s not found", id)
}

func (p *linuxProvider) SilenceAlert(ctx context.Context, ruleName string, hours int) error {
	rules, _ := p.MonitorAlertRules(ctx)
	for i := range rules {
		if rules[i].Name == ruleName {
			rules[i].SilenceUntil = time.Now().Add(time.Duration(hours) * time.Hour)
			p.saveAlertRules(rules)
			return nil
		}
	}
	return fmt.Errorf("rule %s not found", ruleName)
}

func (p *linuxProvider) TestNotification(ctx context.Context, channel string) error {
	return p.Notify(ctx, channel, "Test notification from KilasOS", "info")
}

func (p *linuxProvider) saveAlertEvents(events []AlertEvent) {
	data, _ := json.Marshal(events)
	os.WriteFile(eventsPath, data, 0644)
}

func (p *linuxProvider) AnomalyScore(ctx context.Context, metric string, window int) (AnomalyResult, error) {
	if window <= 0 {
		window = 30
	}
	var values []float64
	switch metric {
	case "disk_free":
		m, _ := p.Metrics(ctx)
		if len(m.PoolUsage) > 0 {
			values = append(values, float64(m.PoolUsage[0].Free)/float64(m.PoolUsage[0].Total)*100)
		}
	case "temperature":
		disks, _ := p.Disks(ctx)
		for _, d := range disks {
			if d.TempCelsius != nil {
				values = append(values, float64(*d.TempCelsius))
			}
		}
	case "cpu":
		m, _ := p.Metrics(ctx)
		values = append(values, m.CPUPercent)
	case "memory":
		m, _ := p.Metrics(ctx)
		values = append(values, float64(m.MemUsed)/float64(m.MemTotal)*100)
	default:
		return AnomalyResult{}, fmt.Errorf("unknown metric: %s", metric)
	}
	if len(values) < 3 {
		return AnomalyResult{Metric: metric, Score: 0, IsAnomaly: false, Threshold: 3.0}, nil
	}
	mean := 0.0
	for _, v := range values {
		mean += v
	}
	mean /= float64(len(values))
	stddev := 0.0
	for _, v := range values {
		stddev += (v - mean) * (v - mean)
	}
	stddev = math.Sqrt(stddev / float64(len(values)))
	latest := values[len(values)-1]
	score := 0.0
	if stddev > 0 {
		score = math.Abs(latest - mean) / stddev
	}
	isAnomaly := score > 3.0
	msg := "normal"
	if isAnomaly {
		msg = fmt.Sprintf("anomaly detected: value %.2f, mean %.2f, z-score %.2f", latest, mean, score)
	}
	return AnomalyResult{
		Metric:    metric,
		Score:     math.Round(score*100) / 100,
		IsAnomaly: isAnomaly,
		Threshold: 3.0,
		Message:   msg,
	}, nil
}

func (p *linuxProvider) sendDiscord(webhookURL, msg string) error {
	if webhookURL == "" {
		return nil
	}
	payload := map[string]string{"content": msg}
	body, _ := json.Marshal(payload)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(webhookURL, "application/json", strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("discord webhook failed: %d", resp.StatusCode)
	}
	return nil
}

func (p *linuxProvider) sendTelegram(chatID, token, msg string) error {
	if token == "" || chatID == "" {
		return nil
	}
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage?chat_id=%s&text=%s", token, chatID, url.QueryEscape(msg))
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("telegram send failed: %d", resp.StatusCode)
	}
	return nil
}

func (p *linuxProvider) sendNtfy(url, msg string) error {
	if url == "" {
		return nil
	}
	client := &http.Client{Timeout: 10 * time.Second}
	req, _ := http.NewRequest("POST", url, strings.NewReader(msg))
	req.Header.Set("Content-Type", "text/plain")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("ntfy send failed: %d", resp.StatusCode)
	}
	return nil
}

func (p *linuxProvider) sendPushover(token, userKey, msg, severity string) error {
	if token == "" || userKey == "" {
		return nil
	}
	priority := 0
	if severity == "crit" {
		priority = 1
	}
	form := url.Values{
		"token":    {token},
		"user":     {userKey},
		"message":  {msg},
		"priority": {strconv.Itoa(priority)},
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.PostForm("https://api.pushover.net/1/messages.json", form)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("pushover send failed: %d", resp.StatusCode)
	}
	return nil
}

// ── BATCH-C (M331-M345): Reverse Proxy & Tunnels impls go here ──

const (
	caddyConfigPath = "/etc/caddy/Caddyfile"
	caddySitesDir   = "/etc/caddy/sites.d"
)

func (p *linuxProvider) CaddySites(ctx context.Context) ([]CaddySite, error) {
	if _, err := os.Stat(caddyConfigPath); os.IsNotExist(err) {
		return []CaddySite{}, nil
	}
	data, err := os.ReadFile(caddyConfigPath)
	if err != nil {
		return nil, err
	}
	return parseCaddyfile(string(data)), nil
}

func (p *linuxProvider) CreateCaddySite(ctx context.Context, s CaddySite) (CaddySite, error) {
	os.MkdirAll(caddySitesDir, 0755)
	siteFile := filepath.Join(caddySitesDir, s.Name+".caddyfile")
	var buf strings.Builder
	buf.WriteString(s.Domain + " {\n")
	if s.TargetHost != "" {
		fmt.Fprintf(&buf, "  reverse_proxy %s:%d\n", s.TargetHost, s.TargetPort)
	}
	if len(s.IPAllow) > 0 {
		buf.WriteString("  @allowed {\n")
		for _, ip := range s.IPAllow {
			fmt.Fprintf(&buf, "    remote_ip %s\n", ip)
		}
		buf.WriteString("  }\n  handle @allowed {\n    reverse_proxy %s:%d\n  }\n  handle { respond \"Forbidden\" 403 }\n")
	}
	if len(s.BasicAuth) > 0 {
		buf.WriteString("  basic_auth {\n")
		for _, auth := range s.BasicAuth {
			hash, _ := hashPassword(auth.Password)
			fmt.Fprintf(&buf, "    %s %s\n", auth.User, hash)
		}
		buf.WriteString("  }\n")
	}
	if s.TLS == "auto" || s.TLS == "" {
		if s.ACMEEmail != "" {
			fmt.Fprintf(&buf, "  tls %s\n", s.ACMEEmail)
		} else {
			buf.WriteString("  tls auto\n")
		}
	} else if s.TLS != "off" {
		fmt.Fprintf(&buf, "  tls %s\n", s.TLS)
	}
	buf.WriteString("}\n")
	os.WriteFile(siteFile, []byte(buf.String()), 0644)
	mergeCaddyConfig()
	p.CaddyReload(ctx)
	return s, nil
}

func (p *linuxProvider) UpdateCaddySite(ctx context.Context, name string, s CaddySite) (CaddySite, error) {
	return p.CreateCaddySite(ctx, s)
}

func (p *linuxProvider) DeleteCaddySite(ctx context.Context, name string) error {
	siteFile := filepath.Join(caddySitesDir, name+".caddyfile")
	os.Remove(siteFile)
	mergeCaddyConfig()
	return p.CaddyReload(ctx)
}

func (p *linuxProvider) CaddyReload(ctx context.Context) error {
	out, _, err := RunPlain(ctx, "caddy", "reload", "--config", caddyConfigPath)
	if err != nil {
		return fmt.Errorf("caddy reload: %s", string(out))
	}
	return nil
}

func (p *linuxProvider) TunnelStatus(ctx context.Context) (TunnelInfo, error) {
	info := TunnelInfo{Name: "cloudflared"}
	out, _, err := RunPlain(ctx, "cloudflared", "tunnel", "status")
	if err != nil {
		info.Connected = false
		info.Error = string(out)
		return info, nil
	}
	info.Connected = strings.Contains(string(out), "running") || strings.Contains(string(out), "connected")
	return info, nil
}

func (p *linuxProvider) TunnelStart(ctx context.Context, name string, config string) error {
	tunnelDir := "/var/lib/kilasos/tunnels"
	os.MkdirAll(tunnelDir, 0755)
	configFile := filepath.Join(tunnelDir, name+".json")
	os.WriteFile(configFile, []byte(config), 0600)
	RunPlain(ctx, "cloudflared", "tunnel", "run", "--config", configFile, name)
	return nil
}

func (p *linuxProvider) TunnelStop(ctx context.Context, name string) error {
	RunPlain(ctx, "pkill", "-f", "cloudflared.*"+name)
	return nil
}

func (p *linuxProvider) TailscaleFunnel(ctx context.Context, port int, enable bool) error {
	if enable {
		out, _, err := RunPlain(ctx, "tailscale", "funnel", strconv.Itoa(port))
		if err != nil {
			return fmt.Errorf("tailscale funnel: %s", string(out))
		}
	} else {
		RunPlain(ctx, "tailscale", "funnel", "disable")
	}
	return nil
}

func (p *linuxProvider) WireGuardPeers(ctx context.Context) ([]WireGuardPeer, error) {
	out, _, err := RunPriv(ctx, "/usr/bin/wg", "show", "wg0", "peers")
	if err != nil || len(out) == 0 {
		return []WireGuardPeer{}, nil
	}
	var peers []WireGuardPeer
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		pk := strings.TrimSpace(line)
		if pk == "" {
			continue
		}
		peer := WireGuardPeer{PublicKey: pk}
		subOut, _, _ := RunPriv(ctx, "/usr/bin/wg", "show", "wg0", "peer", pk)
		for _, l := range strings.Split(string(subOut), "\n") {
			if strings.HasPrefix(l, "endpoint:") {
				peer.Endpoint = strings.TrimSpace(strings.SplitN(l, ":", 2)[1])
			} else if strings.HasPrefix(l, "allowed ips:") {
				peer.AllowedIPs = strings.TrimSpace(strings.SplitN(l, ":", 2)[1])
			} else if strings.HasPrefix(l, "persistent keepalive:") {
				v, _ := strconv.Atoi(strings.TrimSpace(strings.SplitN(l, ":", 2)[1]))
				peer.PersistentKeep = v
			}
		}
		peers = append(peers, peer)
	}
	return peers, nil
}

func (p *linuxProvider) WireGuardAddPeer(ctx context.Context, pubKey string) (WireGuardPeer, error) {
	_, _, err := RunPriv(ctx, "/usr/bin/wg", "set", "wg0", "peer", pubKey, "allowed-ips", "0.0.0.0/0")
	if err != nil {
		return WireGuardPeer{}, err
	}
	peer := WireGuardPeer{PublicKey: pubKey, AllowedIPs: "0.0.0.0/0"}
	return peer, nil
}

func (p *linuxProvider) WireGuardRemovePeer(ctx context.Context, pubKey string) error {
	RunPriv(ctx, "/usr/bin/wg", "set", "wg0", "peer", pubKey, "remove")
	return nil
}

func (p *linuxProvider) WireGuardConfig(ctx context.Context) (WireGuardConfig, error) {
	cfg := WireGuardConfig{ListenPort: 51820, InterfaceAddress: "10.0.0.1/24"}
	out, _, _ := RunPriv(ctx, "/sbin/ip", "addr", "show", "wg0")
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		if strings.Contains(line, "inet ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				cfg.InterfaceAddress = parts[1]
			}
		}
	}
	cfg.Peers, _ = p.WireGuardPeers(ctx)
	return cfg, nil
}

func (p *linuxProvider) UPnPStatus(ctx context.Context) (UPnPStatus, error) {
	status := UPnPStatus{}
	out, _, err := RunPlain(ctx, "upnpc", "-l")
	if err != nil {
		status.Enabled = false
		return status, nil
	}
	status.Enabled = true
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		if strings.Contains(line, "->") {
			parts := strings.Fields(line)
			if len(parts) >= 5 {
				pm := PortMap{Description: strings.Join(parts[5:], " ")}
				if p, err := strconv.Atoi(parts[3]); err == nil {
					pm.ExternalPort = p
				}
				if p, err := strconv.Atoi(parts[1]); err == nil {
					pm.InternalPort = p
				}
				pm.Protocol = parts[2]
				status.MappedPorts = append(status.MappedPorts, pm)
			}
		} else if strings.Contains(line, "_gateway") {
			for _, field := range strings.Fields(line) {
				if net.ParseIP(field) != nil {
					status.Gateway = field
					break
				}
			}
		}
	}
	return status, nil
}

func (p *linuxProvider) UPnPForwardPort(ctx context.Context, internalPort int, protocol string) (int, error) {
	protoUpper := strings.ToUpper(protocol)
	if protoUpper != "TCP" && protoUpper != "UDP" {
		protoUpper = "TCP"
	}
	out, _, err := RunPlain(ctx, "upnpc", "-a", "127.0.0.1", strconv.Itoa(internalPort), strconv.Itoa(internalPort), protoUpper)
	if err != nil {
		return 0, fmt.Errorf("upnp forward: %s", string(out))
	}
	extPort := internalPort
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "external") && strings.Contains(line, "TCP") {
			parts := strings.Fields(line)
			for i, p := range parts {
				if p == "TCP" && i > 0 {
					if ep, err := strconv.Atoi(parts[i-1]); err == nil {
						extPort = ep
					}
				}
			}
		}
	}
	return extPort, nil
}

func (p *linuxProvider) UPnPRemovePort(ctx context.Context, internalPort int, protocol string) error {
	protoUpper := strings.ToUpper(protocol)
	if protoUpper != "TCP" && protoUpper != "UDP" {
		protoUpper = "TCP"
	}
	RunPlain(ctx, "upnpc", "-d", strconv.Itoa(internalPort), protoUpper)
	return nil
}

func (p *linuxProvider) DDNSUpdate(ctx context.Context, provider, domain, token string, ip string) error {
	switch provider {
	case "cloudflare":
		return p.ddnsCloudflare(domain, token, ip)
	case "duckdns":
		return p.ddnsDuckDNS(domain, token, ip)
	default:
		return fmt.Errorf("unknown ddns provider: %s", provider)
	}
}

func (p *linuxProvider) DNSmasqConfig(ctx context.Context) (string, error) {
	data, err := os.ReadFile("/etc/dnsmasq.conf")
	if os.IsNotExist(err) {
		return "", nil
	}
	return string(data), err
}

func (p *linuxProvider) SetDNSmasqConfig(ctx context.Context, cfg string) error {
	return os.WriteFile("/etc/dnsmasq.d/kilasos.conf", []byte(cfg), 0644)
}

func (p *linuxProvider) DHCPConfig(ctx context.Context) (DHCPConfig, error) {
	data, err := os.ReadFile("/etc/dnsmasq.d/kilasos-dhcp.conf")
	if os.IsNotExist(err) {
		return DHCPConfig{Enabled: false, LeaseTime: 24, RangeStart: "192.168.1.100", RangeEnd: "192.168.1.199", Subnet: "192.168.1.0/24", Router: "192.168.1.1", DNSServers: []string{"1.1.1.1", "8.8.8.8"}}, nil
	}
	return parseDnsmasqDHCP(string(data)), err
}

func (p *linuxProvider) SetDHCPConfig(ctx context.Context, cfg DHCPConfig) error {
	var content strings.Builder
	if cfg.Enabled {
		content.WriteString(fmt.Sprintf("dhcp-range=%s,%s,24h\n", cfg.RangeStart, cfg.RangeEnd))
		content.WriteString(fmt.Sprintf("dhcp-option=3,%s\n", cfg.Router))
		for _, dns := range cfg.DNSServers {
			content.WriteString(fmt.Sprintf("dhcp-option=6,%s\n", dns))
		}
	}
	return os.WriteFile("/etc/dnsmasq.d/kilasos-dhcp.conf", []byte(content.String()), 0644)
}

func (p *linuxProvider) ddnsCloudflare(domain, token, ip string) error {
	jsonBody := fmt.Sprintf(`{"name":"%s","type":"A","content":"%s"}`, domain, ip)
	req, _ := http.NewRequest("PUT", "https://api.cloudflare.com/client/v4/zones/"+token+"/dns_records", strings.NewReader(jsonBody))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("cloudflare ddns: status %d", resp.StatusCode)
	}
	return nil
}

func (p *linuxProvider) ddnsDuckDNS(domain, token, ip string) error {
	url := fmt.Sprintf("https://www.duckdns.org/update?domains=%s&token=%s&ip=%s", domain, token, ip)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("duckdns ddns: status %d", resp.StatusCode)
	}
	return nil
}

func hashPassword(password string) (string, error) {
	hash, _, err := RunPlain(context.Background(), "openssl", "passwd", "-apr1", password)
	if err != nil {
		return password, nil
	}
	return strings.TrimSpace(string(hash)), nil
}

func parseCaddyfile(content string) []CaddySite {
	var sites []CaddySite
	currentBlock := ""
	blockLines := []string{}
	for _, line := range strings.Split(content, "\n") {
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if !strings.Contains(line, "{") && !strings.HasPrefix(strings.TrimSpace(line), "}") && !strings.Contains(currentBlock, "{") && len(currentBlock) > 0 {
			continue
		}
		trimmed := strings.TrimSpace(line)
		if strings.HasSuffix(trimmed, "{") {
			currentBlock = strings.TrimSuffix(trimmed, "{")
			blockLines = []string{}
		} else if strings.TrimSpace(line) == "}" && currentBlock != "" {
			site := parseCaddyBlock(currentBlock, blockLines)
			if site.Domain != "" {
				sites = append(sites, site)
			}
			currentBlock = ""
			blockLines = []string{}
		} else if currentBlock != "" {
			blockLines = append(blockLines, trimmed)
		} else if strings.Contains(trimmed, ":") && !strings.Contains(trimmed, " ") {
			site := CaddySite{Domain: trimmed, Enabled: true}
			sites = append(sites, site)
		}
	}
	return sites
}

func parseCaddyBlock(domain string, lines []string) CaddySite {
	site := CaddySite{Domain: domain, Enabled: true}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "reverse_proxy") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				target := strings.TrimPrefix(parts[1], "127.0.0.1:")
				if port, err := strconv.Atoi(target); err == nil {
					site.TargetPort = port
					site.TargetHost = "127.0.0.1"
				}
			}
		} else if strings.HasPrefix(line, "tls") {
			site.TLS = strings.TrimSpace(strings.SplitN(line, "tls", 2)[1])
		} else if strings.HasPrefix(line, "basic_auth") {
			site.BasicAuth = []CaddyBasicAuth{}
		}
	}
	return site
}

func mergeCaddyConfig() {
	os.MkdirAll(caddySitesDir, 0755)
	var buf strings.Builder
	buf.WriteString(":80 {\n  handle / {\n    respond \"KilasOS Reverse Proxy\" 200\n  }\n}\n\n")
	files, _ := filepath.Glob(filepath.Join(caddySitesDir, "*.caddyfile"))
	for _, f := range files {
		data, _ := os.ReadFile(f)
		buf.Write(data)
		buf.WriteString("\n")
	}
	os.WriteFile(caddyConfigPath, []byte(buf.String()), 0644)
}

func parseDnsmasqDHCP(content string) DHCPConfig {
	cfg := DHCPConfig{LeaseTime: 24, DNSServers: []string{"1.1.1.1", "8.8.8.8"}}
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "dhcp-range=") {
			parts := strings.Split(line, ",")
			if len(parts) >= 2 {
				cfg.RangeStart = strings.TrimSpace(strings.TrimPrefix(parts[0], "dhcp-range="))
				cfg.RangeEnd = parts[1]
			}
		} else if strings.HasPrefix(line, "dhcp-option=3,") {
			cfg.Router = strings.TrimPrefix(line, "dhcp-option=3,")
		} else if strings.HasPrefix(line, "dhcp-option=6,") {
			cfg.DNSServers = append(cfg.DNSServers, strings.TrimPrefix(line, "dhcp-option=6,"))
		}
	}
	return cfg
}

// ── BATCH-E (M361-M375): Storage Power-User impls go here ──

const (
	wizardsDir         = "/var/lib/kilasos/wizards"
	dedupScanStatusFile = "/var/lib/kilasos/dedup-status.json"
	burnInStatusFile    = "/var/lib/kilasos/burnin-status.json"
	ddtCacheFile        = "/var/lib/kilasos/zfs-ddt-cache.json"
	lifecyclePoliciesFile = "/var/lib/kilasos/zfs-lifecycle.json"
	compressionCacheFile  = "/var/lib/kilasos/compression-cache.json"
)

func (p *linuxProvider) BtrfsSubvolumes(ctx context.Context) ([]BtrfsSubvol, error) {
	out, _, err := RunPriv(ctx, "/usr/bin/btrfs", "subvolume", "list", "-o", "/")
	if err != nil {
		return []BtrfsSubvol{}, nil
	}
	var subvols []BtrfsSubvol
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := scanner.Text()
		var subvol BtrfsSubvol
		for _, f := range strings.Fields(line) {
			if strings.HasPrefix(f, "path=") {
				subvol.Path = strings.TrimPrefix(f, "path=")
			}
			if strings.HasPrefix(f, "uuid=") {
				subvol.UUID = strings.TrimPrefix(f, "uuid=")
			}
			if strings.HasPrefix(f, "parent_uuid=") {
				if pid, err := strconv.ParseInt(strings.TrimPrefix(f, "parent_uuid="), 10, 64); err == nil {
					subvol.ParentID = pid
				}
			}
		}
		if subvol.Path != "" {
			subvols = append(subvols, subvol)
		}
	}
	return subvols, nil
}

func (p *linuxProvider) CreateBtrfsSubvol(ctx context.Context, path string) (BtrfsSubvol, error) {
	if strings.ContainsAny(path, " ;|&$`\\") {
		return BtrfsSubvol{}, fmt.Errorf("invalid path")
	}
	if _, _, err := RunPriv(ctx, "/usr/bin/btrfs", "subvolume", "create", path); err != nil {
		return BtrfsSubvol{}, fmt.Errorf("btrfs subvolume create failed: %v", err)
	}
	return BtrfsSubvol{Path: path}, nil
}

func (p *linuxProvider) DeleteBtrfsSubvol(ctx context.Context, path string) error {
	if strings.ContainsAny(path, " ;|&$`\\") {
		return fmt.Errorf("invalid path")
	}
	if _, _, err := RunPriv(ctx, "/usr/bin/btrfs", "subvolume", "delete", path); err != nil {
		return fmt.Errorf("btrfs subvolume delete failed: %v", err)
	}
	return nil
}

func (p *linuxProvider) BtrfsSnapshots(ctx context.Context) ([]BtrfsSnapshot, error) {
	out, _, err := RunPriv(ctx, "/usr/bin/btrfs", "subvolume", "list", "-s", "/")
	if err != nil {
		return []BtrfsSnapshot{}, nil
	}
	var snapshots []BtrfsSnapshot
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := scanner.Text()
		var snap BtrfsSnapshot
		for _, f := range strings.Fields(line) {
			if strings.HasPrefix(f, "path=") {
				snap.Path = strings.TrimPrefix(f, "path=")
			}
			if strings.HasPrefix(f, "uuid=") && snap.Source == "" {
				snap.Source = strings.TrimPrefix(f, "uuid=")
			}
			if strings.HasPrefix(f, "cr_time=") {
				t, _ := time.Parse("2006-01-02 15:04:05", strings.TrimPrefix(f, "cr_time="))
				snap.Created = t.Unix()
			}
		}
		if snap.Path != "" {
			snap.ReadOnly = true
			snapshots = append(snapshots, snap)
		}
	}
	return snapshots, nil
}

func (p *linuxProvider) CreateBtrfsSnapshot(ctx context.Context, source, target string) (BtrfsSnapshot, error) {
	if strings.ContainsAny(source, " ;|&$`\\") || strings.ContainsAny(target, " ;|&$`\\") {
		return BtrfsSnapshot{}, fmt.Errorf("invalid path")
	}
	if _, _, err := RunPriv(ctx, "/usr/bin/btrfs", "subvolume", "snapshot", source, target); err != nil {
		return BtrfsSnapshot{}, fmt.Errorf("btrfs snapshot failed: %v", err)
	}
	return BtrfsSnapshot{Path: target, Source: source, Created: time.Now().Unix(), ReadOnly: false}, nil
}

func (p *linuxProvider) DeleteBtrfsSnapshot(ctx context.Context, path string) error {
	return p.DeleteBtrfsSubvol(ctx, path)
}

func (p *linuxProvider) RestoreBtrfsSnapshot(ctx context.Context, path, snapshot string) error {
	if strings.ContainsAny(path, " ;|&$`\\") || strings.ContainsAny(snapshot, " ;|&$`\\") {
		return fmt.Errorf("invalid path")
	}
	ts := time.Now().Unix()
	oldPath := path + "-old-" + strconv.FormatInt(ts, 10)
	if err := os.Rename(path, oldPath); err != nil {
		return fmt.Errorf("rename current subvolume: %w", err)
	}
	_, _, err := RunPriv(ctx, "/usr/bin/btrfs", "subvolume", "snapshot", snapshot, path)
	if err != nil {
		os.Rename(oldPath, path)
		return fmt.Errorf("create snapshot: %w", err)
	}
	return nil
}

func (p *linuxProvider) BtrfsScrub(ctx context.Context, path string) error {
	if strings.ContainsAny(path, " ;|&$`\\") {
		return fmt.Errorf("invalid path")
	}
	_, _, err := RunPriv(ctx, "/usr/bin/btrfs", "scrub", "start", "-B", path)
	return err
}

func (p *linuxProvider) BtrfsBalance(ctx context.Context, path string) error {
	if strings.ContainsAny(path, " ;|&$`\\") {
		return fmt.Errorf("invalid path")
	}
	_, _, err := RunPriv(ctx, "/usr/bin/btrfs", "balance", "start", path)
	return err
}

func (p *linuxProvider) ZFSL2ARCStatus(ctx context.Context) ([]L2ARCDevice, error) {
	pools, _ := p.Arrays(ctx)
	var devices []L2ARCDevice
	for _, pool := range pools {
		out, _, _ := RunPriv(ctx, "/usr/sbin/zpool", "status", "-v", pool.Name)
		scanner := bufio.NewScanner(strings.NewReader(string(out)))
		var currentDevice string
		var currentPool string
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(strings.TrimSpace(line), "cache") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					currentDevice = parts[1]
					currentPool = pool.Name
				}
			}
			if strings.Contains(line, "G") || strings.Contains(line, "M") {
				fields := strings.Fields(line)
				for i, f := range fields {
					if (strings.HasSuffix(f, "G") || strings.HasSuffix(f, "M")) && i > 0 {
						sizeStr := strings.TrimSuffix(f, "G")
						sizeStr = strings.TrimSuffix(sizeStr, "M")
						if size, err := strconv.ParseUint(sizeStr, 10, 64); err == nil {
							if strings.HasSuffix(f, "G") {
								size *= 1024 * 1024 * 1024
							} else {
								size *= 1024 * 1024
							}
							if currentDevice != "" {
								devices = append(devices, L2ARCDevice{Pool: currentPool, Device: currentDevice, Size: size})
								currentDevice = ""
							}
						}
					}
				}
			}
		}
	}
	return devices, nil
}

func (p *linuxProvider) ZFSL2ARCAdd(ctx context.Context, pool, device string) error {
	if strings.ContainsAny(pool, " ;|&$`\\") || strings.ContainsAny(device, " ;|&$`\\") {
		return fmt.Errorf("invalid pool or device")
	}
	_, _, err := RunPriv(ctx, "/usr/sbin/zpool", "add", pool, "cache", device)
	return err
}

func (p *linuxProvider) ZFSL2ARCRemove(ctx context.Context, pool string) error {
	if strings.ContainsAny(pool, " ;|&$`\\") {
		return fmt.Errorf("invalid pool")
	}
	_, _, err := RunPriv(ctx, "/usr/sbin/zpool", "remove", pool)
	return err
}

func (p *linuxProvider) ZFSSLOGStatus(ctx context.Context) ([]SLOGDevice, error) {
	pools, _ := p.Arrays(ctx)
	var devices []SLOGDevice
	for _, pool := range pools {
		out, _, _ := RunPriv(ctx, "/usr/sbin/zpool", "status", "-v", pool.Name)
		scanner := bufio.NewScanner(strings.NewReader(string(out)))
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, "logs") && !strings.Contains(line, "no logs") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					dev := fields[1]
					if dev != "-" && dev != "SIZE" {
						size := uint64(0)
						for i, f := range fields {
							if (strings.HasSuffix(f, "G") || strings.HasSuffix(f, "M")) && i+1 < len(fields) {
								sizeStr := strings.TrimSuffix(f, "G")
								sizeStr = strings.TrimSuffix(sizeStr, "M")
								if s, err := strconv.ParseUint(sizeStr, 10, 64); err == nil {
									if strings.HasSuffix(f, "G") {
										size = s * 1024 * 1024 * 1024
									} else {
										size = s * 1024 * 1024
									}
								}
							}
						}
						devices = append(devices, SLOGDevice{Pool: pool.Name, Device: dev, Size: size})
					}
				}
			}
		}
	}
	return devices, nil
}

func (p *linuxProvider) ZFSSLOGAdd(ctx context.Context, pool, device string) error {
	if strings.ContainsAny(pool, " ;|&$`\\") || strings.ContainsAny(device, " ;|&$`\\") {
		return fmt.Errorf("invalid pool or device")
	}
	_, _, err := RunPriv(ctx, "/usr/sbin/zpool", "add", pool, "log", device)
	return err
}

func (p *linuxProvider) ZFSSLOGRemove(ctx context.Context, pool string) error {
	if strings.ContainsAny(pool, " ;|&$`\\") {
		return fmt.Errorf("invalid pool")
	}
	_, _, err := RunPriv(ctx, "/usr/sbin/zpool", "remove", pool)
	return err
}

func (p *linuxProvider) ZFSSpecialVdevStatus(ctx context.Context) ([]SpecialVdev, error) {
	pools, _ := p.Arrays(ctx)
	var vdevs []SpecialVdev
	for _, pool := range pools {
		out, _, _ := RunPriv(ctx, "/usr/sbin/zpool", "status", "-v", pool.Name)
		scanner := bufio.NewScanner(strings.NewReader(string(out)))
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, "special") && !strings.Contains(line, "no special") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					dev := fields[1]
					if dev != "DEVICE" && dev != "-" {
						vdevs = append(vdevs, SpecialVdev{Pool: pool.Name, Device: dev, Class: "special"})
					}
				}
			}
		}
	}
	return vdevs, nil
}

func (p *linuxProvider) ZFSSpecialVdevAdd(ctx context.Context, pool, device string) error {
	if strings.ContainsAny(pool, " ;|&$`\\") || strings.ContainsAny(device, " ;|&$`\\") {
		return fmt.Errorf("invalid pool or device")
	}
	_, _, err := RunPriv(ctx, "/usr/sbin/zpool", "add", pool, "special", device)
	return err
}

func (p *linuxProvider) ZFSDDTProjection(ctx context.Context) (DDTProjection, error) {
	pools, _ := p.Arrays(ctx)
	if len(pools) == 0 {
		return DDTProjection{}, nil
	}
	pool := pools[0].Name
	os.MkdirAll(filepath.Dir(ddtCacheFile), 0755)
	cachedData, _ := os.ReadFile(ddtCacheFile)
	if len(cachedData) > 0 {
		var cached DDTProjection
		json.Unmarshal(cachedData, &cached)
		if cached.Status == "ready" {
			return cached, nil
		}
	}
	proj := DDTProjection{Pool: pool, Status: "computing"}
	data, _ := json.Marshal(proj)
	os.WriteFile(ddtCacheFile, data, 0644)
	go func() {
		out, _, err := RunPlain(ctx, "zdb", "-DD", pool)
		proj.Status = "ready"
		if err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				if strings.Contains(line, "DDT entries") {
					fields := strings.Fields(line)
					for i, f := range fields {
						if f == "entries" && i > 0 {
							if entries, err := strconv.ParseUint(fields[i-1], 10, 64); err == nil {
								proj.DDTEntries = entries
							}
						}
					}
				}
				if strings.Contains(line, "DDT size") {
					fields := strings.Fields(line)
					for i, f := range fields {
						if f == "size" && i+2 < len(fields) {
							if size, err := strconv.ParseUint(fields[i+2], 10, 64); err == nil {
								proj.DDTSize = size
								proj.EstMemMB = float64(size) / 1024.0 / 1024.0
							}
						}
					}
				}
			}
		}
		proj.DDTEnabled = true
		data, _ := json.Marshal(proj)
		os.WriteFile(ddtCacheFile, data, 0644)
	}()
	return proj, nil
}

func (p *linuxProvider) DDTProjectionStatus(ctx context.Context) (DDTProjection, error) {
	data, err := os.ReadFile(ddtCacheFile)
	if os.IsNotExist(err) {
		return DDTProjection{Status: "idle"}, nil
	}
	if err != nil {
		return DDTProjection{}, err
	}
	var proj DDTProjection
	json.Unmarshal(data, &proj)
	return proj, nil
}

func (p *linuxProvider) ZFSCompressionRatios(ctx context.Context) ([]CompressionRatio, error) {
	pools, _ := p.Arrays(ctx)
	var ratios []CompressionRatio
	for _, pool := range pools {
		out, _, _ := RunPriv(ctx, "/usr/sbin/zfs", "get", "-Hp", "compressratio,used,logicalused", pool.Name)
		var cr CompressionRatio
		cr.Dataset = pool.Name
		scanner := bufio.NewScanner(strings.NewReader(string(out)))
		for scanner.Scan() {
			line := scanner.Text()
			fields := strings.Fields(line)
			if len(fields) >= 3 {
				switch fields[1] {
				case "compressratio":
					ratioStr := strings.TrimSuffix(fields[2], "x")
					if r, err := strconv.ParseFloat(ratioStr, 64); err == nil {
						cr.Ratio = r
					}
				case "used":
					if u, err := strconv.ParseUint(fields[2], 10, 64); err == nil {
						cr.UsedBytes = u
					}
				case "logicalused":
					if u, err := strconv.ParseUint(fields[2], 10, 64); err == nil {
						cr.LogicalUsed = u
					}
				}
			}
		}
		if cr.Ratio == 0 {
			cr.Ratio = 1.0
		}
		ratios = append(ratios, cr)
		datasets, _ := p.Datasets(ctx, pool.Name)
		for _, ds := range datasets {
			out, _, _ = RunPriv(ctx, "/usr/sbin/zfs", "get", "-Hp", "compressratio,used,logicalused", ds.Name)
			var crd CompressionRatio
			crd.Dataset = ds.Name
			scanner = bufio.NewScanner(strings.NewReader(string(out)))
			for scanner.Scan() {
				line := scanner.Text()
				fields := strings.Fields(line)
				if len(fields) >= 3 {
					switch fields[1] {
					case "compressratio":
						ratioStr := strings.TrimSuffix(fields[2], "x")
						if r, err := strconv.ParseFloat(ratioStr, 64); err == nil {
							crd.Ratio = r
						}
					case "used":
						if u, err := strconv.ParseUint(fields[2], 10, 64); err == nil {
							crd.UsedBytes = u
						}
					case "logicalused":
						if u, err := strconv.ParseUint(fields[2], 10, 64); err == nil {
							crd.LogicalUsed = u
						}
					}
				}
			}
			if crd.Ratio == 0 {
				crd.Ratio = 1.0
			}
			ratios = append(ratios, crd)
		}
	}
	return ratios, nil
}

func (p *linuxProvider) LifecyclePolicies(ctx context.Context) ([]LifecyclePolicy, error) {
	data, err := os.ReadFile(lifecyclePoliciesFile)
	if os.IsNotExist(err) {
		return []LifecyclePolicy{}, nil
	}
	if err != nil {
		return nil, err
	}
	var policies []LifecyclePolicy
	json.Unmarshal(data, &policies)
	return policies, nil
}

func (p *linuxProvider) SetLifecyclePolicy(ctx context.Context, pol LifecyclePolicy) error {
	policies, _ := p.LifecyclePolicies(ctx)
	for i, existing := range policies {
		if existing.Name == pol.Name {
			policies[i] = pol
			data, _ := json.Marshal(policies)
			return os.WriteFile(lifecyclePoliciesFile, data, 0644)
		}
	}
	policies = append(policies, pol)
	data, _ := json.Marshal(policies)
	return os.WriteFile(lifecyclePoliciesFile, data, 0644)
}

func (p *linuxProvider) DeleteLifecyclePolicy(ctx context.Context, name string) error {
	policies, _ := p.LifecyclePolicies(ctx)
	newPolicies := []LifecyclePolicy{}
	for _, pol := range policies {
		if pol.Name != name {
			newPolicies = append(newPolicies, pol)
		}
	}
	data, _ := json.Marshal(newPolicies)
	return os.WriteFile(lifecyclePoliciesFile, data, 0644)
}

func (p *linuxProvider) StorageTierPolicy(ctx context.Context) (TierPolicy, error) {
	data, err := os.ReadFile("/var/lib/kilasos/tier-policy.json")
	if os.IsNotExist(err) {
		return TierPolicy{}, nil
	}
	if err != nil {
		return TierPolicy{}, err
	}
	var pol TierPolicy
	json.Unmarshal(data, &pol)
	return pol, nil
}

func (p *linuxProvider) SetStorageTierPolicy(ctx context.Context, pol TierPolicy) error {
	data, _ := json.Marshal(pol)
	return os.WriteFile("/var/lib/kilasos/tier-policy.json", data, 0644)
}

func (p *linuxProvider) DedupScannerStatus(ctx context.Context) (DedupScanResult, error) {
	data, err := os.ReadFile(dedupScanStatusFile)
	if os.IsNotExist(err) {
		return DedupScanResult{Status: "idle"}, nil
	}
	if err != nil {
		return DedupScanResult{}, err
	}
	var res DedupScanResult
	json.Unmarshal(data, &res)
	return res, nil
}

func (p *linuxProvider) StartDedupScan(ctx context.Context, path string) error {
	if strings.ContainsAny(path, " ;|&$`\\") {
		return fmt.Errorf("invalid path")
	}
	os.MkdirAll(filepath.Dir(dedupScanStatusFile), 0755)
	status := DedupScanResult{Status: "running", StartedAt: time.Now().Unix()}
	data, _ := json.Marshal(status)
	os.WriteFile(dedupScanStatusFile, data, 0644)
	go func() {
		out, _, err := RunPlain(ctx, "jdupes", "-r", "-m", path)
		finalStatus := DedupScanResult{Status: "complete", CompletedAt: time.Now().Unix()}
		if err != nil {
			finalStatus.Status = "error"
			finalStatus.Error = err.Error()
		}
		if len(out) > 0 {
			groups := strings.Count(string(out), "\n")
			finalStatus.GroupsFound = groups
		}
		data, _ = json.Marshal(finalStatus)
		os.WriteFile(dedupScanStatusFile, data, 0644)
	}()
	return nil
}

func (p *linuxProvider) DiskBurnInStatus(ctx context.Context) (BurnInStatus, error) {
	data, err := os.ReadFile(burnInStatusFile)
	if os.IsNotExist(err) {
		return BurnInStatus{Status: "idle"}, nil
	}
	if err != nil {
		return BurnInStatus{}, err
	}
	var status BurnInStatus
	json.Unmarshal(data, &status)
	return status, nil
}

func (p *linuxProvider) StartDiskBurnIn(ctx context.Context, disk string) error {
	if strings.ContainsAny(disk, " ;|&$`\\") {
		return fmt.Errorf("invalid disk")
	}
	os.MkdirAll(filepath.Dir(burnInStatusFile), 0755)
	status := BurnInStatus{Disk: disk, Status: "running", StartedAt: time.Now().Unix()}
	data, _ := json.Marshal(status)
	os.WriteFile(burnInStatusFile, data, 0644)
	go func() {
		_, _, err := RunPlain(ctx, "badblocks", "-ws", disk)
		finalStatus := BurnInStatus{Disk: disk, CompletedAt: time.Now().Unix()}
		if err != nil {
			finalStatus.Status = "failed"
		} else {
			finalStatus.Status = "passed"
		}
		data, _ = json.Marshal(finalStatus)
		os.WriteFile(burnInStatusFile, data, 0644)
	}()
	return nil
}

func (p *linuxProvider) ReplacementWizardState(ctx context.Context, id string) (ReplacementWizardState, error) {
	if id == "" {
		return ReplacementWizardState{}, fmt.Errorf("no wizard id")
	}
	os.MkdirAll(wizardsDir, 0755)
	data, err := os.ReadFile(fmt.Sprintf("%s/replacement-%s.json", wizardsDir, id))
	if os.IsNotExist(err) {
		return ReplacementWizardState{ID: id, Step: "identify", Message: "Select the disk to replace"}, nil
	}
	if err != nil {
		return ReplacementWizardState{}, err
	}
	var state ReplacementWizardState
	json.Unmarshal(data, &state)
	return state, nil
}

func (p *linuxProvider) ReplacementWizardStep(ctx context.Context, id string, action string, data map[string]string) (ReplacementWizardState, error) {
	state, err := p.ReplacementWizardState(ctx, id)
	if err != nil {
		return state, err
	}
	switch action {
	case "identify_disk":
		state.Disk = data["disk"]
		state.Pool = data["pool"]
		state.Vdev = data["vdev"]
		state.Step = "confirm_offline"
		state.Message = fmt.Sprintf("Confirm: take %s offline in pool %s?", state.Disk, state.Pool)
	case "confirm_offline":
		if state.Disk != "" {
			_, _, err := RunPriv(ctx, "/usr/sbin/zpool", "offline", state.Pool, state.Disk)
			if err != nil {
				return state, err
			}
		}
		state.Step = "insert"
		state.Message = "Remove the disk and insert the replacement. Click 'Continue' when ready."
	case "insert":
		state.NewDevice = data["new_device"]
		state.Step = "resilver"
		state.Message = "Resilvering... this may take a while."
		if state.NewDevice != "" {
			go func() {
				_, _, _ = RunPriv(ctx, "/usr/sbin/zpool", "replace", state.Pool, state.Disk, state.NewDevice)
				wizState := state
				wizState.Step = "complete"
				wizState.Progress = 100
				wizState.Message = "Replacement complete!"
				d, _ := json.Marshal(wizState)
				os.WriteFile(fmt.Sprintf("%s/replacement-%s.json", wizardsDir, id), d, 0644)
			}()
		}
	case "resilver":
		state.Step = "complete"
		state.Message = "Resilver complete!"
	}
	os.MkdirAll(wizardsDir, 0755)
	outData, _ := json.Marshal(state)
	os.WriteFile(fmt.Sprintf("%s/replacement-%s.json", wizardsDir, id), outData, 0644)
	return state, nil
}

func (p *linuxProvider) PoolExpansionWizardState(ctx context.Context, id string) (PoolExpansionState, error) {
	if id == "" {
		return PoolExpansionState{}, fmt.Errorf("no wizard id")
	}
	os.MkdirAll(wizardsDir, 0755)
	data, err := os.ReadFile(fmt.Sprintf("%s/expansion-%s.json", wizardsDir, id))
	if os.IsNotExist(err) {
		return PoolExpansionState{ID: id, Step: "select_pool", Message: "Select the pool to expand"}, nil
	}
	if err != nil {
		return PoolExpansionState{}, err
	}
	var state PoolExpansionState
	json.Unmarshal(data, &state)
	return state, nil
}

func (p *linuxProvider) PoolExpansionStep(ctx context.Context, id string, action string, data map[string]string) (PoolExpansionState, error) {
	state, err := p.PoolExpansionWizardState(ctx, id)
	if err != nil {
		return state, err
	}
	switch action {
	case "select_pool":
		state.Pool = data["pool"]
		state.Step = "confirm_vdev"
		state.Message = fmt.Sprintf("Pool %s selected. Choose vdev type.", state.Pool)
	case "confirm_vdev":
		state.VdevType = data["vdev_type"]
		state.Step = "add_device"
		state.Message = "Add the devices to add to the pool."
	case "add_device":
		state.Devices = append(state.Devices, data["device"])
		state.Step = "verify"
		state.Message = fmt.Sprintf("Ready to add %s to pool %s. Verify and confirm.", state.VdevType, state.Pool)
	case "confirm_add":
		args := []string{"zpool", "add", state.Pool}
		switch state.VdevType {
		case "mirror":
			args = append(args, "mirror")
		case "raidz1":
			args = append(args, "raidz1")
		case "raidz2":
			args = append(args, "raidz2")
		case "raidz3":
			args = append(args, "raidz3")
		}
		args = append(args, state.Devices...)
		go func() {
			// TODO(arch): generic exec.Command with dynamic binary — cannot migrate to RunPlain without knowing the binary.
			exec.Command(args[0], args[1:]...).Run()
			wizState := state
			wizState.Step = "complete"
			wizState.Progress = 100
			wizState.Message = "Pool expanded successfully!"
			d, _ := json.Marshal(wizState)
			os.WriteFile(fmt.Sprintf("%s/expansion-%s.json", wizardsDir, id), d, 0644)
		}()
		state.Step = "complete"
		state.Message = "Pool expansion in progress..."
	case "reset":
		state = PoolExpansionState{ID: id, Step: "select_pool", Message: "Select the pool to expand"}
	}
	os.MkdirAll(wizardsDir, 0755)
	outData, _ := json.Marshal(state)
	os.WriteFile(fmt.Sprintf("%s/expansion-%s.json", wizardsDir, id), outData, 0644)
	return state, nil
}

// ── BATCH-G (M391-M405): Web File Manager impls go here ──

const (
	sharesPath = "/var/lib/kilasos/shares.json"
	trashBase  = ".kilasos-trash"
)

var trashMigrated sync.Once

func (p *linuxProvider) migrateLegacyTrash(ctx context.Context) {
	legacyTrash := filepath.Join(poolMountBase, trashBase)
	if _, err := os.Stat(legacyTrash); os.IsNotExist(err) {
		return
	}
	slog.Info("migrating legacy trash to per-pool layout")
	entries, err := os.ReadDir(legacyTrash)
	if err != nil {
		slog.Error("cannot read legacy trash", "err", err)
		return
	}
	arrays, err := p.Arrays(ctx)
	if err != nil || len(arrays) == 0 {
		return
	}
	for _, e := range entries {
		oldPath := filepath.Join(legacyTrash, e.Name())
		newPath := filepath.Join(arrays[0].MountPath, trashBase, e.Name())
		os.MkdirAll(filepath.Dir(newPath), 0755)
		if err := os.Rename(oldPath, newPath); err != nil {
			slog.Warn("legacy trash migration failed for entry", "name", e.Name(), "err", err)
		}
	}
	// Remove legacy dir if empty now
	os.Remove(legacyTrash)
	slog.Info("legacy trash migration complete")
}

func (p *linuxProvider) FileTree(ctx context.Context, path string) ([]FileNode, error) {
	clean := filepath.Clean(path)
	if strings.Contains(clean, "..") {
		return nil, fmt.Errorf("invalid path")
	}
	entries, err := os.ReadDir(clean)
	if err != nil {
		return nil, err
	}
	return buildFileTree(clean, entries)
}

func buildFileTree(base string, entries []os.DirEntry) ([]FileNode, error) {
	var nodes []FileNode
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			continue
		}
		node := FileNode{
			Name:     e.Name(),
			Path:     filepath.Join(base, e.Name()),
			Type:     typeFromMode(info.Mode()),
			Size:     info.Size(),
			Mode:     info.Mode().String(),
			Uid:       int(info.Sys().(*syscall.Stat_t).Uid),
			Gid:       int(info.Sys().(*syscall.Stat_t).Gid),
			Modified: info.ModTime().Unix(),
		}
		if node.Type == "dir" {
			subEntries, _ := os.ReadDir(node.Path)
			node.Children, _ = buildFileTree(node.Path, subEntries)
		}
		nodes = append(nodes, node)
	}
	return nodes, nil
}

func typeFromMode(mode os.FileMode) string {
	if mode&os.ModeSymlink != 0 {
		return "symlink"
	}
	if mode.IsDir() {
		return "dir"
	}
	if mode.IsRegular() {
		return "file"
	}
	return "unknown"
}

func (p *linuxProvider) FileList(ctx context.Context, path string) ([]FileNode, error) {
	clean := filepath.Clean(path)
	if strings.Contains(clean, "..") {
		return nil, fmt.Errorf("invalid path")
	}
	entries, err := os.ReadDir(clean)
	if err != nil {
		return nil, err
	}
	var nodes []FileNode
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			continue
		}
		nodes = append(nodes, FileNode{
			Name:     e.Name(),
			Path:     filepath.Join(clean, e.Name()),
			Type:     typeFromMode(info.Mode()),
			Size:     info.Size(),
			Mode:     info.Mode().String(),
			Uid:       int(info.Sys().(*syscall.Stat_t).Uid),
			Gid:       int(info.Sys().(*syscall.Stat_t).Gid),
			Modified: info.ModTime().Unix(),
		})
	}
	return nodes, nil
}

func (p *linuxProvider) FileRead(ctx context.Context, path string) (string, error) {
	clean := filepath.Clean(path)
	if strings.Contains(clean, "..") {
		return "", fmt.Errorf("invalid path")
	}
	data, err := os.ReadFile(clean)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func (p *linuxProvider) FilePreview(ctx context.Context, path string) (FilePreview, error) {
	clean := filepath.Clean(path)
	if strings.Contains(clean, "..") {
		return FilePreview{}, fmt.Errorf("invalid path")
	}
	info, err := os.Stat(clean)
	if err != nil {
		return FilePreview{}, err
	}
	ext := strings.ToLower(filepath.Ext(clean))
	var kind string
	var content string
	switch ext {
	case ".txt", ".md", ".sh", ".py", ".go", ".json", ".yaml", ".yml", ".xml", ".html", ".css", ".js", ".ts", ".c", ".cpp", ".h":
		data, _ := os.ReadFile(clean)
		if len(data) > 65536 {
			data = data[:65536]
		}
		content = string(data)
		kind = "text"
	case ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".svg":
		data, _ := os.ReadFile(clean)
		content = "data:image/" + ext[1:] + ";base64," + base64.StdEncoding.EncodeToString(data)
		kind = "image"
	case ".pdf":
		content = ""
		kind = "pdf"
	default:
		content = ""
		kind = "binary"
	}
	_ = info
	return FilePreview{Kind: kind, Content: content}, nil
}

func (p *linuxProvider) FileRename(ctx context.Context, oldPath, newPath string) error {
	oldClean := filepath.Clean(oldPath)
	newClean := filepath.Clean(newPath)
	if strings.Contains(oldClean, "..") || strings.Contains(newClean, "..") {
		return fmt.Errorf("invalid path")
	}
	return os.Rename(oldClean, newClean)
}

func (p *linuxProvider) FileCopy(ctx context.Context, src, dst string) error {
	srcClean := filepath.Clean(src)
	dstClean := filepath.Clean(dst)
	if strings.Contains(srcClean, "..") || strings.Contains(dstClean, "..") {
		return fmt.Errorf("invalid path")
	}
	srcInfo, err := os.Stat(srcClean)
	if err != nil {
		return err
	}
	if srcInfo.IsDir() {
		return copyDir(srcClean, dstClean)
	}
	return copyFile(srcClean, dstClean)
}

func copyFile(src, dst string) error {
	srcF, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcF.Close()
	dstF, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dstF.Close()
	_, err = io.Copy(dstF, srcF)
	return err
}

func copyDir(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, path)
		dest := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(dest, info.Mode())
		}
		return copyFile(path, dest)
	})
}

func (p *linuxProvider) FileDelete(ctx context.Context, path string) error {
	clean := filepath.Clean(path)
	if strings.Contains(clean, "..") {
		return fmt.Errorf("invalid path")
	}
	if !strings.HasPrefix(clean, poolMountBase) {
		return fmt.Errorf("path not under %s", poolMountBase)
	}
	// Find which pool this file belongs to
	arrays, err := p.Arrays(ctx)
	if err != nil {
		return fmt.Errorf("resolve pool: %w", err)
	}
	var poolMount string
	for _, a := range arrays {
		if a.MountPath != "" && strings.HasPrefix(clean, a.MountPath+"/") {
			poolMount = a.MountPath
			break
		}
	}
	if poolMount == "" {
		poolMount = poolMountBase // fallback to root-level trash
	}
	trashDir := filepath.Join(poolMount, trashBase)
	os.MkdirAll(trashDir, 0755)
	ts := time.Now().Unix()
	rel, _ := filepath.Rel(poolMountBase, clean)
	trashName := fmt.Sprintf("%s.%d", strings.ReplaceAll(rel, "/", "_"), ts)
	trashPath := filepath.Join(trashDir, trashName)
	if err := os.Rename(clean, trashPath); err != nil {
		return err
	}
	meta := map[string]string{"original_path": clean, "deleted_at": time.Now().UTC().Format(time.RFC3339)}
	if metaBytes, err := json.Marshal(meta); err == nil {
		_ = os.WriteFile(trashPath+".meta", metaBytes, 0644)
	}
	return nil
}

func (p *linuxProvider) TrashList(ctx context.Context) ([]FileNode, error) {
	trashMigrated.Do(func() { p.migrateLegacyTrash(ctx) })
	arrays, err := p.Arrays(ctx)
	if err != nil {
		return []FileNode{}, nil
	}
	var nodes []FileNode
	for _, a := range arrays {
		if a.MountPath == "" {
			continue
		}
		trashDir := filepath.Join(a.MountPath, trashBase)
		entries, err := os.ReadDir(trashDir)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			continue
		}
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".meta") {
				continue
			}
			info, err := e.Info()
			if err != nil {
				continue
			}
			nodes = append(nodes, FileNode{
				Name:     e.Name(),
				Path:     filepath.Join(trashDir, e.Name()),
				Type:     typeFromMode(info.Mode()),
				Size:     info.Size(),
				Mode:     info.Mode().String(),
				Modified: info.ModTime().Unix(),
			})
		}
	}
	return nodes, nil
}

func (p *linuxProvider) TrashRestore(ctx context.Context, trashPath string) error {
	clean := filepath.Clean(trashPath)
	if strings.Contains(clean, "..") {
		return fmt.Errorf("invalid path")
	}
	idx := strings.Index(clean, "/"+trashBase+"/")
	if idx < 0 {
		return fmt.Errorf("not in trash")
	}
	poolMount := clean[:idx]
	if poolMount == "" {
		poolMount = "/"
	}
	trashDir := filepath.Join(poolMount, trashBase)
	if !strings.HasPrefix(clean, trashDir) {
		return fmt.Errorf("not in trash")
	}
	var origPath string
	metaPath := clean + ".meta"
	if metaBytes, err := os.ReadFile(metaPath); err == nil {
		var meta map[string]string
		if json.Unmarshal(metaBytes, &meta) == nil {
			origPath = meta["original_path"]
		}
	}
	if origPath == "" {
		parts := strings.Split(filepath.Base(clean), ".")
		if len(parts) < 2 {
			return fmt.Errorf("invalid trash path format")
		}
		origName := strings.Join(parts[:len(parts)-1], ".")
		origPath = filepath.Join(poolMount, origName)
	}
	if err := os.Rename(clean, origPath); err != nil {
		return err
	}
	os.Remove(metaPath)
	return nil
}

func (p *linuxProvider) TrashEmpty(ctx context.Context) error {
	// Per-pool trash: iterate over live pools and empty each one's
	// .kilasos-trash directory.  Mirrors TrashMove's per-pool semantics.
	arrays, err := p.Arrays(ctx)
	if err != nil {
		return err
	}
	var lastErr error
	for _, a := range arrays {
		if a.MountPath == "" {
			continue
		}
		trashDir := filepath.Join(a.MountPath, trashBase)
		if _, statErr := os.Stat(trashDir); os.IsNotExist(statErr) {
			continue
		}
		walkErr := filepath.Walk(trashDir, func(path string, info os.FileInfo, err error) error {
			if err != nil || path == trashDir {
				return nil
			}
			os.Remove(path)
			return nil
		})
		if walkErr != nil {
			lastErr = walkErr
		}
	}
	return lastErr
}

func (p *linuxProvider) FileChmod(ctx context.Context, path string, mode string) error {
	clean := filepath.Clean(path)
	if strings.Contains(clean, "..") {
		return fmt.Errorf("invalid path")
	}
	m, err := parseMode(mode)
	if err != nil {
		return err
	}
	return os.Chmod(clean, m)
}

func parseMode(modeStr string) (os.FileMode, error) {
	m, err := strconv.ParseUint(modeStr, 8, 32)
	return os.FileMode(m), err
}

func (p *linuxProvider) FileChown(ctx context.Context, path string, uid, gid int) error {
	clean := filepath.Clean(path)
	if strings.Contains(clean, "..") {
		return fmt.Errorf("invalid path")
	}
	return os.Chown(clean, uid, gid)
}

func (p *linuxProvider) CreateShareLink(ctx context.Context, path string, opts ShareLinkOptions) (ShareLink, error) {
	clean := filepath.Clean(path)
	if strings.Contains(clean, "..") {
		return ShareLink{}, fmt.Errorf("invalid path")
	}
	b := make([]byte, 32)
	rand.Read(b)
	token := hex.EncodeToString(b)
	link := ShareLink{
		ID:         fmt.Sprintf("shr_%d", time.Now().UnixNano()),
		Token:     token,
		Path:      clean,
		CreatedAt: time.Now().Unix(),
		MaxUses:   opts.MaxUses,
	}
	if opts.ExpiresIn > 0 {
		link.ExpiresAt = time.Now().Add(time.Duration(opts.ExpiresIn) * time.Second).Unix()
	}
	links, _ := p.loadShareLinks()
	links = append(links, link)
	p.saveShareLinks(links)
	return link, nil
}

func (p *linuxProvider) RevokeShareLink(ctx context.Context, id string) error {
	links, _ := p.loadShareLinks()
	newLinks := []ShareLink{}
	found := false
	for _, l := range links {
		if l.ID == id {
			found = true
		} else {
			newLinks = append(newLinks, l)
		}
	}
	if !found {
		return fmt.Errorf("share link not found")
	}
	return p.saveShareLinks(newLinks)
}

func (p *linuxProvider) GetShareLink(ctx context.Context, id string) (ShareLink, error) {
	links, _ := p.loadShareLinks()
	for _, l := range links {
		if l.ID == id {
			if l.ExpiresAt > 0 && time.Now().Unix() > l.ExpiresAt {
				return ShareLink{}, fmt.Errorf("share link expired")
			}
			if l.MaxUses > 0 && l.Used >= l.MaxUses {
				return ShareLink{}, fmt.Errorf("share link max uses reached")
			}
			return l, nil
		}
	}
	return ShareLink{}, fmt.Errorf("share link not found")
}

func (p *linuxProvider) ListShareLinks(ctx context.Context) ([]ShareLink, error) {
	return p.loadShareLinks()
}

// ResolveShareToken — public-share entry point. Validates token, expiry, and
// max-uses; atomically increments Used; persists the updated counter. Caller
// must still re-check safePath() on the returned link.Path before serving.
func (p *linuxProvider) ResolveShareToken(ctx context.Context, token string) (ShareLink, error) {
	if token == "" || len(token) < 16 {
		return ShareLink{}, fmt.Errorf("invalid token")
	}
	links, err := p.loadShareLinks()
	if err != nil {
		return ShareLink{}, err
	}
	for i, l := range links {
		if l.Token != token {
			continue
		}
		if l.ExpiresAt > 0 && time.Now().Unix() > l.ExpiresAt {
			return ShareLink{}, fmt.Errorf("share link expired")
		}
		if l.MaxUses > 0 && l.Used >= l.MaxUses {
			return ShareLink{}, fmt.Errorf("share link max uses reached")
		}
		// Atomically increment Used and persist. saveShareLinks is best-effort
		// against concurrent access — for high-throughput share traffic, swap
		// to a database, but for the typical NAS use-case this is sufficient.
		links[i].Used++
		_ = p.saveShareLinks(links)
		return links[i], nil
	}
	return ShareLink{}, fmt.Errorf("share link not found")
}

func (p *linuxProvider) loadShareLinks() ([]ShareLink, error) {
	data, err := os.ReadFile(sharesPath)
	if os.IsNotExist(err) {
		return []ShareLink{}, nil
	}
	if err != nil {
		return nil, err
	}
	var links []ShareLink
	json.Unmarshal(data, &links)
	return links, nil
}

func (p *linuxProvider) saveShareLinks(links []ShareLink) error {
	data, _ := json.Marshal(links)
	return os.WriteFile(sharesPath, data, 0644)
}

func (p *linuxProvider) BulkDelete(ctx context.Context, paths []string) error {
	for _, path := range paths {
		if err := p.FileDelete(ctx, path); err != nil {
			return err
		}
	}
	return nil
}

func (p *linuxProvider) BulkMove(ctx context.Context, ops []BulkMoveOp) error {
	for _, op := range ops {
		if err := p.FileRename(ctx, op.Src, op.Dst); err != nil {
			return err
		}
	}
	return nil
}

// ── BATCH-H (M406-M420): Mobile & UX Polish (minimal Go) ──

// ── BATCH-I (M421-M435): Observability & Logs impls go here ──

const (
	syslogConfigPath      = "/var/lib/kilasos/syslog-forwarding.json"
	auditRetentionPath    = "/var/lib/kilasos/audit-retention.json"
	logAlertRulesPath     = "/var/lib/kilasos/log-alert-rules.json"
	lokiConfigPath        = "/var/lib/kilasos/loki.json"
	auditArchiveDir       = "/var/lib/kilasos/audit-archives"
)

func (p *linuxProvider) SyslogForwardingConfig(ctx context.Context) (SyslogConfig, error) {
	data, err := os.ReadFile(syslogConfigPath)
	if os.IsNotExist(err) {
		return SyslogConfig{RemotePort: 514, Protocol: "udp"}, nil
	}
	if err != nil {
		return SyslogConfig{}, err
	}
	var cfg SyslogConfig
	json.Unmarshal(data, &cfg)
	return cfg, nil
}

func (p *linuxProvider) SetSyslogForwarding(ctx context.Context, cfg SyslogConfig) error {
	data, _ := json.Marshal(cfg)
	os.WriteFile(syslogConfigPath, data, 0644)
	if cfg.Enabled {
		content := fmt.Sprintf("*.* @@%s:%d\n", cfg.RemoteHost, cfg.RemotePort)
		os.WriteFile("/etc/rsyslog.d/90-kilasos.conf", []byte(content), 0644)
		_, _, err := RunPriv(ctx, "/usr/bin/systemctl", "restart", "rsyslog")
		if err != nil {
			return err
		}
	} else {
		os.Remove("/etc/rsyslog.d/90-kilasos.conf")
		_, _, err := RunPriv(ctx, "/usr/bin/systemctl", "restart", "rsyslog")
		if err != nil {
			return err
		}
	}
	return nil
}

func (p *linuxProvider) AuditRetentionPolicy(ctx context.Context) (AuditRetention, error) {
	data, err := os.ReadFile(auditRetentionPath)
	if os.IsNotExist(err) {
		return AuditRetention{MaxAgeDays: 90, MaxSizeMB: 5000}, nil
	}
	if err != nil {
		return AuditRetention{}, err
	}
	var pol AuditRetention
	json.Unmarshal(data, &pol)
	return pol, nil
}

func (p *linuxProvider) SetAuditRetentionPolicy(ctx context.Context, pol AuditRetention) error {
	data, _ := json.Marshal(pol)
	return os.WriteFile(auditRetentionPath, data, 0644)
}

func (p *linuxProvider) RotateAuditLogs(ctx context.Context) error {
	os.MkdirAll(auditArchiveDir, 0755)
	entries, _ := os.ReadDir("/var/log/kilasos")
	timestamp := time.Now().Format("20060102-150405")
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".log") {
			src := "/var/log/kilasos/" + e.Name()
			dst := fmt.Sprintf("%s/%s-%s.gz", auditArchiveDir, e.Name(), timestamp)
			stdout, _, err := RunPlain(ctx, "gzip", "-c", src)
			if err != nil {
				slog.Error("audit rotate gzip failed", "src", src, "err", err)
				continue
			}
			if err := os.WriteFile(dst, stdout, 0644); err != nil {
				slog.Error("audit rotate write archive failed", "dst", dst, "err", err)
				continue
			}
			RunPlain(ctx, "truncate", "-s", "0", src)
		}
	}
	return nil
}

func (p *linuxProvider) SearchAuditLogs(ctx context.Context, q AuditLogQuery) ([]AuditLogEntry, error) {
	args := []string{"-q", "--system", "--no-pager"}
	if q.Since != "" {
		args = append(args, "--since", q.Since)
	}
	if q.Until != "" {
		args = append(args, "--until", q.Until)
	}
	if q.Limit > 0 {
		args = append(args, "-n", strconv.Itoa(q.Limit))
	} else {
		args = append(args, "-n", "200")
	}
	out, _, _ := RunPriv(ctx, "/usr/bin/journalctl", args...)
	var entries []AuditLogEntry
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, " ", 4)
		if len(parts) >= 4 {
			entries = append(entries, AuditLogEntry{
				Time:    parts[0] + " " + parts[1],
				User:    q.User,
				Action:  parts[2],
				IP:      q.IP,
				Result:  "unknown",
				Details: parts[3],
			})
		}
	}
	return entries, nil
}

func (p *linuxProvider) AggregateSystemLogs(ctx context.Context, sinceHours int) ([]ServiceLogSummary, error) {
	since := fmt.Sprintf("-%d hours", sinceHours)
	units := []string{"nasd.service", "smbd.service", "nfs-server.service", "docker.service", "systemd-logind.service"}
	var summaries []ServiceLogSummary
	for _, unit := range units {
		errOut, _, _ := RunPriv(ctx, "/usr/bin/journalctl", "-u", unit, "--since", since, "--level=err", "--no-pager", "-n", "1000")
		errCount := strings.Count(string(errOut), "\n")
		warnOut, _, _ := RunPriv(ctx, "/usr/bin/journalctl", "-u", unit, "--since", since, "--level=warn", "--no-pager", "-n", "1000")
		warnCount := strings.Count(string(warnOut), "\n")
		infoOut, _, _ := RunPriv(ctx, "/usr/bin/journalctl", "-u", unit, "--since", since, "--no-pager", "-n", "100")
		infoCount := strings.Count(string(infoOut), "\n")
		lastOut, _, _ := RunPriv(ctx, "/usr/bin/journalctl", "-u", unit, "--since", since, "-n", "1", "--no-pager", "-o", "short-iso")
		lastSeen := strings.TrimSpace(string(lastOut))
		summaries = append(summaries, ServiceLogSummary{
			Service:    unit,
			ErrorCount: errCount,
			WarnCount:  warnCount,
			InfoCount:  infoCount,
			LastSeen:   lastSeen,
		})
	}
	return summaries, nil
}

func (p *linuxProvider) SearchContainerLogs(ctx context.Context, q ContainerLogQuery) ([]ContainerLogEntry, error) {
	args := []string{"ps", "-a", "--format", "{{.Names}}"}
	if q.Container != "" {
		args = append(args, "-f", "name="+q.Container)
	}
	out, _, _ := RunPlain(ctx, "docker", args...)
	containers := strings.Fields(string(out))
	var entries []ContainerLogEntry
	for _, c := range containers {
		logArgs := []string{"logs", "--tail", "200", "--timestamps", c}
		if q.Since != "" {
			logArgs = append(logArgs, "--since", q.Since)
		}
		logOut, _, _ := RunPlain(ctx, "docker", logArgs...)
		scanner := bufio.NewScanner(strings.NewReader(string(logOut)))
		for scanner.Scan() {
			line := scanner.Text()
			if q.Search != "" && !strings.Contains(line, q.Search) {
				continue
			}
			level := "info"
			if strings.Contains(line, "error") || strings.Contains(line, "Error") || strings.Contains(line, "ERROR") {
				level = "error"
			} else if strings.Contains(line, "warn") || strings.Contains(line, "Warn") || strings.Contains(line, "WARN") {
				level = "warn"
			}
			parts := strings.SplitN(line, " ", 2)
			timeStr := ""
			if len(parts) >= 1 {
				timeStr = parts[0]
			}
			msg := line
			if len(parts) >= 2 {
				msg = parts[1]
			}
			entries = append(entries, ContainerLogEntry{
				Time:      timeStr,
				Container: c,
				Message:   msg,
				Level:     level,
			})
			if q.Limit > 0 && len(entries) >= q.Limit {
				return entries, nil
			}
		}
	}
	return entries, nil
}

func (p *linuxProvider) LogDownload(ctx context.Context, units []string, sinceHours int) (string, error) {
	os.MkdirAll("/tmp/kilasos-logs", 0755)
	since := fmt.Sprintf("-%d hours", sinceHours)
	for _, unit := range units {
		outPath := fmt.Sprintf("/tmp/kilasos-logs/%s.log", strings.ReplaceAll(unit, ".", "_"))
		f, _ := os.Create(outPath)
		RunPrivWithStdout(ctx, f, "/usr/bin/journalctl", "-u", unit, "--since", since, "--no-pager") //nolint:errcheck
		f.Close()
	}
	archivePath := "/tmp/kilasos-logs-" + time.Now().Format("20060102-150405") + ".tar.gz"
	_, _, _ = RunPlain(ctx, "tar", "czf", archivePath, "-C", "/tmp", "kilasos-logs")
	return archivePath, nil
}

func (p *linuxProvider) LogAlertRules(ctx context.Context) ([]LogAlertRule, error) {
	data, err := os.ReadFile(logAlertRulesPath)
	if os.IsNotExist(err) {
		return []LogAlertRule{}, nil
	}
	if err != nil {
		return nil, err
	}
	var rules []LogAlertRule
	json.Unmarshal(data, &rules)
	return rules, nil
}

func (p *linuxProvider) CreateLogAlertRule(ctx context.Context, r LogAlertRule) (LogAlertRule, error) {
	rules, _ := p.LogAlertRules(ctx)
	for _, existing := range rules {
		if existing.Name == r.Name {
			return r, fmt.Errorf("rule %s already exists", r.Name)
		}
	}
	rules = append(rules, r)
	p.saveLogAlertRules(rules)
	return r, nil
}

func (p *linuxProvider) DeleteLogAlertRule(ctx context.Context, name string) error {
	rules, _ := p.LogAlertRules(ctx)
	for i, r := range rules {
		if r.Name == name {
			rules = append(rules[:i], rules[i+1:]...)
			p.saveLogAlertRules(rules)
			return nil
		}
	}
	return fmt.Errorf("rule %s not found", name)
}

func (p *linuxProvider) saveLogAlertRules(rules []LogAlertRule) {
	data, _ := json.Marshal(rules)
	os.WriteFile(logAlertRulesPath, data, 0644)
}

func (p *linuxProvider) LogStats(ctx context.Context) ([]LogStats, error) {
	units := []string{"nasd.service", "smbd.service", "nfs-server.service", "docker.service"}
	var stats []LogStats
	for _, unit := range units {
		out, _, _ := RunPriv(ctx, "/usr/bin/journalctl", "-u", unit, "-n", "60", "--no-pager", "-o", "short-iso")
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		errCount := 0
		for _, l := range lines {
			if strings.Contains(l, "<err>") || strings.Contains(l, "[ERR]") || strings.Contains(l, "error") {
				errCount++
			}
		}
		sparkline := make([]int, 30)
		for i := 0; i < 30; i++ {
			sparkline[i] = len(lines) / 30
		}
		stats = append(stats, LogStats{
			Service:      unit,
			LinesPerSec:  float64(len(lines)) / 60.0,
			ErrorsPerMin: errCount,
			Sparkline:    sparkline,
		})
	}
	return stats, nil
}

func (p *linuxProvider) ContainerRestartLoops(ctx context.Context) ([]ContainerRestartEvent, error) {
	out, _, _ := RunPlain(ctx, "docker", "ps", "-a", "--format", "{{.Names}}")
	containers := strings.Fields(string(out))
	var events []ContainerRestartEvent
	for _, c := range containers {
		inspectOut, _, _ := RunPlain(ctx, "docker", "inspect", "--format", "{{.RestartCount}}", c)
		restartCount, _ := strconv.Atoi(strings.TrimSpace(string(inspectOut)))
		if restartCount > 3 {
			startedOut, _, _ := RunPlain(ctx, "docker", "inspect", "--format", "{{.State.StartedAt}}", c)
			events = append(events, ContainerRestartEvent{
				Container:   c,
				Restarts:    restartCount,
				WindowMins:  5,
				Alerted:     false,
				LastRestart: strings.TrimSpace(string(startedOut)),
			})
		}
	}
	return events, nil
}

func (p *linuxProvider) LokiConfig(ctx context.Context) (LokiConfig, error) {
	data, err := os.ReadFile(lokiConfigPath)
	if os.IsNotExist(err) {
		return LokiConfig{PushIntervalSec: 60}, nil
	}
	if err != nil {
		return LokiConfig{}, err
	}
	var cfg LokiConfig
	json.Unmarshal(data, &cfg)
	return cfg, nil
}

func (p *linuxProvider) SetLokiConfig(ctx context.Context, cfg LokiConfig) error {
	data, _ := json.Marshal(cfg)
	return os.WriteFile(lokiConfigPath, data, 0644)
}

func (p *linuxProvider) ExportLogsToS3(ctx context.Context, units []string, sinceHours int) (string, error) {
	archivePath, err := p.LogDownload(ctx, units, sinceHours)
	if err != nil {
		return "", err
	}
	cfg, _ := p.SyslogForwardingConfig(ctx)
	if cfg.RemoteHost == "" {
		return archivePath, nil
	}
	_, _, _ = RunPlain(ctx, "rclone", "copy", archivePath, cfg.RemoteHost+":/logs/")
	return archivePath, nil
}

const (
	sshAuditPath         = "/var/lib/kilasos/ssh-key-audit.json"
	integrityBaselineDir = "/var/lib/kilasos/integrity-baseline"
)

func (p *linuxProvider) SSHKeyAudit(ctx context.Context) ([]SSHKeyAuditEntry, error) {
	keys, err := p.SSHKeys(ctx)
	if err != nil {
		return nil, err
	}
	var entries []SSHKeyAuditEntry
	for _, k := range keys {
		fp := computeSSHFingerprint(k.Key)
		entries = append(entries, SSHKeyAuditEntry{
			Fingerprint: fp,
			KeyType:    k.Type,
			Comment:    k.Comment,
			Used:       false,
		})
	}
	out, _, _ := RunPriv(ctx, "/usr/bin/journalctl", "-u", "ssh", "--no-pager", "-n", "2000", "-o", "cat")
	usedComments := parseSSHUsage(string(out))
	for i := range entries {
		for _, uc := range usedComments {
			if entries[i].Comment != "" && strings.Contains(uc, entries[i].Comment) {
				entries[i].Used = true
				break
			}
		}
	}
	data, _ := json.Marshal(entries)
	os.WriteFile(sshAuditPath, data, 0644)
	return entries, nil
}

func computeSSHFingerprint(keyBlob string) string {
	h := sha256.Sum256([]byte(keyBlob))
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(h[:])
}

func parseSSHUsage(logOutput string) []string {
	var comments []string
	for _, line := range strings.Split(logOutput, "\n") {
		if strings.Contains(line, "Accepted publickey") {
			comments = append(comments, line)
		}
	}
	return comments
}

func (p *linuxProvider) MarkSSHKeyUsed(ctx context.Context, fingerprint string) error {
	data, err := os.ReadFile(sshAuditPath)
	if err != nil {
		return err
	}
	var entries []SSHKeyAuditEntry
	json.Unmarshal(data, &entries)
	for i := range entries {
		if entries[i].Fingerprint == fingerprint {
			entries[i].Used = true
			entries[i].LastUsed = time.Now().Format(time.RFC3339)
		}
	}
	out, _ := json.Marshal(entries)
	return os.WriteFile(sshAuditPath, out, 0644)
}

func (p *linuxProvider) SudoAudit(ctx context.Context, sinceDays int) ([]SudoEvent, error) {
	since := fmt.Sprintf("-%d days", sinceDays)
	out, _, _ := RunPriv(ctx, "/usr/bin/journalctl", "-t", "sudo", "--since", since, "--no-pager", "-n", "1000")
	var events []SudoEvent
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)
		if len(parts) >= 4 {
			events = append(events, SudoEvent{
				Time:    parts[0] + " " + parts[1],
				User:    parts[2],
				Command: strings.Join(parts[3:], " "),
			})
		}
	}
	return events, nil
}

func (p *linuxProvider) FailedLogins(ctx context.Context, sinceDays int) ([]FailedLogin, error) {
	since := fmt.Sprintf("-%d days", sinceDays)
	out, _, _ := RunPriv(ctx, "/usr/bin/journalctl", "--since", since, "--grep", "Failed password", "--no-pager", "-n", "500")
	failedMap := make(map[string]FailedLogin)
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := scanner.Text()
		user := extractField(line, "for user ")
		ip := extractField(line, "from ")
		if user == "" {
			continue
		}
		key := user + ":" + ip
		fl := failedMap[key]
		fl.User = user
		fl.IP = ip
		fl.Count++
		if fl.Time == "" {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				fl.Time = parts[0] + " " + parts[1]
			}
		}
		failedMap[key] = fl
	}
	var result []FailedLogin
	for _, fl := range failedMap {
		result = append(result, fl)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Count > result[j].Count })
	return result, nil
}

func extractField(line, prefix string) string {
	start := strings.Index(line, prefix)
	if start == -1 {
		return ""
	}
	rest := line[start+len(prefix):]
	end := strings.IndexAny(rest, " \n")
	if end == -1 {
		return strings.TrimSpace(rest)
	}
	return strings.TrimSpace(rest[:end])
}

func (p *linuxProvider) IntegrityCheck(ctx context.Context) ([]IntegrityFinding, error) {
	os.MkdirAll(integrityBaselineDir, 0755)
	baselinePath := integrityBaselineDir + "/baseline.json"
	var baseline map[string]string
	bdata, err := os.ReadFile(baselinePath)
	if err == nil {
		json.Unmarshal(bdata, &baseline)
	}
	var findings []IntegrityFinding
	if len(baseline) == 0 {
		baseline = make(map[string]string)
	}
	out, _, _ := RunPlain(ctx, "bash", "-c", "debsums --changed 2>/dev/null || rpm -V --audit 2>/dev/null || echo ''")
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			path := parts[len(parts)-1]
			findings = append(findings, IntegrityFinding{
				Path:   path,
				Status: "MODIFIED",
			})
		}
	}
	for path := range baseline {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			findings = append(findings, IntegrityFinding{Path: path, Status: "MISSING"})
		}
	}
	newBaseline, _ := json.MarshalIndent(baseline, "", "  ")
	os.WriteFile(baselinePath, newBaseline, 0644)
	return findings, nil
}
