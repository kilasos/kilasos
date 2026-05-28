package appcatalog

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// AppTemplate is a pre-built Docker Compose recipe.
type AppTemplate struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Icon        string   `json:"icon"`
	Port        string   `json:"port"`
	Category    []string `json:"category,omitempty"`
	Compose     string   `json:"compose"`
}

var Catalog = []AppTemplate{
	{
		ID: "jellyfin", Name: "Jellyfin", Icon: "🎬",
		Description: "Open-source media server for video, music, and photos.",
		Port:        "8096",
		Compose: `services:
  jellyfin:
    image: jellyfin/jellyfin:latest
    container_name: {{NAME}}
    restart: unless-stopped
    network_mode: host
    volumes:
      - {{DATA_PATH}}/config:/config
      - {{DATA_PATH}}/cache:/cache
      - /mnt:/mnt:ro
`,
	},
	{
		ID: "plex", Name: "Plex", Icon: "🎞",
		Description: "Powerful media server with rich client support.",
		Port:        "32400",
		Compose: `services:
  plex:
    image: plexinc/pms-docker:latest
    container_name: {{NAME}}
    restart: unless-stopped
    network_mode: host
    environment:
      - TZ=UTC
      - PLEX_CLAIM=
    volumes:
      - {{DATA_PATH}}/config:/config
      - /mnt:/data:ro
`,
	},
	{
		ID: "nextcloud", Name: "Nextcloud", Icon: "☁️",
		Description: "Self-hosted file sync and collaboration platform.",
		Port:        "8088",
		Compose: `services:
  nextcloud:
    image: nextcloud:latest
    container_name: {{NAME}}
    restart: unless-stopped
    ports:
      - "8088:80"
    volumes:
      - {{DATA_PATH}}/data:/var/www/html
`,
	},
	{
		ID: "portainer", Name: "Portainer", Icon: "🐳",
		Description: "Web UI for managing Docker containers and stacks.",
		Port:        "9000",
		Compose: `services:
  portainer:
    image: portainer/portainer-ce:latest
    container_name: {{NAME}}
    restart: unless-stopped
    ports:
      - "9000:9000"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - {{DATA_PATH}}/data:/data
`,
	},
	{
		ID: "uptime-kuma", Name: "Uptime Kuma", Icon: "📡",
		Description: "Self-hosted uptime and status monitoring tool.",
		Port:        "3001",
		Compose: `services:
  uptime-kuma:
    image: louislam/uptime-kuma:latest
    container_name: {{NAME}}
    restart: unless-stopped
    ports:
      - "3001:3001"
    volumes:
      - {{DATA_PATH}}/data:/app/data
`,
	},
	{
		ID: "homer", Name: "Homer", Icon: "🏠",
		Description: "A dead simple static homepage for your server.",
		Port:        "8902",
		Compose: `services:
  homer:
    image: b4bz/homer:latest
    container_name: {{NAME}}
    restart: unless-stopped
    ports:
      - "8902:8080"
    volumes:
      - {{DATA_PATH}}/assets:/www/assets
`,
	},
	{
		ID: "filebrowser", Name: "File Browser", Icon: "📂",
		Description: "Web-based file manager for your NAS storage.",
		Port:        "8903",
		Compose: `services:
  filebrowser:
    image: filebrowser/filebrowser:latest
    container_name: {{NAME}}
    restart: unless-stopped
    ports:
      - "8903:80"
    volumes:
      - /mnt:/srv
      - {{DATA_PATH}}/filebrowser.db:/database.db
`,
	},
	{
		ID: "transmission", Name: "Transmission", Icon: "⬇",
		Description: "Lightweight BitTorrent client with a web interface.",
		Port:        "9091",
		Compose: `services:
  transmission:
    image: linuxserver/transmission:latest
    container_name: {{NAME}}
    restart: unless-stopped
    ports:
      - "9091:9091"
      - "51413:51413"
    environment:
      - PUID=1000
      - PGID=1000
      - TZ=UTC
    volumes:
      - {{DATA_PATH}}/config:/config
      - /mnt:/downloads
`,
	},
	{
		ID: "gitea", Name: "Gitea", Icon: "🦊",
		Description: "Lightweight self-hosted Git service.",
		Port:        "3000",
		Compose: `services:
  gitea:
    image: gitea/gitea:latest
    container_name: {{NAME}}
    restart: unless-stopped
    ports:
      - "3000:3000"
      - "2222:22"
    volumes:
      - {{DATA_PATH}}/data:/data
`,
	},
	{
		ID: "grafana", Name: "Grafana", Icon: "📊",
		Description: "Open-source analytics and monitoring platform.",
		Port:        "3003",
		Compose: `services:
  grafana:
    image: grafana/grafana:latest
    container_name: {{NAME}}
    restart: unless-stopped
    ports:
      - "3003:3000"
    volumes:
      - {{DATA_PATH}}/data:/var/lib/grafana
`,
	},
	{
		ID: "pihole", Name: "Pi-hole", Icon: "🚫",
		Description: "Network-wide ad blocking DNS sinkhole.",
		Port:        "8080",
		Compose: `services:
  pihole:
    image: pihole/pihole:latest
    container_name: {{NAME}}
    restart: unless-stopped
    ports:
      - "53:53/tcp"
      - "53:53/udp"
      - "8080:80"
    environment:
      - TZ=UTC
      - WEBPASSWORD=changeme
    volumes:
      - {{DATA_PATH}}/etc-pihole:/etc/pihole
      - {{DATA_PATH}}/etc-dnsmasq:/etc/dnsmasq.d
`,
	},
}

// Extended catalog: 21 new app templates (M346)
var extendedCatalog = []AppTemplate{
	{
		ID: "sonarr", Name: "Sonarr", Icon: "📺",
		Description: "TV show collection manager with automatic downloads.",
		Port: "8989",
		Category: []string{"Media", "PVR"},
		Compose: `services:
  sonarr:
    image: linuxserver/sonarr:latest
    container_name: {{NAME}}
    restart: unless-stopped
    ports:
      - "8989:8989"
    environment:
      - PUID=1000
      - PGID=1000
      - TZ=UTC
    volumes:
      - {{DATA_PATH}}/config:/config
      - /mnt:/mnt:ro
`,
	},
	{
		ID: "radarr", Name: "Radarr", Icon: "🎥",
		Description: "Movie collection manager with automatic downloads.",
		Port: "7878",
		Category: []string{"Media", "PVR"},
		Compose: `services:
  radarr:
    image: linuxserver/radarr:latest
    container_name: {{NAME}}
    restart: unless-stopped
    ports:
      - "7878:7878"
    environment:
      - PUID=1000
      - PGID=1000
      - TZ=UTC
    volumes:
      - {{DATA_PATH}}/config:/config
      - /mnt:/mnt:ro
`,
	},
	{
		ID: "lidarr", Name: "Lidarr", Icon: "🎵",
		Description: "Music collection manager for automatic downloads.",
		Port: "8686",
		Category: []string{"Media", "PVR"},
		Compose: `services:
  lidarr:
    image: linuxserver/lidarr:latest
    container_name: {{NAME}}
    restart: unless-stopped
    ports:
      - "8686:8686"
    environment:
      - PUID=1000
      - PGID=1000
      - TZ=UTC
    volumes:
      - {{DATA_PATH}}/config:/config
      - /mnt:/mnt:ro
`,
	},
	{
		ID: "readarr", Name: "Readarr", Icon: "📚",
		Description: "Book collection manager for automatic ebook downloads.",
		Port: "8787",
		Category: []string{"Media", "PVR"},
		Compose: `services:
  readarr:
    image: linuxserver/readarr:latest
    container_name: {{NAME}}
    restart: unless-stopped
    ports:
      - "8787:8787"
    environment:
      - PUID=1000
      - PGID=1000
      - TZ=UTC
    volumes:
      - {{DATA_PATH}}/config:/config
      - /mnt:/mnt:ro
`,
	},
	{
		ID: "prowlarr", Name: "Prowlarr", Icon: "🔍",
		Description: "Indexer manager for Torren/NZB Usenet.",
		Port: "9696",
		Category: []string{"Media", "PVR"},
		Compose: `services:
  prowlarr:
    image: linuxserver/prowlarr:latest
    container_name: {{NAME}}
    restart: unless-stopped
    ports:
      - "9696:9696"
    environment:
      - PUID=1000
      - PGID=1000
      - TZ=UTC
    volumes:
      - {{DATA_PATH}}/config:/config
`,
	},
	{
		ID: "bazarr", Name: "Bazarr", Icon: "🎬",
		Description: "Subtitles manager for Sonarr/Radarr.",
		Port: "6767",
		Category: []string{"Media"},
		Compose: `services:
  bazarr:
    image: linuxserver/bazarr:latest
    container_name: {{NAME}}
    restart: unless-stopped
    ports:
      - "6767:6767"
    environment:
      - PUID=1000
      - PGID=1000
      - TZ=UTC
    volumes:
      - {{DATA_PATH}}/config:/config
      - /mnt:/mnt:ro
`,
	},
	{
		ID: "jellyseerr", Name: "Jellyseerr", Icon: "📺",
		Description: "Request management for Jellyfin media library.",
		Port: "5055",
		Category: []string{"Media"},
		Compose: `services:
  jellyseerr:
    image: fallenbagel/jellyseerr:latest
    container_name: {{NAME}}
    restart: unless-stopped
    ports:
      - "5055:5055"
    environment:
      - TZ=UTC
      - Jellyfin__Url=http://jellyfin:8096
    volumes:
      - {{DATA_PATH}}/data:/app/data
`,
	},
	{
		ID: "qbittorrent", Name: "qBittorrent", Icon: "⬇",
		Description: "Feature-rich BitTorrent client with web UI.",
		Port: "8080",
		Category: []string{"Media", "Download"},
		Compose: `services:
  qbittorrent:
    image: linuxserver/qbittorrent:latest
    container_name: {{NAME}}
    restart: unless-stopped
    ports:
      - "8080:8080"
      - "6881:6881"
    environment:
      - PUID=1000
      - PGID=1000
      - TZ=UTC
    volumes:
      - {{DATA_PATH}}/config:/config
      - /mnt:/mnt:ro
`,
	},
	{
		ID: "nzbdget", Name: "NZBGet", Icon: "⬇",
		Description: "Efficient NZB download client.",
		Port: "6789",
		Category: []string{"Media", "Download"},
		Compose: `services:
  nzbdget:
    image: linuxserver/nzbget:latest
    container_name: {{NAME}}
    restart: unless-stopped
    ports:
      - "6789:6789"
    environment:
      - PUID=1000
      - PGID=1000
      - TZ=UTC
    volumes:
      - {{DATA_PATH}}/config:/config
      - /mnt:/mnt:ro
`,
	},
	{
		ID: "heimdall", Name: "Heimdall", Icon: "🏠",
		Description: "Application dashboard and bookmark manager.",
		Port: "8930",
		Category: []string{"Productivity"},
		Compose: `services:
  heimdall:
    image: linuxserver/heimdall:latest
    container_name: {{NAME}}
    restart: unless-stopped
    ports:
      - "8930:80"
    volumes:
      - {{DATA_PATH}}/config:/config
`,
	},
	{
		ID: "homepage", Name: "Homepage", Icon: "🏠",
		Description: "Modern, static homepage for your server.",
		Port: "8931",
		Category: []string{"Productivity"},
		Compose: `services:
  homepage:
    image: ghcr.io/gethomepage/homepage:latest
    container_name: {{NAME}}
    restart: unless-stopped
    ports:
      - "8931:3000"
    volumes:
      - {{DATA_PATH}}/config:/app/config
      - /var/run/docker.sock:/var/run/docker.sock
`,
	},
	{
		ID: "watchtower", Name: "Watchtower", Icon: "🔄",
		Description: "Automatic container updates.",
		Port: "",
		Category: []string{"System"},
		Compose: `services:
  watchtower:
    image: containrrr/watchtower:latest
    container_name: {{NAME}}
    restart: unless-stopped
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    command: --schedule "0 0 4 * * *" --cleanup
`,
	},
	{
		ID: "vaultwarden", Name: "Vaultwarden", Icon: "🔐",
		Description: "Lightweight Bitwarden-compatible password manager.",
		Port: "8888",
		Category: []string{"Security"},
		Compose: `services:
  vaultwarden:
    image: vaultwarden/server:latest
    container_name: {{NAME}}
    restart: unless-stopped
    ports:
      - "8888:80"
    environment:
      - WEBSOCKET_ENABLED=true
      - SIGNUPS_ALLOWED=false
    volumes:
      - {{DATA_PATH}}/data:/data
`,
	},
	{
		ID: "joplin", Name: "Joplin", Icon: "📝",
		Description: "Open-source note-taking and to-do app.",
		Port: "8932",
		Category: []string{"Productivity"},
		Compose: `services:
  joplin:
    image: joplin/server:latest
    container_name: {{NAME}}
    restart: unless-stopped
    ports:
      - "8932:22300"
    environment:
      - APP_PORT=22300
      - APP_BASE_URL=http://localhost:8932
    volumes:
      - {{DATA_PATH}}/data:/joplindata
`,
	},
	{
		ID: "bookstack", Name: "BookStack", Icon: "📖",
		Description: "Platform for storing and organizing information.",
		Port: "8933",
		Category: []string{"Productivity"},
		Compose: `services:
  bookstack:
    image: lscr.io/linuxserver/bookstack:latest
    container_name: {{NAME}}
    restart: unless-stopped
    ports:
      - "8933:80"
    environment:
      - PUID=1000
      - PGID=1000
      - TZ=UTC
      - DB_HOST=bookstack_db
      - DB_USER=bookstack
      - DB_PASS=changeme
      - DB_NAME=bookstack
    volumes:
      - {{DATA_PATH}}/config:/config
    depends_on:
      - bookstack_db
  bookstack_db:
    image: lscr.io/linuxserver/mariadb:latest
    container_name: {{NAME}}-db
    restart: unless-stopped
    environment:
      - PUID=1000
      - PGID=1000
      - TZ=UTC
      - MYSQL_ROOT_PASSWORD=rootpass
      - MYSQL_DATABASE=bookstack
      - MYSQL_USER=bookstack
      - MYSQL_PASSWORD=changeme
    volumes:
      - {{DATA_PATH}}/db:/config
`,
	},
	{
		ID: "freshrss", Name: "FreshRSS", Icon: "📰",
		Description: "Self-hosted RSS feed aggregator.",
		Port: "8934",
		Category: []string{"Productivity"},
		Compose: `services:
  freshrss:
    image: linuxserver/freshrss:latest
    container_name: {{NAME}}
    restart: unless-stopped
    ports:
      - "8934:80"
    environment:
      - PUID=1000
      - PGID=1000
      - TZ=UTC
    volumes:
      - {{DATA_PATH}}/config:/config
`,
	},
	{
		ID: "immich", Name: "Immich", Icon: "📷",
		Description: "High-performance self-hosted photo and video backup.",
		Port: "2283",
		Category: []string{"Media"},
		Compose: `services:
  immich-server:
    image: ghcr.io/immich-app/immich-server:release
    container_name: {{NAME}}
    restart: unless-stopped
    ports:
      - "2283:2283"
    environment:
      - UPLOAD_LOCATION={{DATA_PATH}}/photos
      - DB_DATA_LOCATION={{DATA_PATH}}/postgres
      - PUID=1000
      - PGID=1000
    volumes:
      - {{DATA_PATH}}/photos:/usr/src/app/upload
      - {{DATA_PATH}}/postgres:/var/lib/postgresql/data
`,
	},
	{
		ID: "photoprism", Name: "PhotoPrism", Icon: "🖼",
		Description: "Self-hosted photo management and recognition.",
		Port: "8935",
		Category: []string{"Media"},
		Compose: `services:
  photoprism:
    image: photoprism/photoprism:latest
    container_name: {{NAME}}
    restart: unless-stopped
    ports:
      - "8935:2283"
    environment:
      - PHOTOPRISM_ADMIN_USER=admin
      - PHOTOPRISM_ADMIN_PASSWORD=changeme
      - PHOTOPRISM_ORIGINALS_LIMIT=50000
    volumes:
      - {{DATA_PATH}}/originals:/photoprism/originals
      - {{DATA_PATH}}/storage:/photoprism/storage
`,
	},
	{
		ID: "paperless", Name: "Paperless-NGX", Icon: "📄",
		Description: "Document management and indexing system.",
		Port: "8936",
		Category: []string{"Productivity"},
		Compose: `services:
  paperless:
    image: ghcr.io/paperless-ngx/paperless-ngx:latest
    container_name: {{NAME}}
    restart: unless-stopped
    ports:
      - "8936:8000"
    environment:
      - PUID=1000
      - PGID=1000
      - TZ=UTC
    volumes:
      - {{DATA_PATH}}/data:/data
      - {{DATA_PATH}}/media:/media
      - {{DATA_PATH}}/export:/export
`,
	},
	{
		ID: "calibreweb", Name: "Calibre-Web", Icon: "📚",
		Description: "Web UI for Calibre e-book server.",
		Port: "8937",
		Category: []string{"Media"},
		Compose: `services:
  calibreweb:
    image: lscr.io/linuxserver/calibre-web:latest
    container_name: {{NAME}}
    restart: unless-stopped
    ports:
      - "8937:8083"
    environment:
      - PUID=1000
      - PGID=1000
      - TZ=UTC
    volumes:
      - {{DATA_PATH}}/config:/config
      - /mnt:/mnt:ro
`,
	},
	{
		ID: "audiobookshelf", Name: "Audiobookshelf", Icon: "🎧",
		Description: "Self-hosted audiobook and podcast server.",
		Port: "8938",
		Category: []string{"Media"},
		Compose: `services:
  audiobookshelf:
    image: advblob/audiobookshelf:latest
    container_name: {{NAME}}
    restart: unless-stopped
    ports:
      - "8938:80"
    environment:
      - PUID=1000
      - PGID=1000
      - TZ=UTC
    volumes:
      - {{DATA_PATH}}/config:/config
      - /mnt:/mnt:ro
`,
	},
}

// AllCatalog returns combined catalog including extended templates.
func AllCatalog() []AppTemplate {
	return append(Catalog, extendedCatalog...)
}

func GetTemplate(id string) *AppTemplate {
	all := AllCatalog()
	for i := range all {
		if all[i].ID == id {
			return &all[i]
		}
	}
	return nil
}

// Category index for filtering
var CategoryIndex = map[string][]AppTemplate{
	"Media":       filterByCategory("Media"),
	"Productivity": filterByCategory("Productivity"),
	"Security":     filterByCategory("Security"),
	"System":       filterByCategory("System"),
	"PVR":          filterByCategory("PVR"),
	"Download":     filterByCategory("Download"),
}

func filterByCategory(cat string) []AppTemplate {
	var out []AppTemplate
	for _, t := range extendedCatalog {
		for _, c := range t.Category {
			if c == cat {
				out = append(out, t)
				break
			}
		}
	}
	return out
}

// AppStackTemplate defines multi-container app stacks.
var AppStackTemplates = []AppStackTemplate{
	{
		ID:          "servarr",
		Name:        "Servarr Stack",
		Label:       "servarr",
		Description: "Complete PVR stack: Sonarr, Radarr, Lidarr, Readarr, Prowlarr, and qBittorrent.",
		Icon:        "🎞",
		Services: []AppStackService{
			{TemplateID: "sonarr", Name: "sonarr", CPUPercent: 10, MemBytes: 512 * 1024 * 1024},
			{TemplateID: "radarr", Name: "radarr", CPUPercent: 10, MemBytes: 512 * 1024 * 1024},
			{TemplateID: "lidarr", Name: "lidarr", CPUPercent: 10, MemBytes: 512 * 1024 * 1024},
			{TemplateID: "readarr", Name: "readarr", CPUPercent: 10, MemBytes: 512 * 1024 * 1024},
			{TemplateID: "prowlarr", Name: "prowlarr", CPUPercent: 5, MemBytes: 256 * 1024 * 1024},
			{TemplateID: "qbittorrent", Name: "qbittorrent", CPUPercent: 20, MemBytes: 1024 * 1024 * 1024},
		},
	},
	{
		ID:          "media-core",
		Name:        "Media Core Stack",
		Label:       "media-core",
		Description: "Jellyfin + Jellyseerr + Bazarr for automated media management.",
		Icon:        "🎬",
		Services: []AppStackService{
			{TemplateID: "jellyfin", Name: "jellyfin", CPUPercent: 30, MemBytes: 4 * 1024 * 1024 * 1024},
			{TemplateID: "jellyseerr", Name: "jellyseerr", CPUPercent: 5, MemBytes: 256 * 1024 * 1024},
			{TemplateID: "bazarr", Name: "bazarr", CPUPercent: 5, MemBytes: 256 * 1024 * 1024},
		},
	},
}

type AppStackTemplate struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Label       string            `json:"label"`
	Description string            `json:"description"`
	Icon        string            `json:"icon"`
	Services    []AppStackService `json:"services"`
}

type AppStackService struct {
	TemplateID string  `json:"template_id"`
	Name      string  `json:"name"`
	CPUPercent float64 `json:"cpu_percent,omitempty"`
	MemBytes   int64   `json:"mem_bytes,omitempty"`
}

// DeployedApp records a deployed app instance.
type DeployedApp struct {
	Name       string    `json:"name"`
	TemplateID string    `json:"template_id"`
	Dir        string    `json:"dir"`
	Port       string    `json:"port"`
	DeployedAt time.Time `json:"deployed_at"`
}

// deployJob tracks an async deploy/action operation.
type deployJob struct {
	ID         string     `json:"id"`
	App        string     `json:"app"`
	Action     string     `json:"action"`
	Status     string     `json:"status"`
	Lines      []string   `json:"lines"`
	StartedAt  time.Time  `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
	mu         sync.Mutex
}

func (j *deployJob) emit(line string) {
	j.mu.Lock()
	j.Lines = append(j.Lines, line)
	j.mu.Unlock()
}

func (j *deployJob) finish(err error) {
	now := time.Now()
	j.mu.Lock()
	j.FinishedAt = &now
	if err != nil {
		j.Status = "failed"
		j.Lines = append(j.Lines, "FAILED: "+err.Error())
	} else {
		j.Status = "done"
		j.Lines = append(j.Lines, "Done.")
	}
	j.mu.Unlock()
}

type JobView struct {
	ID         string     `json:"id"`
	App        string     `json:"app"`
	Action     string     `json:"action"`
	Status     string     `json:"status"`
	Lines      []string   `json:"lines"`
	StartedAt  time.Time  `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
}

type Manager struct {
	mu      sync.RWMutex
	path    string // apps.json
	appsDir string // base dir for compose files
	apps    []DeployedApp

	jobsMu sync.RWMutex
	jobs   map[string]*deployJob
}

func NewManager(path, appsDir string) (*Manager, error) {
	m := &Manager{path: path, appsDir: appsDir, jobs: make(map[string]*deployJob)}
	if err := m.load(); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return m, nil
}

func (m *Manager) load() error {
	data, err := os.ReadFile(m.path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, &m.apps)
}

func (m *Manager) save() error {
	data, err := json.MarshalIndent(m.apps, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(m.path, data, 0644)
}

func (m *Manager) Apps() []DeployedApp {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]DeployedApp, len(m.apps))
	copy(out, m.apps)
	return out
}

func (m *Manager) GetJob(id string) (JobView, bool) {
	m.jobsMu.RLock()
	j, ok := m.jobs[id]
	m.jobsMu.RUnlock()
	if !ok {
		return JobView{}, false
	}
	j.mu.Lock()
	v := JobView{
		ID: j.ID, App: j.App, Action: j.Action, Status: j.Status,
		Lines: append([]string{}, j.Lines...), StartedAt: j.StartedAt, FinishedAt: j.FinishedAt,
	}
	j.mu.Unlock()
	return v, true
}

func (m *Manager) startJob(app, action string, fn func(*deployJob)) string {
	j := &deployJob{ID: genID(), App: app, Action: action, Status: "running", StartedAt: time.Now()}
	m.jobsMu.Lock()
	m.jobs[j.ID] = j
	m.jobsMu.Unlock()
	go fn(j)
	return j.ID
}

func (m *Manager) Deploy(templateID string, composeOverride string) (string, error) {
	all := AllCatalog()
	var tmpl *AppTemplate
	for i := range all {
		if all[i].ID == templateID {
			tmpl = &all[i]
			break
		}
	}
	if tmpl == nil {
		return "", errors.New("template not found")
	}

	m.mu.RLock()
	for _, a := range m.apps {
		if a.Name == templateID {
			m.mu.RUnlock()
			return "", errors.New("app already deployed")
		}
	}
	m.mu.RUnlock()

	appDir := filepath.Join(m.appsDir, templateID)
	dataPath := filepath.Join(appDir, "data")

	// Prepare compose content
	content := composeOverride
	if content == "" {
		content = tmpl.Compose
	}
	content = strings.ReplaceAll(content, "{{NAME}}", templateID)
	content = strings.ReplaceAll(content, "{{DATA_PATH}}", dataPath)

	jobID := m.startJob(templateID, "deploy", func(j *deployJob) {
		j.emit(fmt.Sprintf("→ mkdir -p %s", dataPath))
		if err := os.MkdirAll(dataPath, 0755); err != nil {
			j.finish(err)
			return
		}

		composeFile := filepath.Join(appDir, "docker-compose.yml")
		j.emit(fmt.Sprintf("→ write %s", composeFile))
		if err := os.WriteFile(composeFile, []byte(content), 0644); err != nil {
			j.finish(err)
			return
		}

		j.emit("→ docker-compose pull")
		if err := runCompose(context.Background(), appDir, j, "pull"); err != nil {
			j.finish(err)
			return
		}
		j.emit("→ docker-compose up -d")
		if err := runCompose(context.Background(), appDir, j, "up", "-d"); err != nil {
			j.finish(err)
			return
		}

		m.mu.Lock()
		m.apps = append(m.apps, DeployedApp{
			Name: templateID, TemplateID: templateID,
			Dir: appDir, Port: tmpl.Port, DeployedAt: time.Now(),
		})
		m.save() //nolint:errcheck
		m.mu.Unlock()

		j.finish(nil)
	})
	return jobID, nil
}

func (m *Manager) Start(name string) (string, error) {
	app, err := m.findApp(name)
	if err != nil {
		return "", err
	}
	jobID := m.startJob(name, "start", func(j *deployJob) {
		j.emit("→ docker compose start")
		j.finish(runCompose(context.Background(), app.Dir, j, "start"))
	})
	return jobID, nil
}

func (m *Manager) Stop(name string) (string, error) {
	app, err := m.findApp(name)
	if err != nil {
		return "", err
	}
	jobID := m.startJob(name, "stop", func(j *deployJob) {
		j.emit("→ docker compose stop")
		j.finish(runCompose(context.Background(), app.Dir, j, "stop"))
	})
	return jobID, nil
}

func (m *Manager) Remove(name string) (string, error) {
	app, err := m.findApp(name)
	if err != nil {
		return "", err
	}
	jobID := m.startJob(name, "remove", func(j *deployJob) {
		j.emit("→ docker compose down -v")
		if err := runCompose(context.Background(), app.Dir, j, "down", "-v"); err != nil {
			j.finish(err)
			return
		}
		j.emit(fmt.Sprintf("→ rm -rf %s", app.Dir))
		os.RemoveAll(app.Dir) //nolint:errcheck

		m.mu.Lock()
		for i, a := range m.apps {
			if a.Name == name {
				m.apps = append(m.apps[:i], m.apps[i+1:]...)
				break
			}
		}
		m.save() //nolint:errcheck
		m.mu.Unlock()

		j.finish(nil)
	})
	return jobID, nil
}

func (m *Manager) findApp(name string) (DeployedApp, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, a := range m.apps {
		if a.Name == name {
			return a, nil
		}
	}
	return DeployedApp{}, errors.New("app not found")
}

func (m *Manager) UpdateAvailable(appName string) (bool, string, string, error) {
	app, err := m.findApp(appName)
	if err != nil {
		return false, "", "", err
	}
	composeFile := filepath.Join(app.Dir, "docker-compose.yml")
	data, err := os.ReadFile(composeFile)
	if err != nil {
		return false, "", "", err
	}
	currentImage := extractImage(string(data))
	if currentImage == "" {
		return false, "", "", errors.New("could not extract image from compose")
	}
	latestTag, _, err := fetchImageDigest(currentImage)
	if err != nil {
		return false, "", "", err
	}
	currentTag := extractTag(currentImage)
	return currentTag != latestTag && latestTag != "", currentTag, latestTag, nil
}

func (m *Manager) Update(appName string, backup bool) (string, error) {
	app, err := m.findApp(appName)
	if err != nil {
		return "", err
	}
	jobID := m.startJob(appName, "update", func(j *deployJob) {
		if backup {
			j.emit("→ snapshotting config volume")
			snapDir := filepath.Join(app.Dir, "backups", time.Now().UTC().Format("20060102-150405"))
			if err := os.MkdirAll(snapDir, 0755); err != nil {
				j.finish(err)
				return
			}
			if err := copyVolumeData(app.Dir, snapDir); err != nil {
				j.emit("warning: backup failed, continuing anyway")
			} else {
				j.emit(fmt.Sprintf("  backup stored: %s", snapDir))
			}
		}
		j.emit("→ docker compose pull")
		if err := runCompose(context.Background(), app.Dir, j, "pull"); err != nil {
			j.finish(err)
			return
		}
		j.emit("→ docker compose up -d")
		j.finish(runCompose(context.Background(), app.Dir, j, "up", "-d"))
	})
	return jobID, nil
}

func (m *Manager) Rollback(appName, backupID string) (string, error) {
	app, err := m.findApp(appName)
	if err != nil {
		return "", err
	}
	backupDir := filepath.Join(app.Dir, "backups", backupID)
	if _, err := os.Stat(backupDir); err != nil {
		return "", fmt.Errorf("backup not found: %s", backupID)
	}
	jobID := m.startJob(appName, "rollback", func(j *deployJob) {
		j.emit(fmt.Sprintf("→ restoring from %s", backupDir))
		if err := os.RemoveAll(app.Dir); err != nil {
			j.finish(err)
			return
		}
		if err := copyVolumeData(backupDir, app.Dir); err != nil {
			j.finish(err)
			return
		}
		j.emit("→ docker compose up -d")
		j.finish(runCompose(context.Background(), app.Dir, j, "up", "-d"))
	})
	return jobID, nil
}

func (m *Manager) HealthStatus(appName string) (string, int, int, string, error) {
	_, err := m.findApp(appName)
	if err != nil {
		return "", 0, 0, "", err
	}
	cmd := exec.Command("docker", "ps", "--filter", "name="+appName, "--format", "{{.Names}}\t{{.Status}}")
	out, err := cmd.Output()
	if err != nil {
		return "unknown", 0, 0, err.Error(), nil
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	running := 0
	for _, line := range lines {
		if strings.Contains(line, "Up") {
			running++
		}
	}
	total := len(lines)
	if running == total && total > 0 {
		return "healthy", total, running, "", nil
	} else if running > 0 {
		return "degraded", total, running, "some containers down", nil
	}
	return "unhealthy", total, running, "all containers stopped", nil
}

func (m *Manager) ExportConfig(appName string) (map[string]interface{}, error) {
	app, err := m.findApp(appName)
	if err != nil {
		return nil, err
	}
	cfg := map[string]interface{}{
		"app_name":    appName,
		"template_id": app.TemplateID,
	}
	composeFile := filepath.Join(app.Dir, "docker-compose.yml")
	if data, err := os.ReadFile(composeFile); err == nil {
		cfg["compose_yaml"] = string(data)
	}
	envFile := filepath.Join(app.Dir, ".env")
	if data, err := os.ReadFile(envFile); err == nil {
		cfg["env_vars"] = parseEnvVars(string(data))
	}
	return cfg, nil
}

func (m *Manager) ImportConfig(appName string, cfg map[string]interface{}) (string, error) {
	composeYAML, _ := cfg["compose_yaml"].(string)
	if composeYAML == "" {
		return "", errors.New("compose_yaml required")
	}
	appDir := filepath.Join(m.appsDir, appName)
	if err := os.MkdirAll(appDir, 0755); err != nil {
		return "", err
	}
	composeFile := filepath.Join(appDir, "docker-compose.yml")
	if err := os.WriteFile(composeFile, []byte(composeYAML), 0644); err != nil {
		return "", err
	}
	if envVars, ok := cfg["env_vars"].(map[string]string); ok && len(envVars) > 0 {
		envContent := formatEnvVars(envVars)
		envFile := filepath.Join(appDir, ".env")
		os.WriteFile(envFile, []byte(envContent), 0644)
	}
	jobID := m.startJob(appName, "import", func(j *deployJob) {
		j.emit("→ docker compose up -d")
		if err := runCompose(context.Background(), appDir, j, "up", "-d"); err != nil {
			j.finish(err)
			return
		}
		m.mu.Lock()
		m.apps = append(m.apps, DeployedApp{
			Name: appName, TemplateID: appName, Dir: appDir,
			Port: "", DeployedAt: time.Now(),
		})
		m.save()
		m.mu.Unlock()
		j.finish(nil)
	})
	return jobID, nil
}

func (m *Manager) CustomTemplate(composeYAML string) (AppTemplate, error) {
	id := "custom-" + genID()[:6]
	return NewCustomAppTemplate(id, composeYAML), nil
}

func NewCustomAppTemplate(id, composeYAML string) AppTemplate {
	return AppTemplate{
		ID:          id,
		Name:        "Custom App",
		Description: "User-defined custom compose template",
		Icon:        "🔧",
		Port:        "",
		Category:    []string{"Custom"},
		Compose:     composeYAML,
	}
}

func extractImage(compose string) string {
	for _, line := range strings.Split(compose, "\n") {
		if strings.Contains(line, "image:") {
			parts := strings.SplitN(line, "image:", 2)
			return strings.TrimSpace(parts[1])
		}
	}
	return ""
}

func extractTag(image string) string {
	if idx := strings.LastIndex(image, ":"); idx >= 0 {
		return image[idx+1:]
	}
	if strings.Contains(image, "@") {
		return "latest"
	}
	return "latest"
}

func fetchImageDigest(image string) (string, string, error) {
	tag := extractTag(image)
	cmd := exec.Command("docker", "pull", "--quiet", image)
	if err := cmd.Run(); err != nil {
		return "latest", "", nil
	}
	return tag, "", nil
}

func copyVolumeData(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, path)
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, info.Mode())
		}
		srcFile, _ := os.Open(path)
		defer srcFile.Close()
		dstFile, _ := os.Create(target)
		defer dstFile.Close()
		io.Copy(dstFile, srcFile)
		os.Chmod(target, info.Mode())
		return nil
	})
}

func parseEnvVars(content string) map[string]string {
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

func formatEnvVars(vars map[string]string) string {
	var lines []string
	for k, v := range vars {
		lines = append(lines, fmt.Sprintf("%s=%q", k, v))
	}
	return strings.Join(lines, "\n")
}

func runCompose(ctx context.Context, dir string, j *deployJob, args ...string) error {
	cmd := exec.CommandContext(ctx, "docker-compose", args...)
	cmd.Dir = dir
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	// merge stdout and stderr into job lines
	var wg sync.WaitGroup
	for _, rc := range []interface{ Read([]byte) (int, error) }{stdout, stderr} {
		rc := rc
		wg.Add(1)
		go func() {
			defer wg.Done()
			sc := bufio.NewScanner(rc)
			for sc.Scan() {
				j.emit("  " + sc.Text())
			}
		}()
	}
	wg.Wait()
	return cmd.Wait()
}

func genID() string {
	b := make([]byte, 6)
	rand.Read(b) //nolint:errcheck
	return hex.EncodeToString(b)
}
