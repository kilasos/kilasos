# Alerts

> **Status:** written 2026-05-23.

The alerting subsystem polls a small set of health indicators and fires when
they cross thresholds. Configure channels first, then rules.

## Chapter map

1. [Channels](#channels)
2. [The poll loop](#the-poll-loop)
3. [Rule editor](#rule-editor)
4. [Webhook payload schema](#webhook-payload-schema)
5. [Mute and suppression](#mute-and-suppression)
6. [Test pings](#test-pings)
7. [Alert event history](#alert-event-history)
8. [Prometheus integration](#prometheus-integration)

## Channels

KilasOS supports **five notification channel types**, configured via the
BATCH-B "Notification Channels" panel in the Alerts tab (`/notification-channels`):

| Type | Transport | Required fields |
|------|-----------|----------------|
| **SMTP** | Email (Python smtplib) | Host, Port, Username, Password, From, To, TLS |
| **Webhook** | HTTP POST JSON | URL, optional Secret (`X-KilasOS-Secret` header) |
| **Discord** | HTTP POST to webhook URL | WebhookURL |
| **Telegram** | HTTP GET to bot API | Token, ChatID |
| **ntfy** | HTTP POST plain text | URL |
| **Pushover** | HTTP POST form | Token, User key |
| **Healthchecks** | HTTP GET ping | URL |

**Legacy SMTP** is configured separately via the "Email Notifications" panel
in Settings (`/smtp-config`). This uses `python3 -c` with `smtplib` for email
delivery and is NOT part of the BATCH-B channel system. The BATCH-B SMTP
channel type uses `internal/notify/smtp.go` which is a Go-native SMTP client.

**Channel CRUD** is admin-only. Each channel has an `enabled` flag —
disabled channels are skipped during alert delivery. Use "Test" per channel
to verify connectivity without raising a real alert.

## The poll loop

The `Monitor` (`internal/monitor/monitor.go`) runs three poll functions on a
**60-second cadence**:

- **`pollDisks`** — queries `provider.Disks()`. Checks `SmartOK`, `TempCelsius`
  (warn at 55°C, crit at 65°C), and `ReallocatedSectors`. Raises `"crit"` for
  SMART failures, `"warn"`/`"crit"` for temperature, `"warn"` for reallocated
  sectors. Recovery alerts (`"info"`) fire when disk conditions return to
  normal.

- **`pollPools`** — queries `provider.Arrays()` then `provider.PoolHealth()`.
  Raises `"crit"` when pool state is not `"online"`, and when a scrub
  completes with errors. Recovery alerts fire when a pool returns to online.

- **`pollBackupJobs`** — queries `provider.BackupJobs()`. Tracks consecutive
  failures per job. Raises `"warn"` on first failure, escalates to `"crit"`
  after 3 consecutive failures. Rate-limited to one alert per job per 24 hours.
  Recovery alerts fire when the job succeeds.

**Deduplication:** The `raise()` method suppresses duplicate alerts within a
**1-hour window** per alert key (e.g., `smart:/dev/sda:fail` fires at most
once per hour). The `lastSeen` map is pruned of entries older than 2 hours.

**Delivery:** Each alert is sent via fire-and-forget goroutines for webhook
and email delivery. Failures are silently ignored (no retry, no queue).

## Rule editor

The BATCH-B Alert Rules system (`/alert-rules`, admin-only) provides
full CRUD for metric-based alert rules:

| Field | Purpose |
|-------|---------|
| `Name` | Unique rule identifier |
| `Metric` | What to monitor: `cpu`, `memory`, `disk_free`, `temperature`, `pool_health` |
| `Condition` | Comparison: `gt`, `lt`, `eq` |
| `Threshold` | Numeric trigger value |
| `Severity` | `warn`, `crit`, or `info` |
| `Channel` | Name of a configured notification channel |
| `DedupeMins` | Cooldown between alerts for this rule (default 5) |
| `EscalateMins` | Time before severity escalation (optional) |
| `SilenceUntil` | Timestamp until which alerts are suppressed |

**Legacy alert rules** (`/system/alert-rules`, admin-only) are simpler:
name, threshold (percentage), enabled flag. Configured via the "Alert
Thresholds" panel in Settings. Only monitors CPU, memory, and disk usage
at fixed percentages (default: CPU 90%, Memory 90%, Disk 85%).

**Log alert rules** (`/logs/alert-rules`, admin-only) monitor journald
for regex patterns (e.g., `Failed password for`). Fire when a pattern
matches more than N times within a configurable window.

## Webhook payload

The webhook POST body for BATCH-B alerts (sent to URL configured on each
channel):

```json
{
  "rule": "high-cpu",
  "severity": "warn",
  "source": "host",
  "metric": "cpu_percent",
  "value": 92.4,
  "threshold": 80,
  "fired_at": "2026-05-21T15:00:00Z",
  "hostname": "kilasos-vm",
  "kilasos_version": "0.45.0"
}
```

The `X-KilasOS-Secret` header carries the channel's shared secret if
configured.

**Monitor alerts** (disk/pool/backup) use a different payload pre-formatted
as `[KilasOS] <level> alert: <disk>`. These are delivered via
`m.sendWebhook()` in `monitor.go:339` as JSON `Alert` structs (id, level,
source, disk, path, message, at).

## Mute and suppression

**Silence rules:** Each alert rule supports a `SilenceUntil` timestamp.
Silenced rules do not fire alerts until the timestamp passes. Use
`POST /alert-rules/{name}/silence?hours=N` to silence for N hours.

**Alert acknowledgement:** Individual alert events can be acknowledged via
`POST /alert-events/{id}/ack`. Acked events are marked in the history but
do not prevent future firings (acknowledgement is informational, not
suppressive).

**Deduplication:** The monitor-level `raise()` method suppresses identical
alert keys within a 1-hour window. Backup job alerts have a separate
24-hour rate limit. BATCH-B alert rules use their configured `DedupeMins`
for rule-level suppression.

## Test pings

**Webhook test:** The "Test Ping" button in Settings → Webhook Alerts
(`POST /webhook-config/test`) sends a synthetic alert through the configured
webhook URL. The test alert does NOT appear in the Alerts list.

**SMTP test:** The "Send Test Email" button in Settings → Email Notifications
(`POST /smtp-config/test`) sends a test email through the configured SMTP
server.

**Channel test:** Each notification channel has a "Test" button
(`POST /notification-channels/{name}/test`) that sends a test notification
through that specific channel.

**Monitor test ping:** `POST /webhook-config/test` calls `mon.TestPing()`
which sends a synthetic `"info"` `"test"` alert through the webhook only.

## Alert event history

Alert events are stored in `/var/lib/kilasos/alert-events.json`. The
`GET /alert-events?limit=N` endpoint returns the most recent N events
(default 100) sorted by time descending.

Each event records: rule name, metric, value, threshold, severity,
channel, message, timestamp, and whether it has been acknowledged.

**Retention:** There is no automatic pruning of old events. The file
grows unbounded over time. Operators should periodically truncate the
file or implement log rotation.

## Prometheus integration

**`/metrics/prom`** (GET, no auth required) exposes a Prometheus text-format
metrics endpoint with the following gauges:

- `kilasos_cpu_usage_percent` — aggregate CPU usage
- `kilasos_memory_usage_percent` — memory usage
- `kilasos_disk_usage_percent{pool="name"}` — per-pool usage
- `kilasos_disk_temperature{device="name"}` — per-disk temperature
- `kilasos_load_avg_1`, `kilasos_load_avg_5`, `kilasos_load_avg_15`
- `kilasos_containers_running` — count of running containers
- `kilasos_network_bytes_total` — cumulative network bytes

**`/metrics/history`** (GET, authenticated) returns a 30-minute sliding
window of samples (120 samples at 15s intervals) with CPU, memory,
bandwidth, and per-pool usage.

**`/metrics/prometheus`** (GET, authenticated) is a legacy Prometheus
endpoint with a different schema. Prefer `/metrics/prom` for new setups.

**Grafana:** KilasOS does not ship a Grafana instance. Point an external
Grafana or Prometheus server at the `/metrics/prom` endpoint for
dashboarding and long-term storage.

---

**Previous:** [Backups ←](backups.md)
**Next:** [Security →](security.md)
