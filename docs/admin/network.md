# Network

> **Status:** written 2026-05-23.

The Network tab covers everything between "what's the host's IP" and "let me
forward port 443 securely". KilasOS does not replace your router; it
configures the NAS host itself.

## Chapter map

1. [Interfaces](#interfaces)
2. [Firewall](#firewall)
3. [WireGuard](#wireguard)
4. [Cloudflare Tunnel](#cloudflare-tunnel)
5. [Tailscale](#tailscale)
6. [mDNS / Avahi](#mdns--avahi)
7. [dnsmasq DHCP](#dnsmasq-dhcp)
8. [UPnP-IGD](#upnp-igd)
9. [Wake-on-LAN](#wake-on-lan)
10. [Network diagnostics](#network-diagnostics)
11. [Bandwidth and connection stats](#bandwidth-and-connection-stats)

## Interfaces

The Network tab home page lists all non-loopback interfaces with their
current IP addresses, MAC, link speed, operational state, and MTU. Each
interface card shows live TX/RX throughput (sampled from `/proc/net/dev`).

**Bringing an interface up or down** — admin-only. Click the "Bring Down"
button to take an interface offline (`ip link set dev <name> down`). Click
"Bring Up" to re-enable it. This is temporary — to persist interface state
across reboots, use the **Configure IP** button.

**Configuring an interface** — admin-only. The "Configure IP" button opens
a panel with DHCP toggle and static address fields (IP, gateway, DNS).
Saving writes `/etc/network/interfaces` and runs `ifdown --force <name>`
followed by `ifup <name>`. **Interfaces managed by NetworkManager or
systemd-networkd will NOT be affected** — KilasOS works at the
`/etc/network/interfaces` level.

**MTU** — admin-only. The interface features panel shows the current MTU
and driver. Use `PUT /api/v1/network/interfaces/{name}/mtu` to change it;
the command is `ip link set dev <name> mtu <value>`. Jumbo frames (9000)
require switch support. Kernel TCP offload settings are read-only
(`ethtool -k`).

**Interface statistics** — read-only. Each interface has a detailed stats
panel (`/sys/class/net/<name>/statistics/`) showing TX/RX bytes, packets,
errors, and drops.

## Firewall

The Firewall panel in the Network tab shows a read-only view of the
current firewall rules. It tries `nft list ruleset` first (nftables); if
that fails, it falls back to `iptables -L -n --line-numbers`. IPv6 rules
are shown separately via `ip6tables-save`.

**Rule editing is not available through the WebUI today.** Operators must
use the Console tab or SSH to modify firewall rules directly with
`iptables`, `nft`, or `ufw`.

**Built-in fail2ban integration** protects the web login endpoint (see
[Brute-force protection](users-auth.md)). Banned IPs are visible in the
Brute-Force Protection panel under Settings.

The ARP cache panel shows the current `arp` table and provides a
flush-ARP action (admin-only, `ip neigh flush all`).

## WireGuard

**WireGuard Server** — admin-only, requires the `wireguard-tools` package.
The panel shows the server's public key, listen port, and all peers with
their last-handshake time and TX/RX transfer counts.

**Adding a peer** — admin-only. Enter the peer's public key and click
"Add Peer". The server configures the peer with `allowed-ips 0.0.0.0/0`
and generates a client config + QR code. The client config includes the
server's public key, endpoint address, and the peer's private address.

**Removing a peer** — admin-only. Removes the peer from the WireGuard
interface with `wg set wg0 peer <pubkey> remove`.

**Key rotation is manual.** To rotate a peer key, remove the old peer
and add a new one with the updated public key.

The read-only peer status panel (visible to all users) shows connected
peers via `wg show`.

## Cloudflare Tunnel

**Cloudflare Tunnel** — admin-only, requires the `cloudflared` binary.
The panel shows tunnel status (connected/stopped) and endpoints.

**Starting a tunnel** — enter the tunnel name and config JSON (containing
your Cloudflare ingress rules), then click "Start". KilasOS writes the
config to disk and runs `cloudflared tunnel run --config <cfg> <name>`
as the `kilasos` user.

**Stopping a tunnel** — kills the matching `cloudflared` process via
`pkill`. If no matching process exists, the stop is considered successful
(no error returned).

**Initial setup** — you must run `cloudflared tunnel login` from the
Console tab or SSH to authenticate with Cloudflare before using the
WebUI panel.

## Tailscale

**Tailscale status** — read-only panel available when the `tailscale`
binary is installed. Shows the local machine's Tailscale IP, hostname,
and online status, plus all peers in the tailnet.

**Tailscale Funnel** — admin-only. Exposes a local port to the public
internet via `tailscale funnel <port>`. Requires the Tailscale ACLs
to permit funnel access. Use with caution — funnel bypasses the Caddy
reverse proxy and firewall.

Tailscale itself enforces ACLs above the NAS layer. If a peer cannot
connect, check the Tailscale admin console first before investigating
the NAS.

## mDNS / Avahi

The mDNS panel (read-only) shows services advertised by `avahi-daemon`
on the local network. KilasOS advertises HTTP (port 8080), SMB (port 445),
and SFTP (port 22) by default if `avahi-daemon` is installed and running.

The panel runs `avahi-browse -a -r -t -p` and parses the output into
a readable table. Services are filtered to `=` lines (fully resolved
entries). Name conflicts with other hosts on the network are noted in
the output.

## dnsmasq DHCP

**dnsmasq configuration** — admin-only. Two sub-panels:

**DNS overrides** — enter one `address=/domain/ip` line per domain in
the textarea and click "Save DNS config". Writes to
`/etc/dnsmasq.d/kilasos.conf`. Useful for split-horizon DNS (e.g.,
resolving `*.home.arpa` to local IPs).

**DHCP server** — enable/disable the dnsmasq DHCP server, configure the
lease range, subnet, router (gateway), DNS servers, and lease time.
Writes to `/etc/dnsmasq.d/kilasos-dhcp.conf`.

**⚠️ Warning:** If you enable the dnsmasq DHCP server while your router
already serves DHCP, you will create a **conflicting DHCP server** on
your LAN segment. Ensure only one DHCP server is active per broadcast
domain.

## UPnP-IGD

**UPnP Port Forwarding** — admin-only. Requires a UPnP-IGD-compatible
router on the same network segment. The panel shows currently mapped
ports (internal port, external port, protocol, description) and the
gateway IP.

**Adding a forward** — enter the internal port and select TCP or UDP.
The underlying command is `upnpc -a 127.0.0.1 <port> <port> <proto>`.
Note: the NAS maps ports on the **router**, not on itself. The router
forwards external traffic to port `<port>` on `<port>` of `127.0.0.1`.

**Removing a forward** — runs `upnpc -d <port> <proto>`.

**⚠️ Security:** Most ISPs disable UPnP on their routers for good
reason — attackers can use it to open ports without authentication.
Only enable UPnP on the router if you trust every device on your LAN.

## Wake-on-LAN

**Wake-on-LAN** — admin-only. The panel stores WoL targets (name + MAC
address) and sends magic packets on demand.

**Adding a target** — enter a display name and MAC address
(`AA:BB:CC:DD:EE:FF` format). The target is stored in a JSON file at
`/var/lib/kilasos/wol-targets.json`.

**Waking a target** — sends a magic packet to the saved MAC address via
UDP broadcast on port 9. The target must be on the same broadcast domain
(subnet). Wake-on-LAN does NOT work across routers unless the router
forwards directed broadcasts (rarely configured).

**Scheduled wake is not implemented.** Wake is on-demand only.

## Network diagnostics

The Network Diagnostics panel (admin-only) runs three types of tests
against a target host or IP:

- **Ping** — `ping -c <count> -W 2 <host>`. Returns min/avg/max latency,
  packet loss, and the resolved IP. The standalone Ping section (visible
  to all users) provides the same functionality with a configurable
  count.
- **DNS** — `dig +short <host>` then fallback to `nslookup <host>`.
  Resolves the hostname and returns the IP address.
- **Traceroute** — `traceroute <host>`. Requires root/capabilities;
  may return partial results if the `kilasos` user lacks raw socket
  access.

The **Service Scanner** (admin-only) probes 30 common TCP ports (22, 80,
443, 445, 139, 3306, 5432, 6379, 8080, 8443, etc.) on a target host
with a 500ms per-port timeout. Results show open ports and any banner
grabbed.

The **Internet Speed Test** (admin-only) runs `speedtest-cli --simple`
and returns download/upload Mbps and ping latency. Requires the
`speedtest-cli` binary.

## Bandwidth and connection stats

**Top Bandwidth IPs** — read-only. Aggregates `conntrack -L` output
by source IP, sorted by total bytes transferred. Shows the top 10
talkers. Requires the `conntrack` binary.

**Network Interfaces** dashboard — samples `/proc/net/dev` every poll
cycle (30s default) and computes delta TX/RX bytes per second for each
interface. Displayed as gauges on the Overview tab and as live numbers
on each interface card.

**Active Connections** — read-only. Shows established TCP/UDP
connections via `ss -tunp state established`. Includes the local
address, remote address, process name, and PID.

**Conntrack Table** — read-only. Shows active connection tracking
entries from `conntrack -L` (up to 5000 entries). Total entry count
available separately from `/proc/sys/net/netfilter/nf_conntrack_count`.

**Connection Summary** — read-only. Shows aggregated protocol stats
from `ss -s` (total TCP/UDP/RAW sockets, established/time-wait counts).

**Open Ports** — read-only audit from `ss -tunlp`. Lists every
listening port with the bound address, process name, and PID.

**TCP Congestion** — read-only. Reads
`/proc/sys/net/ipv4/tcp_congestion_control`. Common values:
`cubic` (default), `bbr`.

---

**Previous:** [Files ←](files.md)
**Next:** [Apps →](apps.md)
