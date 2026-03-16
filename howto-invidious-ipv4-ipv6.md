# Invidious IPv4→IPv6 Gateway Setup

Self-hosted Invidious (YouTube frontend) running on an IPv6-only server, accessible for IPv4 browsers via VPS gateway.

## Architecture

```
IPv4-Browser  →  VPS (82.165.41.91):7000
                   │ socat TCP4→TCP6
                   ↓
              OpenWrt Exposed Host IPv6
              (2a02:810d:4117:7300:1ad6:c7ff:fe90:bb17):7000
                   │ nftables DNAT
                   ↓
              pve6 (2a02:810d:4117:73fd::23):7000
              Invidious + companion

IPv6-Browser  →  pve6.heissa.de:7000  (direkt, AAAA-Record)

YouTube-Traffic  →  pve6 native IPv6  (kein VPS-Umweg)
```

## DNS (dual-stack yt.heissa.de)

```
yt.heissa.de.   A    82.165.41.91              ; IPv4 → VPS Gateway
yt.heissa.de.   AAAA 2a02:810d:4117:73fd::23  ; IPv6 → direkt pve6
pve6.heissa.de. AAAA 2a02:810d:4117:73fd::23  ; IPv6-only
```

## 1. pve6 — Invidious + companion

### Invidious config (`/home/gh/invidious/config.yml`)

```yaml
db:
  dbname: invidious
  user: kemal
  password: kemal
  host: localhost
  port: 5433
check_tables: true
domain: pve6.heissa.de
https_only: false
port: 7000
default_user_preferences:
  locale: de
  dark_mode: "dark"
  quality: dash
  volume: 100
  local: true
invidious_companion:
  - private_url: "http://localhost:8282/companion"
    public_url: "http://pve6.heissa.de:7000/companion"
invidious_companion_key: "<your-key>"
```

> **WICHTIG**: `public_url` darf nie geändert werden. Invidious leitet DASH-Manifest-Requests an companion weiter via `/companion/*` Pfad.

### Invidious starten

```bash
docker run -d --name invidious --network host \
  -v /etc/gai.conf:/etc/gai.conf:ro \
  -v /home/gh/invidious/config.yml:/invidious/config/config.yml:ro \
  --restart unless-stopped \
  quay.io/invidious/invidious:latest
```

### companion (`/home/gh/invidious-companion/docker-compose.yml`)

```yaml
services:
  invidious-companion:
    image: quay.io/invidious/invidious-companion:latest
    network_mode: host
    volumes:
      - /etc/gai.conf:/etc/gai.conf:ro
    environment:
      SERVER_SECRET_KEY: "<your-key>"
      HOST: "::"
```

### `/etc/gai.conf` auf pve6 (IPv6-only für ausgehende Verbindungen)

```
precedence  ::1/128       50
precedence  ::/0          40
precedence  2002::/16     30
precedence  ::/96         20
precedence  ::ffff:0:0/96  0
```

## 2. VPS (ipgate1) — socat Gateway

### systemd service `/etc/systemd/system/socat-invidious.service`

```ini
[Unit]
Description=socat IPv4->IPv6 bridge for Invidious port 7000
After=network.target

[Service]
ExecStart=/usr/bin/socat TCP4-LISTEN:7000,fork,reuseaddr TCP6:[2a02:810d:4117:7300:1ad6:c7ff:fe90:bb17]:7000
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
systemctl enable --now socat-invidious
```

### systemd service `/etc/systemd/system/iptables-invidious.service`

Verhindert dass der catch-all DNAT in PREROUTING port 7000 abfängt:

```ini
[Unit]
Description=iptables RETURN rule for port 7000 (socat local)
After=network.target
Before=socat-invidious.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/sbin/iptables -t nat -I PREROUTING 1 -p tcp --dport 7000 -j RETURN
ExecStop=/sbin/iptables -t nat -D PREROUTING -p tcp --dport 7000 -j RETURN

[Install]
WantedBy=multi-user.target
```

```bash
systemctl enable --now iptables-invidious
```

### WireGuard (`/etc/wireguard/wg0.conf`)

OpenWrt-Peer darf **keine** IPv6-Ranges in `AllowedIPs` haben:

```ini
[Peer]
# tplink-archer-openwrt
PublicKey = oDsJ6GJ0D6OZ2vJccRqFCMttFnsGzPe584JZQdBRATY=
AllowedIPs = 10.9.0.5/32, 192.168.5.0/24
# NICHT: 2a02:2479:8f:e700:f::/80  ← würde IPv6-Traffic falsch routen
```

## 3. OpenWrt — IPv6 DNAT

Port 7000 von WAN (FritzBox Exposed Host) zu pve6 weiterleiten:

```bash
uci add firewall redirect
uci set firewall.@redirect[-1].name='invidious-ipv6'
uci set firewall.@redirect[-1].src='wan'
uci set firewall.@redirect[-1].dest='lan'
uci set firewall.@redirect[-1].proto='tcp'
uci set firewall.@redirect[-1].src_dport='7000'
uci set firewall.@redirect[-1].dest_ip='2a02:810d:4117:73fd::23'
uci set firewall.@redirect[-1].dest_port='7000'
uci set firewall.@redirect[-1].family='ipv6'
uci commit firewall && fw4 reload
```

## 4. FritzBox

- OpenWrt (`192.168.178.47`) als **Exposed Host** eingetragen
- Alle eingehenden Verbindungen (inkl. port 7000) werden an OpenWrt weitergeleitet
- OpenWrt DNAT leitet weiter zu pve6

## Traffic-Flow Details

### DASH Video-Playback (IPv4-Browser)

```
1. Browser → yt.heissa.de:7000 (A → 82.165.41.91)
2. VPS socat → OpenWrt IPv6:7000
3. OpenWrt DNAT → pve6:7000 (Invidious)
4. Invidious redirect → /companion/api/manifest/dash/id/VIDEO_ID
5. Browser → pve6.heissa.de:7000/companion/* (relative URL im DASH-Manifest)
   → VPS:7000 → OpenWrt → pve6 companion:8282
6. companion → YouTube via pve6 IPv6 (googlevideo.com)
7. Video-Segmente → Browser via companion-Proxy
```

### YouTube-Downloads (TubeArchivist)

```
TubeArchivist (network_mode: host, gai.conf IPv6-only)
→ direkt 2a02:810d:4117:73fd::23 → YouTube IPv6
```
