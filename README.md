# OpenWrt VPS Port Sync

Automatic synchronization of OpenWrt firewall port forwards to a VPS via MQTT.

## Features

- 🔄 MQTT-based config synchronization
- 🎯 Automatic port mapping (ports < 80 → +2000)
- 🛡️ Protection for critical ports (WireGuard, MQTT, etc.)
- 🌐 Exposed host support with VPN client exclusion
- 📝 Automatic log rotation at >100KB

## Architecture
```
OpenWrt Router (WireGuard Client)
    │
    │ WireGuard Tunnel
    ▼
VPS (WireGuard Server)
    │
    │ MQTT (retained messages)
    ▼
fwdsync.py (iptables automation)
```

## Use Case

You have an OpenWrt router connected to a VPS via WireGuard, using the VPS as exit node. You want to expose services from your home network (behind the router) to the internet via the VPS public IP.

This tool automatically syncs OpenWrt firewall redirects to iptables rules on the VPS.

## Setup

### VPS (Debian/Ubuntu)

See [vps/README.md](vps/README.md)

### OpenWrt Router

See [router/README.md](router/README.md)

## Configuration

In `fwdsync.py` adjust:
```python
BROKER = "127.0.0.1"              # MQTT Broker
VPN_INTERFACE = "wg0"             # WireGuard interface
VPN_NETWORK = "10.9.0.0/24"       # VPN client network
PORT_MAPPING_THRESHOLD = 80       # Ports < 80 are mapped
PORT_OFFSET = 2000                # Mapping offset
PROTECTED_PORTS = {51820, 1883, 3282}  # Never forward
```

## Port Mapping Examples

| Router Port | VPS Port | Description |
|-------------|----------|-------------|
| 22 (SSH)    | 2022     | Auto-mapped |
| 80 (HTTP)   | 80       | Direct pass-through |
| 443 (HTTPS) | 443      | Direct pass-through |

## How It Works

1. OpenWrt sends firewall config via MQTT (hourly + on changes)
2. VPS receives config and updates iptables DNAT rules
3. External traffic to VPS is forwarded to internal hosts
4. VPN clients (10.9.0.0/24) are excluded from port forwarding

## License

MIT
