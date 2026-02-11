# VPS Setup

## Requirements

- Debian/Ubuntu VPS
- WireGuard server configured
- MQTT broker (mosquitto)
- Python 3.7+

## Installation
```bash
# Install dependencies
apt update && apt install python3-pip iptables mosquitto

# Install Python packages
pip3 install paho-mqtt

# Copy script
mkdir -p /root/python
cd /root/python
# Copy fwdsync.py here

chmod +x fwdsync.py

# Setup cronjob (runs after router sends at :22)
crontab -e
# Add:
# 25,55 * * * * /usr/bin/python3 /root/python/fwdsync.py >> /tmp/fwd_sync.log 2>&1
```

## Configuration

Edit `fwdsync.py`:
```python
# MQTT settings
BROKER = "127.0.0.1"
TOPIC = "router/backup/firewall"

# WireGuard settings
VPN_INTERFACE = "wg0"
VPN_NETWORK = "10.9.0.0/24"  # Your VPN client network

# Port mapping
PORT_MAPPING_THRESHOLD = 80  # Ports below this are mapped
PORT_OFFSET = 2000           # Mapping offset (22 → 2022)

# Protected ports (never forwarded)
PROTECTED_PORTS = {
    51820,   # WireGuard
    1883,    # MQTT
    3282,    # Custom service
}
```

## Testing
```bash
# Manual run
sudo python3 /root/python/fwdsync.py

# Check logs
tail -f /tmp/fwd_sync.log

# Check iptables
sudo iptables -t nat -L PREROUTING -n -v
```

## Troubleshooting

### No config received
```bash
# Check MQTT broker
systemctl status mosquitto

# Test MQTT manually
mosquitto_sub -v -t "router/backup/firewall"
```

### Port forwards not working
```bash
# Check iptables rules
iptables -t nat -L PREROUTING -n -v

# Check FORWARD chain
iptables -L FORWARD -n -v

# Enable IP forwarding (if not enabled)
sysctl -w net.ipv4.ip_forward=1
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
```
