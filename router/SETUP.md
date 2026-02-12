# OpenWrt Router Setup Guide

## Prerequisites

- OpenWrt 24.10.4 or later with nftables (fw4)
- WireGuard client configured (wg0)
- MQTT client installed: `opkg install mosquitto-client-ssl`

## Network Topology
```
Internet
    |
    | (WireGuard Tunnel)
    v
VPS (10.9.0.1) - WireGuard Server
    |
    | wg0
    v
OpenWrt Router (10.9.0.5) - WireGuard Client
    |
    | br-lan (192.168.5.1)
    v
Internal Network (192.168.5.0/24)
    |
    +-- deb12 (192.168.5.24) - Exposed Host
```

## Step 1: Install MQTT Client
```bash
opkg update
opkg install mosquitto-client-ssl
```

## Step 2: Configure Firewall

### Enable VPN -> LAN Forwarding

This is **critical** for the exposed host to work:
```bash
uci add firewall forwarding
uci set firewall.@forwarding[-1].src='vpn'
uci set firewall.@forwarding[-1].dest='lan'
uci commit firewall
```

### Enable Masquerading on VPN Zone

This ensures return traffic is routed correctly:
```bash
uci set firewall.wg_zone.masq='1'
uci set firewall.wg_zone.masq6='1'
uci commit firewall
```

### Add Exposed Host Redirect
```bash
uci add firewall redirect
uci set firewall.@redirect[-1].name='VPN-Exposed-to-deb12'
uci set firewall.@redirect[-1].src='vpn'
uci set firewall.@redirect[-1].dest='lan'
uci set firewall.@redirect[-1].dest_ip='192.168.5.24'
uci set firewall.@redirect[-1].proto='tcp udp'
uci set firewall.@redirect[-1].target='DNAT'
uci set firewall.@redirect[-1].enabled='1'
uci commit firewall
/etc/init.d/firewall restart
```

## Step 3: Setup Sync Script
```bash
cat > /root/sync_firewall.sh << 'SCRIPT'
#!/bin/sh
MQTT_BROKER="10.9.0.1"
MQTT_TOPIC="router/backup/firewall"
ubus call uci get '{"config":"firewall"}' | \
    mosquitto_pub -h "$MQTT_BROKER" -t "$MQTT_TOPIC" -s -r -q 1
SCRIPT

chmod +x /root/sync_firewall.sh
```

## Step 4: Setup Cronjob
```bash
crontab -e

# Add this line:
22 * * * * /root/sync_firewall.sh
```

This sends the firewall config to the VPS every hour at minute 22.

## Step 5: Manual Sync After Changes

Whenever you change the firewall config, manually sync:
```bash
uci commit firewall
/etc/init.d/firewall restart
/root/sync_firewall.sh
```

## Verification

### Check Firewall Config
```bash
# Show all redirects
uci show firewall | grep redirect

# Show all forwardings
uci show firewall | grep forwarding

# Check VPN zone masquerading
uci show firewall.wg_zone
```

### Check nftables Rules
```bash
# Show DNAT rules
nft list ruleset | grep -A 5 dnat

# Check packet counters (should increase when traffic flows)
nft list ruleset | grep -A 3 "VPN-Exposed"
```

### Test from VPS
```bash
# On VPS, after running fwdsync.py
curl http://10.9.0.5
# Should show the web page from 192.168.5.24
```

## Troubleshooting

### Traffic not reaching internal host

1. Check forwarding rule exists:
```bash
   uci show firewall | grep "vpn.*lan"
```

2. Check masquerading is enabled:
```bash
   uci show firewall.wg_zone.masq
```

3. Check redirect is enabled:
```bash
   uci show firewall | grep -A 5 "Exposed"
```

### Config not syncing to VPS

1. Test MQTT connection:
```bash
   mosquitto_pub -h 10.9.0.1 -t "test/topic" -m "hello"
```

2. Check VPS is listening:
```bash
   # On VPS
   mosquitto_sub -v -t "router/backup/firewall"
```

3. Manually trigger sync:
```bash
   /root/sync_firewall.sh
```
