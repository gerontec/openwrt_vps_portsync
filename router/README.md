# OpenWrt Setup

## Installation
```bash
# 1. Install MQTT client
opkg update
opkg install mosquitto-client-ssl

# 2. Copy script
cat > /root/sync_firewall.sh << 'SCRIPT'
#!/bin/sh
MQTT_BROKER="10.9.0.1"
MQTT_TOPIC="router/backup/firewall"
ubus call uci get '{"config":"firewall"}' | \
    mosquitto_pub -h "$MQTT_BROKER" -t "$MQTT_TOPIC" -s -r -q 1
SCRIPT

chmod +x /root/sync_firewall.sh

# 3. Setup cronjob
crontab -e
# Add:
# 22 * * * * /root/sync_firewall.sh

# 4. Test
/root/sync_firewall.sh
```

## Firewall Redirect Examples

### SSH to internal host (port 2022)
```bash
uci add firewall redirect
uci set firewall.@redirect[-1].name='SSH-to-deb12'
uci set firewall.@redirect[-1].src='vpn'
uci set firewall.@redirect[-1].dest='lan'
uci set firewall.@redirect[-1].src_dport='2022'
uci set firewall.@redirect[-1].dest_ip='192.168.5.24'
uci set firewall.@redirect[-1].dest_port='22'
uci set firewall.@redirect[-1].proto='tcp'
uci set firewall.@redirect[-1].target='DNAT'
uci set firewall.@redirect[-1].enabled='1'
uci commit firewall
/etc/init.d/firewall restart
/root/sync_firewall.sh
```

### Exposed Host (all ports)
```bash
uci add firewall redirect
uci set firewall.@redirect[-1].name='VPN-Exposed-Host'
uci set firewall.@redirect[-1].src='vpn'
uci set firewall.@redirect[-1].dest='lan'
uci set firewall.@redirect[-1].dest_ip='192.168.5.24'
uci set firewall.@redirect[-1].proto='tcp udp'
uci set firewall.@redirect[-1].target='DNAT'
uci set firewall.@redirect[-1].enabled='1'
uci commit firewall
/etc/init.d/firewall restart
/root/sync_firewall.sh
```
