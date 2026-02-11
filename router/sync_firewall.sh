#!/bin/sh
# OpenWrt Firewall Config Sync via MQTT
# Sendet Firewall-Config an VPS

MQTT_BROKER="10.9.0.1"
MQTT_TOPIC="router/backup/firewall"

# Config als JSON holen und via MQTT senden
ubus call uci get '{"config":"firewall"}' | \
    mosquitto_pub -h "$MQTT_BROKER" \
                  -t "$MQTT_TOPIC" \
                  -s \
                  -r \
                  -q 1
