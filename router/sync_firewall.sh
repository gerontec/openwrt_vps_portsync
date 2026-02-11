#!/bin/sh
# OpenWrt Firewall Config Sync via MQTT
# Sends firewall config to VPS

MQTT_BROKER="10.9.0.1"
MQTT_TOPIC="router/backup/firewall"

# Fetch config as JSON and send via MQTT
ubus call uci get '{"config":"firewall"}' | \
    mosquitto_pub -h "$MQTT_BROKER" \
                  -t "$MQTT_TOPIC" \
                  -s \
                  -r \
                  -q 1
