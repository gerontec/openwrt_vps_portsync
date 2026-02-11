import paho.mqtt.client as mqtt
import json
import os
import time

BROKER = "127.0.0.1"
TOPIC = "router/backup/firewall"
FILE = "/tmp/last_fw_config.json"

message_received = False

def on_connect(client, userdata, flags, rc, props=None):
    print(f"✓ Verbunden mit Broker (rc={rc})")
    client.subscribe(TOPIC)
    print(f"✓ Subscribed zu: {TOPIC}")

def on_message(client, userdata, msg):
    global message_received
    print(f"✓ Message empfangen auf {msg.topic}")
    print(f"  Payload-Größe: {len(msg.payload)} bytes")
    
    try:
        data = json.loads(msg.payload.decode())
        with open(FILE, "w") as f:
            json.dump(data, f, indent=4)
        print(f"✓ Gespeichert in {FILE}")
        message_received = True
    except Exception as e:
        print(f"✗ Fehler: {e}")
    finally:
        client.disconnect()

client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
client.on_connect = on_connect
client.on_message = on_message

print(f"Verbinde zu {BROKER}:1883 ...")
client.connect(BROKER, 1883, 60)  # Sync statt async

print("Warte auf Message (max 30 Sek) ...")
client.loop_start()

# Länger warten
for i in range(30):
    if message_received:
        break
    time.sleep(1)
    if i % 5 == 0:
        print(f"  ... noch {30-i} Sek")

client.loop_stop()

if not message_received:
    print("✗ Timeout - keine Message empfangen")
    os._exit(1)

os._exit(0)
