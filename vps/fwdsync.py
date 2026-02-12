#!/usr/bin/env python3
"""
OpenWrt VPN Port Forwarding Sync mit Port-Mapping
Ports < 80: werden auf Port+2000 gemappt (z.B. 22 -> 2022)
Geschützte Ports: werden komplett blockiert
Exposed Host: NUR für externe IPs, NICHT für VPN-Clients
"""

import paho.mqtt.client as mqtt
import json
import subprocess
import time
import sys
import os
from datetime import datetime

# --- CONFIG ---
BROKER = "127.0.0.1"
TOPIC = "router/backup/firewall"
BACKUP_FILE = "/tmp/last_fw_config.json"
LOG_FILE = "/tmp/fwd_sync.log"
LOG_MAX_SIZE = 100 * 1024  # 100 KB

VPN_INTERFACE = "wg0"
VPN_NETWORK = "10.9.0.0/24"  # VPN-Clients die NICHT umgeleitet werden
ROUTER_VPN_IP = "10.9.0.1"

# SCHUTZ: Diese Ports NIE weiterleiten (auch nicht gemappt)
PROTECTED_PORTS = {
    51820,   # WireGuard
    1883,    # MQTT
    3282,    # Dein Service
}

# Ports < diesem Wert werden auf Port+2000 gemappt
PORT_MAPPING_THRESHOLD = 80
PORT_OFFSET = 2000

message_received = False

def rotate_log_if_needed():
    """Rotiert Log wenn > 100kB"""
    try:
        if os.path.exists(LOG_FILE):
            size = os.path.getsize(LOG_FILE)
            if size > LOG_MAX_SIZE:
                # Backup der letzten 20 Zeilen
                with open(LOG_FILE, 'r') as f:
                    lines = f.readlines()
                    last_lines = lines[-20:] if len(lines) > 20 else lines
                
                # Neu schreiben
                with open(LOG_FILE, 'w') as f:
                    f.write(f"=== LOG ROTATED at {datetime.now()} (was {size} bytes) ===\n")
                    f.writelines(last_lines)
                
                print(f"📝 Log rotiert: {size} bytes -> neu gestartet")
    except Exception as e:
        print(f"⚠️  Log-Rotation Fehler: {e}")

def log(msg):
    """Schreibt ins Log mit Timestamp"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] {msg}\n"
    print(msg, end='')  # Auch auf stdout
    try:
        with open(LOG_FILE, 'a') as f:
            f.write(line)
    except:
        pass

def is_port_protected(port):
    """Prüft ob Port geschützt werden muss"""
    try:
        port_num = int(port)
        if port_num in PROTECTED_PORTS:
            return True, f"Port {port_num} ist geschützt"
        # Auch gemappte Ports prüfen
        if port_num + PORT_OFFSET in PROTECTED_PORTS:
            return True, f"Gemappter Port {port_num + PORT_OFFSET} ist geschützt"
        return False, None
    except:
        # Port-Range?
        if '-' in str(port):
            start, end = map(int, str(port).split('-'))
            # Prüfe ob Range geschützte Ports enthält
            for p in range(start, end+1):
                if p in PROTECTED_PORTS or (p + PORT_OFFSET) in PROTECTED_PORTS:
                    return True, f"Port-Range enthält geschützten Port {p}"
        return False, None

def clear_existing_forwards():
    """Entfernt alle bestehenden Port-Forwards für diesen Router"""
    log("🔧 Lösche alte Port-Forwards...\n")
    
    result = subprocess.run(
        ["iptables", "-t", "nat", "-L", "PREROUTING", "-n", "--line-numbers"],
        capture_output=True, text=True
    )
    
    lines = result.stdout.strip().split('\n')
    rule_nums = []
    for line in lines:
        # DNAT Rules zu unserem Router-Netz oder RETURN (geschützte Ports)
        if ("192.168.5." in line and "DNAT" in line) or "RETURN" in line:
            parts = line.split()
            if parts and parts[0].isdigit():
                rule_nums.append(int(parts[0]))
    
    for num in sorted(rule_nums, reverse=True):
        subprocess.run(["iptables", "-t", "nat", "-D", "PREROUTING", str(num)])
        log(f"  ✓ Gelöscht: PREROUTING Rule #{num}\n")

    # FORWARD Chain: alte Rules für unser Netz aufräumen
    fwd_result = subprocess.run(
        ["iptables", "-L", "FORWARD", "-n", "--line-numbers"],
        capture_output=True, text=True
    )
    fwd_lines = fwd_result.stdout.strip().split('\n')
    fwd_nums = []
    for line in fwd_lines:
        if "192.168.5." in line:
            parts = line.split()
            if parts and parts[0].isdigit():
                fwd_nums.append(int(parts[0]))
    for num in sorted(fwd_nums, reverse=True):
        subprocess.run(["iptables", "-D", "FORWARD", str(num)])
        log(f"  ✓ Gelöscht: FORWARD Rule #{num}\n")

def create_exposed_host_rules(dest_ip, protocols):
    """
    Erstellt Exposed Host Rules mit Port-Mapping
    NUR für externe IPs - VPN-Clients (10.9.0.0/24) werden ausgeschlossen!
    
    Ports < 80: auf VPS-Port+2000, zu Router original Port
    Ports >= 80: direkt durchleiten
    Geschützte Ports: komplett blockieren
    """
    log(f"\n🎯 Erstelle EXPOSED HOST für {dest_ip}\n")
    log(f"   Geschützte Ports: {sorted(PROTECTED_PORTS)}\n")
    log(f"   Port-Mapping: <{PORT_MAPPING_THRESHOLD} -> +{PORT_OFFSET}\n")
    log(f"   ⚠️  VPN-Clients ({VPN_NETWORK}) ausgeschlossen\n")
    
    applied = 0
    
    for protocol in protocols:
        # Range 1: Niedrige Ports (1-79) -> gemappt auf 2001-2079
        low_port_start = 1
        low_port_end = PORT_MAPPING_THRESHOLD - 1
        mapped_start = low_port_start + PORT_OFFSET
        mapped_end = low_port_end + PORT_OFFSET
        
        cmd_low = [
            "iptables", "-t", "nat", "-A", "PREROUTING",
            "!", "-s", VPN_NETWORK,  # VPN-Clients ausschließen
            "-p", protocol,
            "-m", protocol,
            "--dport", f"{mapped_start}:{mapped_end}",
            "-j", "DNAT",
            "--to-destination", f"{dest_ip}:{low_port_start}-{low_port_end}"
        ]
        
        result = subprocess.run(cmd_low, capture_output=True, text=True)
        
        if result.returncode == 0:
            log(f"  ✓ Mapped: {protocol}/{mapped_start}-{mapped_end} -> {dest_ip}:{low_port_start}-{low_port_end} (extern only)\n")
            applied += 1
        else:
            log(f"  ❌ Fehler (low): {result.stderr}\n")
        
        # Range 2: Hohe Ports (80-65535) -> direkt
        cmd_high = [
            "iptables", "-t", "nat", "-A", "PREROUTING",
            "!", "-s", VPN_NETWORK,  # VPN-Clients ausschließen
            "-p", protocol,
            "-m", protocol,
            "--dport", f"{PORT_MAPPING_THRESHOLD}:65535",
            "-j", "DNAT",
            "--to-destination", dest_ip
        ]
        
        result = subprocess.run(cmd_high, capture_output=True, text=True)
        
        if result.returncode == 0:
            log(f"  ✓ Direct: {protocol}/{PORT_MAPPING_THRESHOLD}-65535 -> {dest_ip} (extern only)\n")
            applied += 1
        else:
            log(f"  ❌ Fehler (high): {result.stderr}\n")
        
        # Explizit geschützte Ports blockieren
        for port in PROTECTED_PORTS:
            # Blockiere sowohl original als auch gemappt
            for block_port in [port, port - PORT_OFFSET if port > PORT_OFFSET else None]:
                if block_port and block_port > 0:
                    block_cmd = [
                        "iptables", "-t", "nat", "-I", "PREROUTING", "1",
                        "-p", protocol,
                        "--dport", str(block_port),
                        "-j", "RETURN"
                    ]
                    subprocess.run(block_cmd)
                    log(f"  🛡️  Blockiert: {protocol}/{block_port}\n")
    
    return applied

def apply_port_forwards(config_data):
    """Analysiert Config und erstellt iptables Rules"""
    
    if "values" not in config_data:
        log("❌ Keine 'values' in Config gefunden\n")
        return
    
    redirects = []
    
    for key, value in config_data["values"].items():
        if value.get(".type") == "redirect":
            redirects.append(value)
    
    log(f"\n📋 Gefundene Redirects: {len(redirects)}\n")
    
    applied = 0
    
    for redir in redirects:
        # Nur aktive Redirects
        if redir.get("enabled") == "0":
            log(f"  ⊘ Überspringe (disabled): {redir.get('name', 'unnamed')}\n")
            continue
        
        # Nur Redirects die src='vpn' haben
        if redir.get("src") != "vpn":
            continue
        
        name = redir.get("name", "unnamed")
        target = redir.get("target")
        dest_ip = redir.get("dest_ip")
        src_dport = redir.get("src_dport")
        dest_port = redir.get("dest_port")
        proto = redir.get("proto", "tcp")
        
        log(f"\n  🔍 Prüfe: {name}\n")
        
        # EXPOSED HOST (kein src_dport = alle Ports)
        if not src_dport and dest_ip and target == "DNAT":
            protocols = proto.split()
            applied += create_exposed_host_rules(dest_ip, protocols)
            continue
        
        # Normaler Port-Forward mit Port-Mapping
        if src_dport and dest_ip and target == "DNAT":
            
            # Schutzprüfung
            protected, reason = is_port_protected(src_dport)
            if protected:
                log(f"  🛡️  BLOCKIERT: {reason}\n")
                continue
            
            try:
                src_port_num = int(src_dport)
                
                # Port-Mapping für niedrige Ports
                if src_port_num < PORT_MAPPING_THRESHOLD:
                    vps_port = src_port_num + PORT_OFFSET
                    router_port = dest_port if dest_port else src_dport
                    log(f"  🔀 Port-Mapping: VPS:{vps_port} -> Router:{router_port}\n")
                else:
                    vps_port = src_dport
                    router_port = dest_port if dest_port else src_dport
                
            except:
                # Kein Mapping für Ranges
                vps_port = src_dport
                router_port = dest_port if dest_port else src_dport
            
            protocols = proto.split()
            
            for protocol in protocols:
                cmd = [
                    "iptables", "-t", "nat", "-A", "PREROUTING",
                    "!", "-s", VPN_NETWORK,
                    "-p", protocol,
                    "--dport", str(vps_port),
                    "-j", "DNAT",
                    "--to-destination", f"{dest_ip}:{router_port}"
                ]
                
                result = subprocess.run(cmd, capture_output=True, text=True)
                
                if result.returncode == 0:
                    log(f"  ✓ Forward: {protocol}/{vps_port} -> {dest_ip}:{router_port}\n")
                    applied += 1
                else:
                    log(f"  ❌ Fehler: {result.stderr}\n")
    
    # FORWARD Chain: Return-Traffic (Antworten) erlauben
    subprocess.run([
        "iptables", "-A", "FORWARD",
        "-m", "state", "--state", "RELATED,ESTABLISHED",
        "-j", "ACCEPT"
    ])

    # FORWARD Chain: Neue Verbindungen zu Port-Forward Zielen via WireGuard
    subprocess.run([
        "iptables", "-A", "FORWARD",
        "-o", VPN_INTERFACE,
        "-d", "192.168.5.0/24",
        "-m", "state", "--state", "NEW",
        "-j", "ACCEPT"
    ])
    
    log(f"\n✅ {applied} Port-Forwards konfiguriert\n")

def on_connect(client, userdata, flags, rc, props=None):
    log(f"✓ Verbunden mit MQTT Broker (rc={rc})\n")
    client.subscribe(TOPIC)
    log(f"✓ Subscribed zu: {TOPIC}\n")

def on_message(client, userdata, msg):
    global message_received
    log(f"\n✓ Message empfangen: {len(msg.payload)} bytes\n")
    
    try:
        data = json.loads(msg.payload.decode())
        
        with open(BACKUP_FILE, "w") as f:
            json.dump(data, f, indent=4)
        log(f"✓ Backup gespeichert\n")
        
        log("\n" + "="*60 + "\n")
        clear_existing_forwards()
        apply_port_forwards(data)
        log("="*60 + "\n\n")
        
        message_received = True
        
    except Exception as e:
        log(f"✗ Fehler: {e}\n")
        import traceback
        traceback.print_exc()
    finally:
        client.disconnect()

def main():
    # Log-Rotation prüfen
    rotate_log_if_needed()
    
    log("🚀 OpenWrt VPN Port Forward Sync mit VPN-Client-Schutz\n")
    log(f"   Start: {datetime.now()}\n")
    log(f"   VPN Network (ausgeschlossen): {VPN_NETWORK}\n")
    log(f"   Geschützte Ports: {sorted(PROTECTED_PORTS)}\n")
    log(f"   Port-Mapping: <{PORT_MAPPING_THRESHOLD} -> +{PORT_OFFSET}\n")
    
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    client.on_connect = on_connect
    client.on_message = on_message
    
    log(f"Verbinde zu {BROKER}:1883 ...\n")
    client.connect(BROKER, 1883, 60)
    
    log("Warte auf Message (max 30 Sek) ...\n")
    client.loop_start()
    
    for i in range(30):
        if message_received:
            break
        time.sleep(1)
    
    client.loop_stop()
    
    if not message_received:
        log("✗ Timeout - keine Message empfangen\n")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
