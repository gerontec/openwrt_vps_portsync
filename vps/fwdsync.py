#!/usr/bin/env python3
"""
OpenWrt VPN Port Forwarding Sync
Syncs OpenWrt firewall port forwards to VPS iptables via MQTT

Uses custom iptables chains (FWDSYNC_*) for clean rule management.
Flush chain = all rules gone. No stale rules, no parsing needed.
"""
VERSION = "2.1.0"

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
LOG_MAX_SIZE = 100 * 1024

VPN_INTERFACE = "wg0"
PUBLIC_INTERFACE = "ens6"
VPN_NETWORK = "10.9.0.0/24"
ROUTER_VPN_IP = "10.9.0.5"

# Ports that are completely blocked (no forwarding at all)
BLOCKED_PORTS = {
    22,      # SSH (VPS itself)
    51820,   # WireGuard
    1883,    # MQTT
    3282,    # Custom service
}

# Custom chain names - all our rules go here, never in main chains
CHAIN_NAT = "FWDSYNC"
CHAIN_FWD = "FWDSYNC_FWD"
CHAIN_POST = "FWDSYNC_POST"

message_received = False

def rotate_log_if_needed():
    try:
        if os.path.exists(LOG_FILE):
            size = os.path.getsize(LOG_FILE)
            if size > LOG_MAX_SIZE:
                with open(LOG_FILE, 'r') as f:
                    lines = f.readlines()
                    last_lines = lines[-20:] if len(lines) > 20 else lines
                with open(LOG_FILE, 'w') as f:
                    f.write(f"=== LOG ROTATED at {datetime.now()} (was {size} bytes) ===\n")
                    f.writelines(last_lines)
                print(f"📝 Log rotated: {size} bytes")
    except Exception as e:
        print(f"⚠️  Log rotation error: {e}")

def log(msg):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] {msg}\n"
    print(msg, end='')
    try:
        with open(LOG_FILE, 'a') as f:
            f.write(line)
    except:
        pass

def run_ipt(*args):
    """Run iptables command, return success bool"""
    return subprocess.run(["iptables"] + list(args), capture_output=True).returncode == 0

def setup_system():
    log("🌐 Setup system...\n")
    result = subprocess.run(
        ["sysctl", "-w", "net.ipv4.ip_forward=1"],
        capture_output=True, text=True
    )
    if result.returncode == 0:
        log("  ✓ IP forwarding enabled\n")

def setup_chains():
    """Create custom iptables chains and jump rules (idempotent)"""
    log("🔗 Setup iptables chains...\n")

    chains = [
        ("nat", CHAIN_NAT, "PREROUTING"),
        ("filter", CHAIN_FWD, "FORWARD"),
        ("nat", CHAIN_POST, "POSTROUTING"),
    ]

    for table, chain, parent in chains:
        # Create chain (ignore error if already exists)
        subprocess.run(
            ["iptables", "-t", table, "-N", chain],
            capture_output=True
        )

        # Check if jump rule already exists
        result = subprocess.run(
            ["iptables", "-t", table, "-C", parent, "-j", chain],
            capture_output=True
        )

        if result.returncode != 0:
            # Insert jump at top so our rules are processed first
            subprocess.run(
                ["iptables", "-t", table, "-I", parent, "1", "-j", chain],
                capture_output=True
            )
            log(f"  ✓ Added jump: {parent} -> {chain} ({table})\n")

    log(f"  ✓ Chains ready\n")

def cleanup_old_rules():
    """One-time migration: remove old-style rules from main chains"""
    log("🧹 Cleanup old rules from main chains...\n")

    # Clean old PREROUTING rules (DNAT and RETURN with -i ens6)
    result = subprocess.run(
        ["iptables-save", "-t", "nat"],
        capture_output=True, text=True
    )

    deleted = 0
    for line in result.stdout.split('\n'):
        if (f"-i {PUBLIC_INTERFACE}" in line and
            ("DNAT" in line or "RETURN" in line) and
            "-A PREROUTING" in line):
            delete_line = line.replace("-A PREROUTING", "-D PREROUTING")
            parts = delete_line.split()
            subprocess.run(["iptables", "-t", "nat"] + parts[1:], capture_output=True)
            deleted += 1

    # Clean old FORWARD rules
    result_all = subprocess.run(
        ["iptables-save"],
        capture_output=True, text=True
    )

    for line in result_all.stdout.split('\n'):
        if (("-i " + PUBLIC_INTERFACE in line or "-o " + PUBLIC_INTERFACE in line) and
            "-A FORWARD" in line and
            VPN_NETWORK in line):
            delete_line = line.replace("-A FORWARD", "-D FORWARD")
            parts = delete_line.split()
            subprocess.run(["iptables"] + parts[1:], capture_output=True)
            deleted += 1

    # Clean old POSTROUTING MASQUERADE rules for wg0
    for line in result.stdout.split('\n'):
        if (f"-o {VPN_INTERFACE}" in line and
            "MASQUERADE" in line and
            "-A POSTROUTING" in line):
            delete_line = line.replace("-A POSTROUTING", "-D POSTROUTING")
            parts = delete_line.split()
            subprocess.run(["iptables", "-t", "nat"] + parts[1:], capture_output=True)
            deleted += 1

    log(f"  ✓ Removed {deleted} old rules from main chains\n")

def clear_existing_forwards():
    """Flush all custom chains - instant, clean, no parsing"""
    log("🔧 Flush forwarding rules...\n")

    for table, chain in [("nat", CHAIN_NAT), ("filter", CHAIN_FWD), ("nat", CHAIN_POST)]:
        result = subprocess.run(
            ["iptables", "-t", table, "-F", chain],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            log(f"  ✓ Flushed {chain}\n")

def is_port_blocked(port):
    """Check if port should be completely blocked"""
    try:
        port_num = int(port)
        if port_num in BLOCKED_PORTS:
            return True, f"Port {port_num} blocked"
        return False, None
    except:
        if '-' in str(port):
            start, end = map(int, str(port).split('-'))
            for p in range(start, end+1):
                if p in BLOCKED_PORTS:
                    return True, f"Port range contains blocked port {p}"
        return False, None

def create_port_range_rules(start, end, protocol, dest_ip_port):
    """
    Create rules for a port range, skipping blocked ports
    Returns list of applied rules
    """
    rules_created = []

    # Split range into segments, excluding blocked ports
    current_start = start

    for port in range(start, end + 1):
        if port in BLOCKED_PORTS:
            # Create rule for segment before blocked port
            if current_start < port:
                cmd = [
                    "iptables", "-t", "nat", "-A", CHAIN_NAT,
                    "-i", PUBLIC_INTERFACE,
                    "-p", protocol,
                    "--dport", f"{current_start}:{port-1}" if current_start < port - 1 else str(current_start),
                    "-j", "DNAT",
                    "--to-destination", dest_ip_port
                ]
                if subprocess.run(cmd, capture_output=True).returncode == 0:
                    rules_created.append((current_start, port-1))
            current_start = port + 1

    # Create rule for remaining segment
    if current_start <= end:
        cmd = [
            "iptables", "-t", "nat", "-A", CHAIN_NAT,
            "-i", PUBLIC_INTERFACE,
            "-p", protocol,
            "--dport", f"{current_start}:{end}" if current_start < end else str(current_start),
            "-j", "DNAT",
            "--to-destination", dest_ip_port
        ]
        if subprocess.run(cmd, capture_output=True).returncode == 0:
            rules_created.append((current_start, end))

    return rules_created

def create_exposed_host_rules(protocols):
    """Create exposed host rules with port ranges, excluding blocked ports"""
    log(f"\n🎯 Create EXPOSED HOST via Router {ROUTER_VPN_IP}\n")
    log(f"   Blocked ports: {sorted(BLOCKED_PORTS)}\n")

    applied = 0

    for protocol in protocols:
        # All ports 1:1 (1-65535), skipping blocked ports
        rules = create_port_range_rules(
            1,
            65535,
            protocol,
            ROUTER_VPN_IP
        )

        for start, end in rules:
            log(f"  ✓ Forward: {protocol}/{start}-{end} -> {ROUTER_VPN_IP}\n")
            applied += 1

    return applied

def apply_port_forwards(config_data):
    """Parse config and create iptables rules"""

    if "values" not in config_data:
        log("❌ No 'values' found in config\n")
        return

    redirects = [v for v in config_data["values"].values() if v.get(".type") == "redirect"]
    log(f"\n📋 Found {len(redirects)} redirects\n")

    applied = 0

    for redir in redirects:
        if redir.get("enabled") == "0" or redir.get("src") != "vpn":
            continue

        name = redir.get("name", "unnamed")
        log(f"\n  🔍 Processing: {name}\n")

        # Exposed host
        if not redir.get("src_dport") and redir.get("dest_ip") and redir.get("target") == "DNAT":
            log(f"     Type: Exposed Host -> {redir.get('dest_ip')}\n")
            protocols = redir.get("proto", "tcp").split()
            applied += create_exposed_host_rules(protocols)
            continue

        # Specific port forward
        if redir.get("src_dport") and redir.get("target") == "DNAT":
            src_dport = redir.get("src_dport")
            dest_port = redir.get("dest_port", src_dport)

            blocked, reason = is_port_blocked(src_dport)
            if blocked:
                log(f"  🛡️  BLOCKED: {reason} (VPS port {src_dport})\n")
                continue

            log(f"     Port: {src_dport} -> {dest_port}\n")

            for protocol in redir.get("proto", "tcp").split():
                cmd = [
                    "iptables", "-t", "nat", "-A", CHAIN_NAT,
                    "-i", PUBLIC_INTERFACE,
                    "-p", protocol,
                    "--dport", str(src_dport),
                    "-j", "DNAT",
                    "--to-destination", f"{ROUTER_VPN_IP}:{dest_port}"
                ]

                if subprocess.run(cmd, capture_output=True).returncode == 0:
                    log(f"  ✓ Forward: {protocol}/{src_dport} -> {ROUTER_VPN_IP}:{dest_port}\n")
                    applied += 1

    # Setup FORWARD chain
    log("\n🔗 Setup FORWARD rules...\n")

    subprocess.run([
        "iptables", "-A", CHAIN_FWD,
        "-i", PUBLIC_INTERFACE, "-o", VPN_INTERFACE,
        "-d", VPN_NETWORK,
        "-j", "ACCEPT"
    ])

    subprocess.run([
        "iptables", "-A", CHAIN_FWD,
        "-i", VPN_INTERFACE, "-o", PUBLIC_INTERFACE,
        "-s", VPN_NETWORK,
        "-j", "ACCEPT"
    ])

    log(f"  ✓ FORWARD rules configured\n")

    # MASQUERADE for traffic into WireGuard tunnel
    # Without this, replies from LAN hosts go via WAN instead of back through wg0
    subprocess.run([
        "iptables", "-t", "nat", "-A", CHAIN_POST,
        "-o", VPN_INTERFACE,
        "-d", VPN_NETWORK,
        "-j", "MASQUERADE"
    ])

    log(f"  ✓ MASQUERADE for {VPN_INTERFACE} configured\n")
    log(f"\n✅ {applied} port forwards configured\n")

def on_connect(client, userdata, flags, rc, props=None):
    log(f"✓ Connected to MQTT broker (rc={rc})\n")
    client.subscribe(TOPIC)
    log(f"✓ Subscribed to: {TOPIC}\n")

def on_message(client, userdata, msg):
    global message_received
    log(f"\n✓ Message received: {len(msg.payload)} bytes\n")

    try:
        data = json.loads(msg.payload.decode())

        with open(BACKUP_FILE, "w") as f:
            json.dump(data, f, indent=4)
        log(f"✓ Backup saved to {BACKUP_FILE}\n")

        log("\n" + "="*60 + "\n")
        setup_system()
        setup_chains()
        cleanup_old_rules()
        clear_existing_forwards()
        apply_port_forwards(data)
        log("="*60 + "\n\n")

        message_received = True

    except Exception as e:
        log(f"✗ Error: {e}\n")
        import traceback
        traceback.print_exc()
    finally:
        client.disconnect()

def main():
    rotate_log_if_needed()

    log(f"🚀 OpenWrt VPN Port Forward Sync v{VERSION}\n")
    log(f"   Start: {datetime.now()}\n")
    log(f"   Router VPN IP: {ROUTER_VPN_IP}\n")
    log(f"   Blocked Ports: {sorted(BLOCKED_PORTS)}\n\n")

    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    client.on_connect = on_connect
    client.on_message = on_message

    log(f"Connecting to {BROKER}:1883 ...\n")
    client.connect(BROKER, 1883, 60)

    log("Waiting for message (max 30 sec) ...\n")
    client.loop_start()

    for i in range(30):
        if message_received:
            break
        time.sleep(1)

    client.loop_stop()

    if not message_received:
        log("✗ Timeout - no message received\n")
        return 1

    return 0

if __name__ == "__main__":
    sys.exit(main())
