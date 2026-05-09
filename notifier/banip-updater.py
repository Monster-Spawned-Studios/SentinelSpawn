#!/usr/bin/env python3
"""
Automatic banIP Blocklist Updater from Suricata Alerts
Watches eve.json for high-severity malicious IPs and automatically blocks them on OpenWRT via SSH + banIP.

Requirements:
- paramiko (SSH library)
- OpenWRT with banIP installed and configured (opkg install banip)
- SSH key-based auth from this container to OpenWRT (no passwords)

Environment variables (in .env):
- OPENVRT_HOST=192.168.1.1
- OPENVRT_USER=root
- OPENVRT_SSH_KEY_PATH=/app/id_rsa_openwrt   # Mount your private key here
- BANIP_BLOCKLIST_NAME=banip     # or "auto" / custom list name
- BANIP_MIN_SEVERITY=2           # Only block severity <= this (1 or 2 recommended)

Security note: Use a dedicated low-privilege SSH key with command restriction on OpenWRT if possible.
"""

import os
import json
import time
import logging
import paramiko
from pathlib import Path
from datetime import datetime

EVE_LOG = "/var/log/suricata/eve.json"
OPENVRT_HOST = os.getenv("OPENVRT_HOST", "")
OPENVRT_USER = os.getenv("OPENVRT_USER", "root")
OPENVRT_SSH_KEY_PATH = os.getenv("OPENVRT_SSH_KEY_PATH", "/app/id_rsa_openwrt")
BANIP_BLOCKLIST_NAME = os.getenv("BANIP_BLOCKLIST_NAME", "banip")
BANIP_MIN_SEVERITY = int(os.getenv("BANIP_MIN_SEVERITY", "2"))

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Track already-blocked IPs to avoid duplicates
blocked_ips = set()

def connect_ssh():
    """Establish SSH connection to OpenWRT."""
    if not OPENVRT_HOST:
        logger.error("OPENVRT_HOST not set in .env — banIP updates disabled.")
        return None

    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        key = paramiko.RSAKey.from_private_key_file(OPENVRT_SSH_KEY_PATH)
        ssh.connect(OPENVRT_HOST, username=OPENVRT_USER, pkey=key, timeout=10)
        return ssh
    except Exception as e:
        logger.error(f"SSH connection to OpenWRT failed: {e}")
        return None

def block_ip_on_openwrt(ssh, ip: str, reason: str):
    """Add IP to banIP blocklist and reload firewall."""
    if ip in blocked_ips:
        return

    try:
        # banIP command to add IP to the specified list
        cmd = f"banip.sh add {ip} {BANIP_BLOCKLIST_NAME} '{reason}'"
        stdin, stdout, stderr = ssh.exec_command(cmd)
        exit_status = stdout.channel.recv_exit_status()

        if exit_status == 0:
            blocked_ips.add(ip)
            logger.info(f"✅ Blocked {ip} on OpenWRT via banIP ({reason})")
            # Optional: also trigger a firewall reload if needed
            ssh.exec_command("fw4 reload")
        else:
            error = stderr.read().decode().strip()
            logger.warning(f"Failed to block {ip}: {error}")
    except Exception as e:
        logger.error(f"Error blocking {ip} on OpenWRT: {e}")

def should_block(alert: dict) -> bool:
    """Decide if this alert warrants an automatic banIP block."""
    severity = alert.get("severity", 3)
    category = alert.get("category", "").lower()
    signature = alert.get("signature", "").lower()

    if severity > BANIP_MIN_SEVERITY:
        return False

    # Block on critical categories
    critical_keywords = ["exploit", "malware", "command and control", "denial of service", "brute force"]
    if any(kw in category for kw in critical_keywords):
        return True

    # Block on high-severity signatures containing these terms
    if severity <= 2 and any(kw in signature for kw in ["scan", "brute", "exploit", "c2", "malware"]):
        return True

    return False

def process_eve_log():
    """Main loop: watch eve.json and block malicious IPs."""
    logger.info("Starting banIP auto-blocker from Suricata alerts...")

    if not Path(EVE_LOG).exists():
        logger.warning(f"{EVE_LOG} not found. Waiting for Suricata...")
        while not Path(EVE_LOG).exists():
            time.sleep(10)

    ssh = connect_ssh()
    if not ssh:
        logger.error("Cannot start banIP updater without SSH access to OpenWRT.")
        return

    last_position = Path(EVE_LOG).stat().st_size

    while True:
        try:
            with open(EVE_LOG, "r") as f:
                f.seek(last_position)
                for line in f:
                    if line.strip():
                        try:
                            event = json.loads(line)
                            if event.get("event_type") == "alert":
                                alert = event.get("alert", {})
                                src_ip = event.get("src_ip")
                                dest_ip = event.get("dest_ip")

                                if should_block(alert):
                                    reason = f"Suricata: {alert.get('signature', 'Unknown threat')} (sev {alert.get('severity')})"
                                    if src_ip and src_ip != "N/A":
                                        block_ip_on_openwrt(ssh, src_ip, reason)
                                    if dest_ip and dest_ip != "N/A" and dest_ip != src_ip:
                                        block_ip_on_openwrt(ssh, dest_ip, reason)
                        except json.JSONDecodeError:
                            pass
                last_position = f.tell()
        except Exception as e:
            logger.error(f"Error in banIP updater loop: {e}")

        time.sleep(5)  # Check every 5 seconds

if __name__ == "__main__":
    process_eve_log()
