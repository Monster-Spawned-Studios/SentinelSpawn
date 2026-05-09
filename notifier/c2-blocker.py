#!/usr/bin/env python3
"""
Auto C2 Domain Blocker for AdGuard Home
Watches Suricata eve.json for Command & Control (C2) alerts and automatically adds the malicious domains to AdGuard Home's custom filtering rules.

This gives you automatic DNS-level blocking of malware C2 domains as soon as Suricata detects them.

Requirements:
- requests library
- AdGuard Home with API access enabled (default on port 3000)

Environment variables:
- ADGUARD_HOME_URL=http://192.168.1.1:3000
- ADGUARD_HOME_USERNAME=admin
- ADGUARD_HOME_PASSWORD=your_password
- C2_MIN_SEVERITY=2   # Only block C2 alerts with severity <= this

Security: Use a dedicated AdGuard Home user with limited permissions if possible.
"""

import os
import json
import time
import logging
import requests
from pathlib import Path
from datetime import datetime

EVE_LOG = "/var/log/suricata/eve.json"

ADGUARD_HOME_URL = os.getenv("ADGUARD_HOME_URL", "").rstrip("/")
ADGUARD_HOME_USERNAME = os.getenv("ADGUARD_HOME_USERNAME", "")
ADGUARD_HOME_PASSWORD = os.getenv("ADGUARD_HOME_PASSWORD", "")
C2_MIN_SEVERITY = int(os.getenv("C2_MIN_SEVERITY", "2"))

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

blocked_domains = set()  # Avoid duplicate API calls

def get_adguard_session():
    """Create an authenticated session for AdGuard Home API."""
    if not ADGUARD_HOME_URL or not ADGUARD_HOME_USERNAME or not ADGUARD_HOME_PASSWORD:
        logger.error("AdGuard Home credentials not configured in .env — C2 blocking disabled.")
        return None

    session = requests.Session()
    session.auth = (ADGUARD_HOME_USERNAME, ADGUARD_HOME_PASSWORD)
    # Test connection
    try:
        r = session.get(f"{ADGUARD_HOME_URL}/control/status", timeout=5)
        if r.status_code == 200:
            logger.info("Successfully connected to AdGuard Home API")
            return session
        else:
            logger.error(f"AdGuard Home auth failed: {r.status_code}")
            return None
    except Exception as e:
        logger.error(f"Cannot connect to AdGuard Home: {e}")
        return None

def is_c2_alert(alert: dict) -> bool:
    """Check if this alert is a C2 / malware command and control event."""
    if alert.get("severity", 3) > C2_MIN_SEVERITY:
        return False

    category = alert.get("category", "").lower()
    signature = alert.get("signature", "").lower()

    c2_keywords = ["command and control", "c2", "malware", "trojan", "botnet", "backdoor"]
    return any(kw in category or kw in signature for kw in c2_keywords)

def extract_domain(event: dict) -> str | None:
    """Try to extract the C2 domain from various Suricata event fields."""
    # From HTTP event (most common for C2)
    if "http" in event:
        host = event["http"].get("hostname") or event["http"].get("http_host")
        if host:
            return host.lower().strip()

    # From DNS event
    if "dns" in event:
        rrname = event["dns"].get("rrname")
        if rrname:
            return rrname.lower().strip()

    # Fallback: try to parse from alert metadata or signature (less reliable)
    alert = event.get("alert", {})
    if "metadata" in alert:
        for item in alert["metadata"]:
            if item.startswith("domain "):
                return item.split(" ", 1)[1].lower().strip()

    return None

def add_domain_to_adguard(session, domain: str, reason: str):
    """Add domain to AdGuard Home custom filtering rules using the API."""
    if domain in blocked_domains:
        return

    try:
        # Get current rules
        r = session.get(f"{ADGUARD_HOME_URL}/control/filtering/status", timeout=10)
        if r.status_code != 200:
            logger.warning(f"Failed to fetch current rules: {r.status_code}")
            return

        current_rules = r.json().get("user_rules", [])

        # Add new blocking rule (AdGuard syntax)
        new_rule = f"||{domain}^"
        if new_rule in current_rules:
            blocked_domains.add(domain)
            return

        current_rules.append(new_rule)

        # Update rules via API
        payload = {"user_rules": current_rules}
        r = session.post(
            f"{ADGUARD_HOME_URL}/control/filtering/set_rules",
            json=payload,
            timeout=10
        )

        if r.status_code == 200:
            blocked_domains.add(domain)
            logger.info(f"✅ Blocked C2 domain in AdGuard Home: {domain} ({reason})")
        else:
            logger.warning(f"Failed to add {domain} to AdGuard Home: {r.status_code} - {r.text}")

    except Exception as e:
        logger.error(f"Error adding {domain} to AdGuard Home: {e}")

def process_eve_log():
    """Main watcher loop."""
    logger.info("Starting C2 domain auto-blocker for AdGuard Home...")

    if not Path(EVE_LOG).exists():
        logger.warning(f"{EVE_LOG} not found. Waiting for Suricata...")
        while not Path(EVE_LOG).exists():
            time.sleep(10)

    session = get_adguard_session()
    if not session:
        logger.error("C2 blocker disabled — no valid AdGuard Home connection.")
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
                                if is_c2_alert(alert):
                                    domain = extract_domain(event)
                                    if domain:
                                        reason = alert.get("signature", "C2 / Malware")
                                        add_domain_to_adguard(session, domain, reason)
                        except json.JSONDecodeError:
                            pass
                last_position = f.tell()
        except Exception as e:
            logger.error(f"Error in C2 blocker loop: {e}")

        time.sleep(5)

if __name__ == "__main__":
    process_eve_log()
