#!/usr/bin/env python3
"""
Suricata Alert Notifier
Watches eve.json for new alerts and sends notifications via Apprise to Discord and/or Email.
Customizable filters for severity, categories (e.g., DoS, exploit, brute force), to reduce noise.
Run inside the 'notifier' container (see docker-compose.yml).

Requirements (installed automatically in container):
- apprise
- watchdog (for efficient file watching)

Configuration via environment variables (in .env):
- DISCORD_WEBHOOK=discord://webhook_id/token   (or full URL)
- EMAIL_SMTP=mailto://user:pass@smtp.example.com:587?to=alerts@yourdomain.com&name=NetworkSecurity
  (Supports Gmail, Outlook, custom SMTP, etc. Use app passwords for Gmail.)
- Optional: NOTIFY_SEVERITY_MAX=2  (1=high/critical, 2=medium; notify only <= this)
- Optional: NOTIFY_CATEGORIES="Denial of Service,Exploit,Brute Force,Malware C2" (comma-separated; notify only these or all if empty)

Test: Trigger with `curl http://testmyids.com` (should generate alert and notification).
"""

import os
import json
import time
import logging
from datetime import datetime
from pathlib import Path

import apprise
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Configuration from environment
EVE_LOG = "/var/log/suricata/eve.json"
DISCORD_WEBHOOK = os.getenv("DISCORD_WEBHOOK", "")
EMAIL_TARGET = os.getenv("EMAIL_SMTP", "")
NTFY_TOPIC = os.getenv("NTFY_TOPIC", "")
NTFY_BASE_URL = os.getenv("NTFY_BASE_URL", "https://ntfy.sh")
NOTIFY_SEVERITY_MAX = int(os.getenv("NOTIFY_SEVERITY_MAX", "3"))  # 1=most severe
NOTIFY_CATEGORIES = [c.strip() for c in os.getenv("NOTIFY_CATEGORIES", "").split(",") if c.strip()]

# Apprise setup
apobj = apprise.Apprise()
if DISCORD_WEBHOOK:
    apobj.add(DISCORD_WEBHOOK)
if EMAIL_TARGET:
    apobj.add(EMAIL_TARGET)
if NTFY_TOPIC:
    # Default to https://ntfy.sh unless NTFY_BASE_URL is set (user-specified self-hosted instance)
    base = NTFY_BASE_URL.replace("https://", "").replace("http://", "").rstrip("/")
    ntfy_url = f"ntfys://{base}/{NTFY_TOPIC}"
    apobj.add(ntfy_url)

if not apobj:
    logging.error("No notification targets configured! Set at least one of DISCORD_WEBHOOK, EMAIL_SMTP, or NTFY_TOPIC in .env")
    exit(1)

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

def should_notify(alert_event: dict) -> bool:
    """Filter logic: Notify on interesting security events (breach attempts, DoS, etc.)."""
    if alert_event.get("event_type") != "alert":
        return False

    alert = alert_event.get("alert", {})
    severity = alert.get("severity", 3)  # Suricata: lower = higher severity typically (1=critical)
    category = alert.get("category", "").lower()
    signature = alert.get("signature", "").lower()

    # Severity filter (notify if severity <= threshold, e.g. 1 or 2)
    if severity > NOTIFY_SEVERITY_MAX:
        return False

    # Category filter (if specified, only those; else all alerts)
    if NOTIFY_CATEGORIES:
        if not any(cat.lower() in category for cat in NOTIFY_CATEGORIES):
            # Also check signature keywords for DoS/brute/exploit
            keywords = ["dos", "denial", "brute", "exploit", "scan", "malware", "c2", "command and control"]
            if not any(kw in signature for kw in keywords):
                return False

    return True


def get_ntfy_priority_and_tags(alert: dict) -> tuple[int, str]:
    """Map Suricata severity + category to NTFY priority (1=min ... 5=urgent) and emoji tags.
    Critical breach/DoS/exploit/malware C2 → priority 5 (urgent + sound/vibration)
    Medium brute force/web attacks → priority 3 (default warning)
    Low/info (scans, pings) → priority 1 (silent/minimal)
    """
    severity = alert.get("severity", 3)
    category = alert.get("category", "").lower()
    signature = alert.get("signature", "").lower()

    # Critical events (actual breach attempts, active DoS, high-impact exploits)
    if severity == 1 or any(kw in category for kw in ["denial of service", "exploit", "malware", "command and control"]):
        return 5, "skull,rotating_light"

    # Medium severity or suspicious activity
    if severity == 2 or any(kw in category for kw in ["brute force", "web application attack", "attempted"]):
        return 3, "warning"

    # Low / informational (generic scans, pings, etc.)
    return 1, "information_source"


def format_notification(event: dict) -> tuple[str, str]:
    """Create rich title and body for Discord (supports embeds + links), Email, and NTFY.
    Includes VirusTotal links for quick IP reputation checks.
    """
    alert = event.get("alert", {})
    src_ip = event.get("src_ip", "N/A")
    dest_ip = event.get("dest_ip", "N/A")
    proto = event.get("proto", "N/A")
    timestamp = event.get("timestamp", datetime.now().isoformat())

    title = f"🚨 Network Alert: {alert.get('signature', 'Unknown Threat')}"

    # VirusTotal links (highly useful for quick threat intel on source/destination IPs)
    vt_src = f"https://www.virustotal.com/gui/ip-address/{src_ip}" if src_ip != "N/A" else ""
    vt_dest = f"https://www.virustotal.com/gui/ip-address/{dest_ip}" if dest_ip != "N/A" else ""

    body = (
        f"**Time:** {timestamp}\n"
        f"**Source:** {src_ip} → **Dest:** {dest_ip} ({proto})\n"
        f"**Category:** {alert.get('category', 'N/A')}\n"
        f"**Severity:** {alert.get('severity', 'N/A')}\n"
        f"**Signature ID:** {alert.get('signature_id', 'N/A')}\n\n"
        f"**Details:** {alert.get('signature', 'No details')}\n\n"
        f"**VirusTotal Checks:**\n"
        f"  • Source IP: {vt_src}\n"
        f"  • Dest IP: {vt_dest}\n\n"
        f"View full details & manage alerts in EveBox: https://your-evebox-domain.com:5636\n"
        f"(Replace with your Cloudflare domain)"
    )
    return title, body

class EveLogHandler(FileSystemEventHandler):
    def __init__(self):
        self.last_position = 0
        if Path(EVE_LOG).exists():
            self.last_position = Path(EVE_LOG).stat().st_size

    def on_modified(self, event):
        if event.src_path != EVE_LOG:
            return
        try:
            with open(EVE_LOG, "r") as f:
                f.seek(self.last_position)
                for line in f:
                    if line.strip():
                        try:
                            event_data = json.loads(line)
                            if should_notify(event_data):
                                title, body = format_notification(event_data)
                                logger.info(f"Sending notification: {title}")

                                # Send to Discord + Email via main apobj
                                apobj.notify(title=title, body=body)

                                # Special handling for NTFY with dynamic priority based on severity/category
                                if NTFY_TOPIC:
                                    priority, tags = get_ntfy_priority_and_tags(event_data.get("alert", {}))
                                    base = NTFY_BASE_URL.replace("https://", "").replace("http://", "").rstrip("/")
                                    ntfy_url = f"ntfys://{base}/{NTFY_TOPIC}?priority={priority}&tags={tags}"
                                    ntfy_apobj = apprise.Apprise()
                                    ntfy_apobj.add(ntfy_url)
                                    ntfy_apobj.notify(title=title, body=body)
                        except json.JSONDecodeError:
                            pass  # Skip malformed lines
                self.last_position = f.tell()
        except Exception as e:
            logger.error(f"Error processing eve.json: {e}")

def main():
    logger.info("Starting Suricata Alert Notifier...")
    logger.info(f"Monitoring: {EVE_LOG}")
    logger.info(f"Targets: Discord={'Yes' if DISCORD_WEBHOOK else 'No'}, Email={'Yes' if EMAIL_TARGET else 'No'}, NTFY={'Yes' if NTFY_TOPIC else 'No'} (base: {NTFY_BASE_URL})")
    logger.info(f"Filters: Severity <= {NOTIFY_SEVERITY_MAX}, Categories: {NOTIFY_CATEGORIES or 'All'}")

    if not Path(EVE_LOG).exists():
        logger.warning(f"{EVE_LOG} not found yet. Waiting for Suricata to start logging...")
        while not Path(EVE_LOG).exists():
            time.sleep(5)

    event_handler = EveLogHandler()
    observer = Observer()
    observer.schedule(event_handler, path=str(Path(EVE_LOG).parent), recursive=False)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == "__main__":
    main()
