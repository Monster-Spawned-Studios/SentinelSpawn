<p align="center">
  <img src="grafana/MSS_LOGO.png" alt="Monster Spawned Studios Logo" width="220">
</p>

# 🛡️ Monster Spawned Studios
## Advanced Network Security Monitoring Stack

**Suricata + EveBox + Cloudflare Tunnel + Notifications (Discord / Email / NTFY) + GeoIP + Auto Log Cleanup + Prometheus/Grafana Analytics**

*Precision-crafted security tooling by Monster Spawned Studios*

This is a complete, production-grade Docker Compose setup for real-time network intrusion detection, DoS/breach alerting, beautiful dashboard, and secure remote access.

### Key Features (Updated)
- **Suricata** — Detects active breach attempts, exploits, port scans, brute force, malware C2, **Denial of Service** attacks, and more using thousands of Emerging Threats rules.
- **EveBox Dashboard** — Real-time web UI with search, filtering, alert suppression, and **GeoIP enrichment** (country/city for every alert IP).
- **Notifications** — Instant alerts via **Discord** (rich embeds), **Email** (SMTP), and **NTFY** (https://ntfy.sh by default, or your self-hosted instance via `NTFY_BASE_URL`).
  - Includes **VirusTotal links** for every source and destination IP for instant reputation checks.
- **Cloudflare Tunnel** — Zero-trust remote access to the dashboard (no ports opened on your router). Includes free DDoS protection.
- **Automatic 30-day log cleanup** — Prevents disk space issues.
- **Automatic GeoIP database updates** — Weekly downloads (with explicit user consent via `GEOIP_CONSENT=true` + MaxMind credentials).
- Fully compatible with:
  - **Ubuntu LTS** (22.04 / 24.04)
  - **WSL2** (Windows Subsystem for Linux 2)
  - **Portainer EE** (and Community Edition)
  - Any modern Linux with Docker

---

### Quick Start (Ubuntu / WSL2 / Portainer)

#### 1. Prerequisites
**All systems:**
- Docker Engine 24.0+ and Docker Compose v2.20+
- At least 4 GB RAM (8 GB+ recommended), 20 GB free disk
- A network interface to monitor (run `ip link` to find it — usually `eth0`, `enp*`, or `wlan0` in WSL)

**Ubuntu LTS (recommended native):**
```bash
# Official Docker install (best)
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
newgrp docker
```

**WSL2 (Windows):**
- Install **Docker Desktop** (WSL2 backend enabled) **or** install Docker inside WSL2.
- In WSL2 `.wslconfig` (in Windows `%USERPROFILE%\.wslconfig`):
  ```ini
  [wsl2]
  memory=8GB
  processors=4
  ```
- Restart WSL: `wsl --shutdown`
- Note: `--net=host` works but interface visibility can be limited in WSL2. Test with `curl http://testmyids.com` after setup. For best packet capture, run on native Linux or use mirrored networking (WSL 2.0.0+).

**Portainer EE:**
- Deploy this as a **Stack** in Portainer.
- The compose file is fully compatible (host network + capabilities supported).
- No extra labels needed, but you can add `com.portainer.stack=true` if desired.

#### 2. Setup Steps
```bash
git clone <your-repo> security-monitoring   # or copy files from artifacts/
cd security-monitoring

# 1. Copy environment file
cp .env.example .env

# 2. Edit .env with your values (see detailed comments in the file)
nano .env

# 3. Edit docker-compose.yml — change the Suricata interface
nano docker-compose.yml
# Look for: command: ["-c", "/etc/suricata/suricata.yaml", "-i", "eth0"]
# Change "eth0" to your actual interface name

# 4. Start everything
docker compose up -d

# 5. Update Suricata rules (first time)
docker exec suricata suricata-update -f
docker compose restart suricata

# 6. (Optional but recommended) Enable GeoIP
# Set GEOIP_CONSENT=true + your MaxMind Account ID / License Key in .env
# Then restart:
docker compose up -d geoip-updater
```

#### 3. Access the Dashboard
- **Local**: https://localhost:5636 (accept self-signed certificate)
- **Remote (recommended)**: After setting up Cloudflare Tunnel in `.env`, access via your custom domain (e.g. `https://evebox.yourdomain.com`)

First login to EveBox: Check logs `docker compose logs evebox` for the auto-generated admin password, then change it.

#### 4. Test Everything
```bash
curl http://testmyids.com
```
You should see:
- New alert in EveBox within 5–10 seconds
- Notification in Discord + Email + NTFY (with VirusTotal links)

---

### Environment Variables (.env) — Full Reference

See the `.env.example` file for all options with explanations.

**Critical ones:**
- `CLOUDFLARE_TUNNEL_TOKEN`
- `DISCORD_WEBHOOK`
- `EMAIL_SMTP`
- `NTFY_TOPIC` (e.g. `my-homelab-alerts-abc123`)
- `NTFY_BASE_URL` (leave default for https://ntfy.sh, or set your own self-hosted ntfy URL)
- `GEOIP_CONSENT=true` + MaxMind credentials (only after accepting terms)

---

### How Consent & GeoIP Works
MaxMind requires explicit acceptance of their terms for the free GeoLite2 database.

1. Read: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
2. Create free account → get Account ID + License Key
3. Set in `.env`:
   ```
   GEOIP_CONSENT=true
   MAXMIND_ACCOUNT_ID=your_id
   MAXMIND_LICENSE_KEY=your_key
   ```
4. The `geoip-updater` service will automatically download `GeoLite2-City.mmdb` and `GeoLite2-Country.mmdb` and mount them into EveBox.

If you do **not** want GeoIP, simply leave `GEOIP_CONSENT` blank or false — the service will skip downloading.

---

### Automatic Log Cleanup (30 Days)
The `log-cleaner` service runs 24/7 and deletes any files in `./logs/` older than 30 days every day. No configuration needed. Your disk will never fill up from historical alerts.

---

### Compatibility Notes & Requirements

**Ubuntu LTS (22.04/24.04)**: Fully supported out of the box. Use official Docker repo for best stability.

**WSL2**:
- Works well with Docker Desktop.
- Packet capture (`--net=host`) functions but may see fewer interfaces than native Linux.
- Recommendation: Allocate 6–8 GB RAM in WSL settings.
- If capture is unreliable, run the stack on a cheap VPS or dedicated Linux box instead.

**Portainer EE**:
- Deploy via **Stacks > Add stack** → paste or upload `docker-compose.yml`.
- All capabilities (`NET_RAW`, `NET_ADMIN`) and `network_mode: host` are supported.
- Monitor logs and restart individual services directly from Portainer UI.

**Other Requirements**:
- Modern Linux kernel with `CONFIG_PACKET` and `af_packet` module (present on all recent distros).
- No special firewall rules needed (Cloudflare Tunnel handles exposure).
- For high-traffic networks: Increase `memcap` values in `config/suricata.yaml`.

---

### Maintenance
- **Daily rules update** (recommended): Add to crontab or run manually:
  ```bash
  docker exec suricata suricata-update -q && docker compose restart suricata
  ```
- **View logs**: `docker compose logs -f notifier` (for notifications) or `docker compose logs evebox`
- **Suppress noisy alerts**: Use EveBox UI (click the minus icon next to any signature).
- **Update stack**: `docker compose pull && docker compose up -d`

---

### Troubleshooting
- **No alerts appearing**: Wrong interface in `docker-compose.yml` or Suricata not seeing traffic. Run `tcpdump -i eth0` (replace interface) to verify.
- **GeoIP not showing in EveBox**: Restart EveBox after geoip-updater finishes (`docker compose restart evebox`).
- **Notifications not sending**: Check `docker compose logs notifier` — usually missing credentials or invalid webhook/topic.
- **WSL2 capture issues**: Try interface name `eth0` inside WSL or switch to native Linux.

This setup gives you enterprise-grade network visibility with zero ongoing cost and maximum privacy. Enjoy your secure, monitored network!

For questions or customizations (e.g. adding Fail2Ban, full ELK, or IPS mode), just ask.

---

## OpenWRT Integration Guide (Recommended Router Firmware)

OpenWRT is an excellent choice for your router because it is highly customizable, supports advanced networking features, and pairs perfectly with this monitoring stack.

### Recommended Architecture (Best Performance & Security)
**Do NOT run the full Docker stack directly on a typical OpenWRT router** (resource constraints on most consumer devices).

**Best practice**:
1. Run this full Docker Compose stack on a **separate always-on Linux device** (Raspberry Pi 5, mini-PC, old laptop, or even a second OpenWRT x86 device).
2. Mirror/copy traffic from your main OpenWRT router to the monitoring host.
3. Forward Suricata `eve.json` (if you choose to run Suricata on OpenWRT) or use network mirroring.

This keeps your router fast and stable while giving you full NIDS visibility.

### Option 1: Traffic Mirroring from OpenWRT (Recommended for Most Users)

#### Step-by-Step on OpenWRT

1. **Install necessary packages** (via LuCI or SSH):
   ```bash
   opkg update
   opkg install tcpdump
   ```

2. **Create a traffic mirror script** (sends packets to your monitoring host):
   Create `/etc/mirror-traffic.sh`:
   ```bash
   #!/bin/sh
   # Mirror WAN + LAN traffic to monitoring host (change IPs)
   MONITOR_IP="192.168.1.50"   # IP of your Docker host running this stack
   MONITOR_PORT=4789           # Arbitrary UDP port

   # Mirror br-lan (LAN) and eth0.2 (WAN) — adjust interfaces
   tcpdump -i br-lan -s 0 -w - | nc -u $MONITOR_IP $MONITOR_PORT &
   tcpdump -i eth0.2 -s 0 -w - | nc -u $MONITOR_IP $MONITOR_PORT &
   ```

3. **Make it persistent**:
   ```bash
   chmod +x /etc/mirror-traffic.sh
   echo "/etc/mirror-traffic.sh" >> /etc/rc.local
   ```

4. **On the Docker host** (your monitoring machine):
   - Use `socat` or a simple UDP listener to receive the mirrored stream and feed it to Suricata (advanced) or run Suricata with a virtual interface.
   - Simpler alternative: Use a managed switch with SPAN/mirror port to the Docker host (best performance, no CPU overhead on router).

**Alternative (Easier)**: If your OpenWRT device has a spare Ethernet port, configure it as a monitor port in LuCI → Network → Switch.

### Option 2: Run Suricata Directly on OpenWRT + Forward eve.json

Many users run a lightweight Suricata on OpenWRT itself:

1. Install Suricata on OpenWRT (community packages exist or compile from source):
   ```bash
   opkg install suricata
   ```

2. Configure Suricata on OpenWRT to output to `/var/log/suricata/eve.json`.

3. **Forward logs to your Docker host** using `rsyslog` or `filebeat` (lightweight):
   - Install `rsyslog` on OpenWRT.
   - Add to `/etc/rsyslog.conf`:
     ```
     *.* @@192.168.1.50:514   # Your Docker host IP
     ```
   - On Docker host, run a simple Logstash or Filebeat container that receives syslog and writes to the shared `eve.json` volume (or use the existing notifier to watch a forwarded file).

4. Point the `notifier` and `evebox` in this stack to the forwarded log file.

### Option 3: Full Docker on OpenWRT (Advanced Users Only)

If you have a powerful OpenWRT device (x86_64, plenty of RAM, e.g., Protectli or custom build):
- Enable Docker support in OpenWRT (requires recent snapshot or specific builds).
- Copy this entire `docker-compose.yml` to the router and run it natively.
- Use the router's own interfaces directly with `network_mode: host`.

**Networking Hooks & Integrations Available in This Stack for OpenWRT**:
- **eve.json forwarding** via rsyslog/syslog-ng (real-time alerts to notifier).
- **Suricata on OpenWRT** with `af-packet` or `nfqueue` for IPS mode (can drop malicious packets at the router level).
- **Integration with OpenWRT firewall** (`/etc/config/firewall` + `nftables`): Later add IPS rules that react to Suricata alerts.
- **mwan3** (multi-WAN) + policy routing to isolate monitoring traffic.
- **Adblock + banIP** synergy: Use this stack to detect new threats and feed blocklists back to OpenWRT.
- **LuCI statistics** + this stack for combined visibility (bandwidth + security alerts).
- **Prometheus exporter** (optional future addition): Expose Suricata metrics to OpenWRT's statistics page.

### Security Best Practices When Integrating with OpenWRT
- Run the monitoring stack on a **separate VLAN** or isolated subnet.
- Use WireGuard or OpenVPN from OpenWRT to the Docker host for secure log forwarding.
- Never expose EveBox directly — always use the Cloudflare Tunnel.
- On OpenWRT, restrict outbound traffic from the monitoring VLAN.

### Quick Start Recommendation for You
1. Keep this Docker stack on a dedicated Linux box (RPi or mini-PC).
2. On OpenWRT: Set up simple `tcpdump | nc` mirroring to the Linux box (or use a cheap managed switch with mirror port).
3. Point Suricata in the compose file to the correct interface that receives the mirrored traffic.
4. Enjoy full breach/DoS detection with critical NTFY alerts on your phone.

This combination (OpenWRT router + dedicated monitoring host) is used by thousands of homelab enthusiasts and gives you professional-grade visibility without compromising router performance.

If you tell me your exact OpenWRT model and current network layout (single WAN, multiple LANs, etc.), I can give you copy-paste configuration files tailored to your setup.

---

## Additional Integrations (AdGuard Home + banIP + Portainer)

### 1. Automatic banIP Blocklist Updates from Suricata Alerts
When Suricata detects a high-severity threat (exploit, malware C2, active DoS, brute force, etc.), the `banip-updater` service automatically adds the malicious source/destination IP to your OpenWRT banIP blocklist via SSH.

**Setup:**
1. On OpenWRT: `opkg install banip && /etc/init.d/banip enable && /etc/init.d/banip start`
2. Generate SSH key: `ssh-keygen -t rsa -b 4096 -f ./ssh-keys/id_rsa_openwrt`
3. Copy public key to OpenWRT: `ssh-copy-id -i ./ssh-keys/id_rsa_openwrt.pub root@192.168.1.1`
4. Set variables in `.env` (see `.env.example`)
5. Mount the key in docker-compose (already configured)

The updater only blocks severity 1–2 alerts by default and avoids duplicate blocks.

### 2. AdGuard Home Integration + Automatic C2 Domain Blocking (New!)
AdGuard Home (excellent DNS-level ad/malware blocking, often used on OpenWRT) now has **automatic C2 domain blocking** powered by Suricata.

**How it works:**
- When Suricata flags a **Command & Control (C2)** alert (malware, botnet, trojan, backdoor, etc.), the `c2-blocker` service automatically extracts the domain and adds it to AdGuard Home’s custom filtering rules via the REST API.
- This gives you **real-time DNS-level blocking** of malicious C2 infrastructure the moment it is detected.

**Setup:**
1. Enable AdGuard Home API access (Settings → General → Enable API).
2. Set the following in `.env`:
   ```env
   ADGUARD_HOME_URL=http://192.168.1.1:3000
   ADGUARD_HOME_USERNAME=admin
   ADGUARD_HOME_PASSWORD=your_password
   C2_MIN_SEVERITY=2
   ```
3. Restart the stack — the `c2-blocker` service will start automatically.

**Additional options:**
- **Syslog forwarding** from AdGuard Home (for query log visibility in EveBox)
- Manual API polling for blocked domains

This creates a powerful closed-loop system: Suricata detects → AdGuard Home blocks at DNS level + banIP blocks at IP level.

### 3. Portainer Stack Template
A ready-to-use `portainer-stack.yml` file is included in this repository.

**How to use:**
1. In Portainer EE → Stacks → Add stack
2. Choose "Web editor" and paste the entire content of `portainer-stack.yml`
3. In the "Environment variables" section, paste your `.env` content
4. Deploy

The template includes all advanced features (NTFY priorities, VirusTotal links, automatic banIP, GeoIP, log cleanup, etc.) and proper Portainer labels.

---

## Grafana Dashboard for Suricata Metrics

A full Prometheus + Grafana stack has been added to your compose file.

**Included metrics** (via `suricata-exporter`):
- Total alerts (by severity, category, signature)
- Events by type (alert, http, dns, flow, etc.)
- Rough traffic volume

**Access**:
- Grafana: `http://your-host:3000` (default login: `admin` / `admin123` — change immediately!)
- Prometheus: `http://your-host:9090`

**Pre-loaded Dashboard**:
The enhanced dashboard **"Suricata Network Security Monitoring - Full Analytics v4"** now includes:

- Total / Critical alerts + rate stats
- Top Source & Destination IPs
- Protocol, HTTP Methods, Status Codes, DNS Query Types (Pie Charts)
- **Top 10 Domains** (HTTP hostnames)
- **Top User-Agents** table
- Top 15 Signatures
- GeoIP World Map (optional — see below)

Prometheus alerting rules are also included for high critical alert rates and C2 detection.

**Project Name**: **SentinelSpawn**  
**Browser Tab Title**: "Monster Spawned Studios - SentinelSpawn"

**Optional GeoIP World Map Toggle**:
Set `ENABLE_GEOIP_MAP=true` in `.env` to automatically enable the interactive world map panel.

**Region-based Filtering (Web UI)**:
When the GeoIP map is enabled, the dashboard includes **template variables** at the top:
- **Continent** (multi-select dropdown)
- **Country** (multi-select, dynamically populated from your data)

You can instantly filter the entire dashboard (World Map + all other panels) by specific continents or countries directly from the Grafana UI — no code changes needed.

**Footer**:
All dashboards include:  
**"Powered by Monster Spawned Studios - Copyright © 2026"**

If the year advances past 2026, simply update the footer text in the dashboard JSON (easy to do via Grafana UI).

To customize or add more panels, edit the JSON in `./grafana/provisioning/dashboards/suricata-dashboard.json` or build new ones in the UI.

---

**You now have a complete, automated security ecosystem:**
- Suricata detection → EveBox dashboard + multi-channel notifications (with dynamic NTFY priority) + VirusTotal links
- Automatic IP blocking on your OpenWRT router via banIP
- Optional AdGuard Home DNS visibility
- One-click deployment via Portainer
- 30-day log auto-cleanup + weekly GeoIP updates

This is a very powerful, low-maintenance setup tailored for OpenWRT users.

Let me know if you want me to expand any part (e.g., full AdGuard Home forwarder script, custom banIP list names, or OpenWRT-specific firewall integration).
