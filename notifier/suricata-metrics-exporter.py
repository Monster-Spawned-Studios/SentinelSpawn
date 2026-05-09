#!/usr/bin/env python3
"""
Simple Prometheus Exporter for Suricata
Exposes key metrics from eve.json in Prometheus format.

Metrics provided:
- suricata_alerts_total (by severity, category, signature)
- suricata_events_total (by event_type)
- suricata_traffic_bytes (approx from flow records)
"""

import os
import json
import time
from pathlib import Path
from collections import defaultdict
from prometheus_client import start_http_server, Counter, Gauge

EVE_LOG = "/var/log/suricata/eve.json"
METRICS_PORT = 9100

# Prometheus metrics
ALERTS_TOTAL = Counter(
    'suricata_alerts_total',
    'Total number of Suricata alerts',
    ['severity', 'category', 'signature']
)

EVENTS_TOTAL = Counter(
    'suricata_events_total',
    'Total number of Suricata events by type',
    ['event_type']
)

SRC_IP_ALERTS = Counter(
    'suricata_alerts_by_src_ip',
    'Alerts by source IP (top sources)',
    ['src_ip']
)

DEST_IP_ALERTS = Counter(
    'suricata_alerts_by_dest_ip',
    'Alerts by destination IP (top targets)',
    ['dest_ip']
)

PROTO_EVENTS = Counter(
    'suricata_events_by_proto',
    'Events by IP protocol',
    ['proto']
)

TRAFFIC_BYTES = Gauge(
    'suricata_traffic_bytes_total',
    'Approximate total traffic volume processed'
)

# New metrics for HTTP/DNS/GeoIP
HTTP_METHODS = Counter(
    'suricata_http_methods_total',
    'HTTP methods observed',
    ['method']
)

DNS_QUERY_TYPES = Counter(
    'suricata_dns_query_types_total',
    'DNS query types',
    ['qtype']
)

ALERTS_BY_COUNTRY = Counter(
    'suricata_alerts_by_country',
    'Alerts by country (GeoIP)',
    ['country']
)

# HTTP Analytics
HTTP_USER_AGENTS = Counter(
    'suricata_http_user_agents_total',
    'HTTP User-Agents observed (truncated)',
    ['user_agent']
)

HTTP_DOMAINS = Counter(
    'suricata_http_domains_total',
    'Top HTTP domains (hostnames)',
    ['domain']
)

HTTP_STATUS_CODES = Counter(
    'suricata_http_status_codes_total',
    'HTTP status codes',
    ['status']
)

last_position = 0

def process_eve_log():
    global last_position

    if not Path(EVE_LOG).exists():
        print(f"Waiting for {EVE_LOG}...")
        while not Path(EVE_LOG).exists():
            time.sleep(5)

    with open(EVE_LOG, "r") as f:
        f.seek(last_position)
        for line in f:
            if line.strip():
                try:
                    event = json.loads(line)
                    event_type = event.get("event_type", "unknown")

                    EVENTS_TOTAL.labels(event_type=event_type).inc()

                    proto = event.get("proto", "Unknown")
                    PROTO_EVENTS.labels(proto=proto).inc()

                    if event_type == "alert":
                        alert = event.get("alert", {})
                        severity = str(alert.get("severity", 3))
                        category = alert.get("category", "Unknown").replace(" ", "_")
                        signature = alert.get("signature", "Unknown")[:100]
                        src_ip = event.get("src_ip", "unknown")
                        dest_ip = event.get("dest_ip", "unknown")

                        ALERTS_TOTAL.labels(
                            severity=severity,
                            category=category,
                            signature=signature
                        ).inc()

                        SRC_IP_ALERTS.labels(src_ip=src_ip).inc()
                        DEST_IP_ALERTS.labels(dest_ip=dest_ip).inc()

                        # GeoIP country (if Suricata has it in metadata or geoip field)
                        country = "Unknown"
                        if "geoip" in event:
                            country = event["geoip"].get("country_name", "Unknown")
                        elif "alert" in event and "metadata" in event["alert"]:
                            for item in event["alert"]["metadata"]:
                                if item.startswith("country "):
                                    country = item.split(" ", 1)[1]
                                    break
                        ALERTS_BY_COUNTRY.labels(country=country).inc()

                    # Very rough traffic estimation from flow records
                    if event_type == "flow":
                        bytes_toserver = event.get("flow", {}).get("bytes_toserver", 0)
                        bytes_toclient = event.get("flow", {}).get("bytes_toclient", 0)
                        TRAFFIC_BYTES.set(TRAFFIC_BYTES._value.get() + bytes_toserver + bytes_toclient)

                    # HTTP analytics
                    if event_type == "http":
                        http_data = event.get("http", {})
                        method = http_data.get("http_method", "UNKNOWN")
                        HTTP_METHODS.labels(method=method).inc()

                        # User-Agent (truncated to avoid high cardinality)
                        ua = http_data.get("http_user_agent", "Unknown")[:80]
                        HTTP_USER_AGENTS.labels(user_agent=ua).inc()

                        # Domain (hostname)
                        domain = http_data.get("hostname") or http_data.get("http_host", "Unknown")
                        HTTP_DOMAINS.labels(domain=domain).inc()

                        # Status code
                        status = str(http_data.get("status", "0"))
                        HTTP_STATUS_CODES.labels(status=status).inc()

                    # DNS analytics
                    if event_type == "dns":
                        qtype = event.get("dns", {}).get("rrtype", "UNKNOWN")
                        DNS_QUERY_TYPES.labels(qtype=qtype).inc()

                except Exception:
                    pass  # Skip bad lines

        last_position = f.tell()

def main():
    print(f"Starting Suricata Prometheus exporter on port {METRICS_PORT}...")
    start_http_server(METRICS_PORT)

    while True:
        try:
            process_eve_log()
        except Exception as e:
            print(f"Error processing eve.json: {e}")
        time.sleep(10)  # Update every 10 seconds

if __name__ == "__main__":
    main()
