"""
trust.py — NetGuardAI Trusted IP & MAC Database

Features:
  1. CDN/platform detection  → never flag YouTube/Google/Netflix flows
  2. MAC+IP tracking         → handle dynamic DHCP IPs correctly
  3. Trusted IP allowlist    → valid users never get blocked
"""

import json
import os
import threading
import time

DB_FILE = "trustedip.json"
lock    = threading.Lock()

# ── Load / save database ───────────────────────────────────────────────────────
def _load_db():
    if not os.path.exists(DB_FILE):
        return {"trusted_ips": [], "trusted_mac_ip_pairs": [], "known_cdns": []}
    with open(DB_FILE, "r") as f:
        return json.load(f)

def _save_db(db):
    with open(DB_FILE, "w") as f:
        json.dump(db, f, indent=2)

# ── In-memory cache (refreshes every 60 s so live edits take effect) ─────────
_cache      = _load_db()
_cache_time = time.time()
CACHE_TTL   = 60

def _get_db():
    global _cache, _cache_time
    if time.time() - _cache_time > CACHE_TTL:
        _cache      = _load_db()
        _cache_time = time.time()
    return _cache


# ── MAC ↔ IP history ──────────────────────────────────────────────────────────
# Populated by capture.py when ARP packets are observed.
MAC_IP_TABLE = {}   # ip  → {"mac": ..., "first_seen": ..., "last_seen": ...}
IP_MAC_TABLE = {}   # mac → {"ip":  ..., "first_seen": ..., "last_seen": ...}

def record_arp(ip, mac):
    """Called from handle_packet() whenever an ARP packet is seen."""
    now = time.time()
    with lock:
        existing_mac = MAC_IP_TABLE.get(ip, {}).get("mac")

        if existing_mac and existing_mac != mac:
            # IP reassigned to a different device by DHCP — clear old block state
            print(f"[DHCP CHANGE] {ip}  old_mac={existing_mac}  new_mac={mac} "
                  f"→ IP reassigned, clearing block history")
            _notify_ip_changed(ip, existing_mac, mac)

        MAC_IP_TABLE[ip]  = {"mac": mac, "first_seen": now, "last_seen": now}
        IP_MAC_TABLE[mac] = {"ip":  ip,  "first_seen": now, "last_seen": now}

def _notify_ip_changed(ip, old_mac, new_mac):
    """Clear firewall block state when DHCP reassigns an IP to a new device."""
    try:
        import firewall as fw
        with fw.lock:
            if ip in fw.IP_STATE:
                fw.IP_STATE[ip]["score"]      = 0
                fw.IP_STATE[ip]["blocked"]    = False
                fw.IP_STATE[ip]["blocked_at"] = None
                print(f"[TRUST] Cleared block state for {ip} after DHCP reassignment")
    except Exception as e:
        print(f"[TRUST] Could not clear IP state: {e}")

def get_mac_for_ip(ip):
    with lock:
        return MAC_IP_TABLE.get(ip, {}).get("mac", "unknown")


# ── Is this IP trusted / allowlisted? ─────────────────────────────────────────
def is_trusted_ip(ip):
    """
    Returns (True, reason_string) if the IP is in the trusted database.
    Returns (False, None) otherwise.
    """
    db = _get_db()

    # Direct IP match
    if ip in db.get("trusted_ips", []):
        return True, "trusted_ips list"

    # MAC+IP pair match (survives DHCP changes as long as MAC is stable)
    mac = get_mac_for_ip(ip)
    if mac != "unknown":
        for entry in db.get("trusted_mac_ip_pairs", []):
            if entry.get("mac") == mac and entry.get("ip") == ip:
                return True, f"trusted device: {entry.get('label', mac)}"

    return False, None


# ── Is the DESTINATION a known CDN / streaming platform? ─────────────────────
def is_cdn_destination(dst_ip):
    """
    Returns (True, platform_name) if dst_ip starts with a known CDN prefix.
    Prevents heavy YouTube/Google/Netflix traffic being flagged as exfiltration.
    """
    db = _get_db()
    for prefix in db.get("known_cdns", []):
        if dst_ip.startswith(prefix):
            return True, _cdn_label(prefix)
    return False, None

def _cdn_label(prefix):
    labels = {
        "142.250.": "Google",    "172.217.": "Google",
        "216.58.":  "Google",    "31.13.":   "Facebook",
        "157.240.": "Facebook",  "23.246.":  "Netflix",
        "54.239.":  "Amazon",    "13.107.":  "Microsoft",
        "204.79.":  "Microsoft", "151.101.": "Fastly",
        "104.16.":  "Cloudflare","104.17.":  "Cloudflare",
    }
    return labels.get(prefix, "CDN")


# ── Add / remove trusted IPs at runtime ───────────────────────────────────────
def add_trusted_ip(ip, label="manual"):
    global _cache, _cache_time
    with lock:
        db = _load_db()
        if ip not in db["trusted_ips"]:
            db["trusted_ips"].append(ip)
            _save_db(db)
            _cache      = db           # ← update cache immediately
            _cache_time = time.time()  # ← so next read sees the change
            print(f"[TRUST] Added trusted IP: {ip} ({label})")
            return True
        return False

def remove_trusted_ip(ip):
    global _cache, _cache_time
    with lock:
        db = _load_db()
        if ip in db["trusted_ips"]:
            db["trusted_ips"].remove(ip)
            _save_db(db)
            _cache      = db           # ← update cache immediately
            _cache_time = time.time()  # ← so next read sees the change
            print(f"[TRUST] Removed trusted IP: {ip}")
            return True
        return False

def get_trusted_ips():
    return _get_db().get("trusted_ips", [])

def get_mac_ip_table():
    with lock:
        return dict(MAC_IP_TABLE)