"""
capture.py — NetGuardAI  Real-Time IDS  (main entry point)

Fixes in this version
──────────────────────────────────────────────────────────────────────────────
 1. Public-IP HIGH tagging bug FIXED — public IPs are never tagged HIGH
    just for being public; all rule-gates now check direction (inbound only).
 2. Exfil rule scope FIXED — only private→public flows qualify; a CDN
    pushing data to you is NOT exfiltration.
 3. CDN check moved BEFORE all rules so it can never be bypassed.
 4. ML false-positive spam FIXED — per-IP 60-second cooldown.
 5. Behavioral anomaly severity lowered to MEDIUM (was HIGH).
 6. GeoIP & ASN rules now only fire on inbound flows (public→private).
 7. Honeypot severity changed from CRITICAL to HIGH for single-hit events.
 8. Network discovery (ARP sweep) added — /api/scan, /api/ping.
 9. Passive ARP populates discovered_hosts table in real-time.
10. Auto-gateway skip: any x.x.x.1 or x.x.x.254 is always skipped.
"""

from scapy.all import sniff, IP, TCP, UDP, ARP, Ether, get_if_list, conf, srp
from firewall import observe, tick_unblock
from trust import (is_trusted_ip, is_cdn_destination,
                   record_arp, get_mac_for_ip)
import time
import joblib
import pandas as pd
import csv
import os
import threading
import ipaddress
import subprocess
import platform
import socket

from server import start_server, add_alert, add_packet, metrics
from baseline import update_baseline, is_behaviorally_anomalous

model = joblib.load("netguard_model.pkl")
from scan import get_discovered_hosts, ping_single, start_scanner
import server
server._get_discovered_hosts = get_discovered_hosts
server._ping_single          = ping_single
start_scanner()
# ===== GeoIP SETUP ==========================================================
GEOIP_ENABLED = False
ASN_ENABLED   = False
try:
    import geoip2.database
    if os.path.exists("GeoLite2-Country.mmdb"):
        _geo_reader   = geoip2.database.Reader("GeoLite2-Country.mmdb")
        GEOIP_ENABLED = True
        print("[GeoIP] GeoLite2-Country database loaded OK")
    else:
        print("[GeoIP] GeoLite2-Country.mmdb not found — download from MaxMind")
    if os.path.exists("GeoLite2-ASN.mmdb"):
        _asn_reader = geoip2.database.Reader("GeoLite2-ASN.mmdb")
        ASN_ENABLED = True
        print("[GeoIP] GeoLite2-ASN database loaded OK")
except ImportError:
    print("[GeoIP] geoip2 not installed — run: pip install geoip2")

HIGH_RISK_COUNTRIES   = {"KP", "IR", "RU", "CN", "SY"}
HIGH_RISK_ASN_KEYWORDS = {
    "digitalocean","linode","vultr","ovh","hetzner",
    "choopa","frantech","m247","mullvad","expressvpn",
    "nordvpn","tor exit","privacyfirst","quadranet"
}

def get_country(ip):
    if not GEOIP_ENABLED: return "UNKNOWN"
    try: return _geo_reader.country(ip).country.iso_code or "UNKNOWN"
    except: return "UNKNOWN"

def get_asn_info(ip):
    if not ASN_ENABLED: return None, None
    try:
        r = _asn_reader.asn(ip)
        return r.autonomous_system_number, r.autonomous_system_organization or ""
    except: return None, None

def is_high_risk_asn(org):
    if not org: return False
    return any(kw in org.lower() for kw in HIGH_RISK_ASN_KEYWORDS)

# ===== INTERFACE ============================================================
def find_wifi_interface():
    try:
        iface = conf.iface
        print(f"[AUTO] Using interface: {iface}")
        return str(iface)
    except: pass
    interfaces = get_if_list()
    for i, iface in enumerate(interfaces): print(f"  [{i}] {iface}")
    return interfaces[0]

INTERFACE      = find_wifi_interface()
FLOW_TIMEOUT   = 10
CHECK_INTERVAL = 2
STARTUP_TIME   = time.time()

STATIC_SKIP = {
    "192.168.1.1","192.168.0.1","192.168.1.254",
    "10.0.0.1","10.0.0.138",
    "192.168.21.1","192.168.21.2","192.168.21.248",
    "0.0.0.0","255.255.255.255"
}

def should_skip(ip):
    if ip in STATIC_SKIP: return True
    if ip.startswith("127.") or ip.startswith("169.254."): return True
    if ip.startswith("224.") or ip.startswith("239.") or ip.startswith("255."): return True
    last = ip.rsplit(".",1)[-1]
    if last in ("1","254"): return True   # auto-skip gateway addresses
    return False

def is_private(ip):
    try: return ipaddress.ip_address(ip).is_private
    except: return False

# ===== NETWORK DISCOVERY ====================================================
discovered_hosts = {}   # ip -> {mac, hostname, last_seen, ping_ms}
discovery_lock   = threading.Lock()

def _get_local_subnet():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        parts = local_ip.rsplit(".",1)
        return f"{parts[0]}.0/24"
    except: return "192.168.1.0/24"

def _arp_sweep(subnet):
    print(f"[SCAN] ARP sweep on {subnet} ...")
    try:
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
        answered, _ = srp(pkt, timeout=3, verbose=False, iface=INTERFACE)
        now = time.time()
        with discovery_lock:
            for _, rcvd in answered:
                ip  = rcvd[ARP].psrc
                mac = rcvd[ARP].hwsrc
                if ip and mac:
                    try: hostname = socket.gethostbyaddr(ip)[0]
                    except: hostname = ""
                    existing = discovered_hosts.get(ip, {})
                    discovered_hosts[ip] = {
                        "mac":      mac,
                        "hostname": hostname or existing.get("hostname",""),
                        "last_seen": now,
                        "ping_ms":  existing.get("ping_ms")
                    }
                    record_arp(ip, mac)
        print(f"[SCAN] Done — {len(answered)} host(s)")
    except Exception as e:
        print(f"[SCAN] Error: {e}")

def _ping_host(ip):
    try:
        param  = "-n" if platform.system().lower() == "windows" else "-c"
        result = subprocess.run(
            ["ping", param, "1", "-W", "1", ip],
            capture_output=True, text=True, timeout=3
        )
        out = result.stdout
        for token in out.split():
            for prefix in ("time=","time<"):
                if token.startswith(prefix):
                    try: return float(token.replace(prefix,"").replace("ms",""))
                    except: pass
        if "Average" in out:
            try: return float(out.split("=")[-1].strip().replace("ms",""))
            except: pass
        if result.returncode == 0: return 0.0
        return None
    except: return None

def _ping_all_discovered():
    with discovery_lock: ips = list(discovered_hosts.keys())
    for ip in ips:
        ms = _ping_host(ip)
        with discovery_lock:
            if ip in discovered_hosts: discovered_hosts[ip]["ping_ms"] = ms

def _discovery_loop():
    subnet = _get_local_subnet()
    while True:
        _arp_sweep(subnet)
        _ping_all_discovered()
        time.sleep(300)

def get_discovered_hosts():
    with discovery_lock: return dict(discovered_hosts)

def ping_single(ip):
    ms = _ping_host(ip)
    with discovery_lock:
        if ip in discovered_hosts: discovered_hosts[ip]["ping_ms"] = ms
    return {"ip": ip, "ping_ms": ms, "reachable": ms is not None}

# ===== THRESHOLDS ===========================================================
FLOOD_PKT_THRESHOLD = 2000
EXFIL_BPS_THRESHOLD = 5_000_000
SSH_PKT_THRESHOLD   = 40
ML_CONF_THRESHOLD   = 0.85
ML_MIN_PKT_COUNT    = 8
ML_MIN_BPS          = 1_000
ML_STARTUP_GRACE    = 120
ML_COOLDOWN_WINDOW  = 60      # seconds between ML alerts for same IP
_ml_last_alert      = {}
_ml_lock            = threading.Lock()

BENIGN_PORTS   = {53,67,68,80,123,443,853,5353,8080,8443}
HONEYPOT_PORTS = {23,3389,1433,5900,4444,31337}
TRUSTED_PORTS  = {443,8443}

NORMAL_FLOWS_FILE = "normal_flows_buffer.csv"
NORMAL_FLOWS_LOCK = threading.Lock()
FEATURE_COLS      = ["src_port","dst_port","protocol","duration",
                     "pkt_count","total_bytes","mean_pkt_len",
                     "max_pkt_len","mean_iat","bytes_per_sec"]

def _save_normal_flow(features):
    row = dict(zip(FEATURE_COLS, features)); row["label"] = 0
    with NORMAL_FLOWS_LOCK:
        exists = os.path.exists(NORMAL_FLOWS_FILE)
        with open(NORMAL_FLOWS_FILE,"a",newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(row.keys()))
            if not exists: w.writeheader()
            w.writerow(row)

def _ml_on_cooldown(ip):
    with _ml_lock: return time.time() - _ml_last_alert.get(ip,0) < ML_COOLDOWN_WINDOW

def _ml_mark_alerted(ip):
    with _ml_lock: _ml_last_alert[ip] = time.time()

# ===== LATERAL MOVEMENT =====================================================
LATERAL_MAP       = {}
lateral_lock      = threading.Lock()
LATERAL_THRESHOLD = 25
LATERAL_WINDOW    = 300

def check_lateral_movement(src_ip, dst_ip):
    if not is_private(dst_ip): return None
    now = time.time()
    with lateral_lock:
        e = LATERAL_MAP.setdefault(src_ip, {"ips":set(),"window_start":now})
        if now - e["window_start"] > LATERAL_WINDOW:
            e["ips"] = set(); e["window_start"] = now
        e["ips"].add(dst_ip)
        count = len(e["ips"])
    if count > LATERAL_THRESHOLD:
        return f"Contacted {count} unique internal IPs within {LATERAL_WINDOW}s"
    return None

# ===== SOC REPORT ===========================================================
def generate_soc_report(flow, features, attack_type, severity,
                        mac="unknown", country="UNKNOWN",
                        asn_num=None, asn_org=None, extra=""):
    src, dst, sport, dport, proto = flow
    asn_line = ""
    if asn_num or asn_org:
        risk = " HIGH-RISK ASN" if is_high_risk_asn(asn_org) else ""
        asn_line = f"  ASN          : AS{asn_num} {asn_org}{risk}\n"
    return (
        f"=== SOC ANALYSIS REPORT ===\n\n"
        f"ATTACK TYPE : {attack_type}\nSEVERITY    : {severity}\n"
        f"COUNTRY     : {country}\n{asn_line}\n"
        f"SOURCE      : {src}:{sport}  (MAC: {mac})\n"
        f"DESTINATION : {dst}:{dport}\n\nINDICATORS\n"
        f"  Packet Count : {features[4]}\n"
        f"  Duration     : {features[3]:.2f}s\n"
        f"  Bytes/sec    : {features[9]:.2f}\n"
        f"  Total Bytes  : {features[5]}\n\n"
        + (f"DETAIL: {extra}\n" if extra else "")
    )

def extract_features(key, pkts):
    times = [p["time"] for p in pkts]; sizes = [p["size"] for p in pkts]
    duration     = max(times)-min(times) if len(times)>1 else 0
    pkt_count    = len(pkts)
    total_bytes  = sum(sizes)
    mean_pkt_len = total_bytes/pkt_count
    max_pkt_len  = max(sizes)
    iats         = [t2-t1 for t1,t2 in zip(times[:-1],times[1:])]
    mean_iat     = sum(iats)/len(iats) if iats else 0
    bps          = total_bytes/duration if duration>0 else 0
    src_ip,dst_ip,src_port,dst_port,protocol = key
    return [src_port,dst_port,protocol,duration,pkt_count,
            total_bytes,mean_pkt_len,max_pkt_len,mean_iat,bps]

# ===== PACKET HANDLER =======================================================
flows      = {}
flows_lock = threading.Lock()

def handle_packet(pkt):
    if ARP in pkt:
        arp_ip  = pkt[ARP].psrc
        arp_mac = pkt[ARP].hwsrc
        if arp_ip and arp_mac and arp_ip != "0.0.0.0":
            record_arp(arp_ip, arp_mac)
            now = time.time()
            with discovery_lock:
                if arp_ip not in discovered_hosts:
                    discovered_hosts[arp_ip] = {"mac":arp_mac,"hostname":"","last_seen":now,"ping_ms":None}
                else:
                    discovered_hosts[arp_ip]["mac"]       = arp_mac
                    discovered_hosts[arp_ip]["last_seen"] = now
        return

    if IP not in pkt: return
    now   = time.time()
    src   = pkt[IP].src
    dst   = pkt[IP].dst
    proto = pkt[IP].proto
    sport, dport = 0, 0
    if TCP in pkt:   sport,dport = pkt[TCP].sport,pkt[TCP].dport; proto_name="TCP"
    elif UDP in pkt: sport,dport = pkt[UDP].sport,pkt[UDP].dport; proto_name="UDP"
    else: proto_name=str(proto)

    # HONEYPOT — HIGH (not CRITICAL) so single accidental hit never insta-blocks
    if dport in HONEYPOT_PORTS and not should_skip(src):
        trusted,_ = is_trusted_ip(src)
        if not trusted:
            is_cdn,_ = is_cdn_destination(dst)
            if not is_cdn:
                mac=get_mac_for_ip(src); country=get_country(src)
                add_alert({"type":"Honeypot Triggered","severity":"HIGH",
                           "src":src,"dst":dst,"port":dport,
                           "mac":mac,"country":country,
                           "time":time.strftime("%H:%M:%S"),
                           "report":f"Decoy port {dport} hit from {src} (MAC:{mac}) [{country}]",
                           "blocked":False,"is_private_ip":is_private(src)})
                observe(src,"HIGH",f"Honeypot:{dport}")
                print(f"[HONEYPOT] {src} -> port {dport} mac={mac}")

    key = (src,dst,sport,dport,proto)
    with flows_lock:
        if key not in flows: flows[key]={"packets":[],"last_seen":now}
        flows[key]["packets"].append({"time":now,"size":len(pkt)})
        flows[key]["last_seen"]=now

    metrics["packets"]+=1
    add_packet({"time":time.strftime("%H:%M:%S"),"src":src,"dst":dst,
                "proto":proto_name,"info":f"{sport} -> {dport}"})

# ===== FLOW PROCESSING ======================================================
def process_flows():
    now = time.time()
    with flows_lock:
        completed = [k for k,v in flows.items() if now-v["last_seen"]>FLOW_TIMEOUT]
        snapshot  = {k:flows.pop(k) for k in completed}
    uptime = now - STARTUP_TIME

    for key, flow in snapshot.items():
        src_ip=key[0]; dst_ip=key[1]; dst_port=key[3]
        if should_skip(src_ip): continue
        trusted,reason = is_trusted_ip(src_ip)
        if trusted:
            print(f"[TRUSTED] {src_ip} ({reason})")
            continue

        # CDN check FIRST — before ANY threshold check
        is_cdn,cdn_name = is_cdn_destination(dst_ip)
        if is_cdn:
            print(f"[CDN] {src_ip} -> {dst_ip} ({cdn_name}) skipped")
            continue

        if dst_port in TRUSTED_PORTS and is_private(src_ip): continue

        features = extract_features(key, flow["packets"])
        df       = pd.DataFrame([features], columns=FEATURE_COLS)
        pred     = model.predict(df)[0]
        conf     = model.predict_proba(df)[0][1]

        pkt_count=features[4]; bytes_sec=features[9]; duration=features[3]
        mac=get_mac_for_ip(src_ip); country=get_country(src_ip)
        asn_num,asn_org = get_asn_info(src_ip) if not is_private(src_ip) else (None,None)

        update_baseline(src_ip, bytes_sec, pkt_count)

        attack_type=None; severity=None; extra_detail=""

        # Rule 1: Flood
        if pkt_count > FLOOD_PKT_THRESHOLD:
            attack_type="Packet Flood"; severity="HIGH"

        # Rule 2: Exfiltration — ONLY private->public direction
        elif (bytes_sec > EXFIL_BPS_THRESHOLD
              and is_private(src_ip) and not is_private(dst_ip)):
            attack_type="Data Exfiltration"; severity="HIGH"

        # Rule 3: SSH Brute Force
        elif dst_port==22 and pkt_count>SSH_PKT_THRESHOLD:
            attack_type="SSH Brute Force"; severity="HIGH"

        # Rule 4: Behavioral Anomaly (MEDIUM, not HIGH)
        else:
            anomalous,detail = is_behaviorally_anomalous(src_ip,bytes_sec,pkt_count)
            if anomalous:
                attack_type="Behavioral Anomaly"; severity="MEDIUM"; extra_detail=detail

        # Rule 5: ML — with per-IP cooldown
        if not attack_type:
            if (uptime>=ML_STARTUP_GRACE
                    and pkt_count>=ML_MIN_PKT_COUNT
                    and bytes_sec>=ML_MIN_BPS
                    and dst_port not in BENIGN_PORTS
                    and not _ml_on_cooldown(src_ip)
                    and pred==1 and conf>=ML_CONF_THRESHOLD):
                attack_type="ML Detected Anomaly"; severity="MEDIUM"
                _ml_mark_alerted(src_ip)
            elif not (uptime>=ML_STARTUP_GRACE) and pred==1:
                print(f"[ML-GRACE] {src_ip} conf={conf:.2f} suppressed")

        # Rule 6: GeoIP — ONLY inbound (public->private)
        if (not attack_type
                and not is_private(src_ip)
                and is_private(dst_ip)
                and country in HIGH_RISK_COUNTRIES):
            attack_type=f"Geo-Threat ({country})"; severity="HIGH"
            extra_detail=f"Inbound from high-risk country {country}"

        # Rule 7: Lateral Movement
        lat = check_lateral_movement(src_ip,dst_ip)
        if lat and not attack_type:
            attack_type="Lateral Movement"; severity="CRITICAL"; extra_detail=lat

        # Rule 8: High-Risk ASN — ONLY inbound
        if (not attack_type
                and is_high_risk_asn(asn_org)
                and not is_private(src_ip)
                and is_private(dst_ip)):
            attack_type="High-Risk ASN"; severity="MEDIUM"
            extra_detail=f"AS{asn_num} ({asn_org}) cloud/VPN/hosting"

        verdict = f"ALERT {attack_type}" if attack_type else "clean"
        print(f"[FLOW] {src_ip}[{country}] ->{dst_ip}:{dst_port} "
              f"pkts={pkt_count} bps={bytes_sec:.0f} ml={pred}/{conf:.2f} {verdict}")

        if not attack_type:
            _save_normal_flow(features); continue

        if is_private(src_ip):
            print(f"[DHCP WARN] {src_ip} is private — MAC={mac}")

        report  = generate_soc_report(key,features,attack_type,severity,
                                      mac,country,asn_num,asn_org,extra_detail)
        blocked = observe(src_ip, severity, attack_type)

        add_alert({
            "type":attack_type,"severity":severity,
            "src":src_ip,"dst":dst_ip,"port":key[3],
            "mac":mac,"country":country,
            "asn":f"AS{asn_num} {asn_org}" if asn_num else "—",
            "time":time.strftime("%H:%M:%S"),
            "report":report,"blocked":blocked,
            "is_private_ip":is_private(src_ip),"extra":extra_detail,
            "features":{
                "src_port":features[0],"dst_port":features[1],
                "protocol":features[2],"duration":features[3],
                "pkt_count":features[4],"total_bytes":features[5],
                "mean_pkt_len":features[6],"max_pkt_len":features[7],
                "mean_iat":features[8],"bytes_per_sec":features[9],
                "label":1,"attack_type":attack_type
            }
        })
        if blocked:
            metrics["threats_blocked"]+=1
            print(f"[BLOCKED] {src_ip} reason={attack_type}")
        else:
            print(f"[ALERT]   {src_ip} reason={attack_type}")

# ===== MAIN =================================================================
print("NetGuardAI — Real-Time IDS")
print("="*60)
print(f"Interface     : {INTERFACE}")
print(f"GeoIP         : {'on' if GEOIP_ENABLED else 'off'}")
print(f"ASN detect    : {'on' if ASN_ENABLED else 'off'}")
print(f"Exfil rule    : private->public only (CDN pre-filtered)")
print(f"GeoIP/ASN     : inbound-only (no false alerts on outbound browsing)")
print(f"ML cooldown   : {ML_COOLDOWN_WINDOW}s per IP")
print(f"Honeypot sev  : HIGH (not CRITICAL — no insta-block on single hit)")
print("="*60)

import server as _srv
_srv._get_discovered_hosts = get_discovered_hosts
_srv._ping_single          = ping_single

start_server()

disc_thread = threading.Thread(target=_discovery_loop, daemon=True)
disc_thread.start()
print(f"[SCAN] Discovery thread started — subnet {_get_local_subnet()}")

sniff_thread = threading.Thread(
    target=lambda: sniff(iface=INTERFACE, prn=handle_packet, store=0)
)
sniff_thread.daemon = True
sniff_thread.start()

while True:
    process_flows()
    tick_unblock()
    time.sleep(CHECK_INTERVAL)