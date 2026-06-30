"""
server.py — NetGuardAI Flask API

Additions vs original:
  /api/scan   — return all discovered hosts (ARP sweep results)
  /api/ping   — ping a specific IP and return latency
  /api/ping_all — ping all discovered hosts
"""

from flask import Flask, jsonify, send_from_directory, request
from flask_cors import CORS
from firewall import EVENT_LOG, lock as firewall_lock
import os, threading, subprocess, csv

print("SERVER MODULE LOADED")

app  = Flask(__name__)
CORS(app)

alerts  = []
packets = []
metrics = {"packets": 0, "threats_blocked": 0, "avg_latency": 0}
lock    = threading.Lock()

CONFIRMED_ATTACKS_FILE = "confirmed_attacks.csv"

# Injected by capture.py after import so we avoid circular imports
_get_discovered_hosts = lambda: {}
_ping_single          = lambda ip: {"ip": ip, "ping_ms": None, "reachable": False}

# ===== HOME =================================================================
DASHBOARD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "dashboard")

@app.route("/")
def home():
    return send_from_directory(DASHBOARD_DIR, "index.html")
# ===== ALERTS ===============================================================
@app.route("/alerts")
def get_alerts():
    with lock: return jsonify(alerts)

def add_alert(data):
    with lock:
        alerts.insert(0, data)
        if len(alerts) > 50: alerts.pop()

# ===== CONFIRM ==============================================================
@app.route("/confirm/<int:alert_idx>", methods=["POST"])
def confirm_attack(alert_idx):
    with lock:
        if alert_idx < 0 or alert_idx >= len(alerts):
            return jsonify({"success": False, "error": "index out of range"}), 404
        alert = alerts[alert_idx]
    features = alert.get("features") or {
        "src_port":0,"dst_port":alert.get("port",0),"protocol":6,
        "duration":0,"pkt_count":0,"total_bytes":0,"mean_pkt_len":0,
        "max_pkt_len":0,"mean_iat":0,"bytes_per_sec":0,
        "label":1,"attack_type":alert.get("type","unknown")
    }
    file_exists = os.path.exists(CONFIRMED_ATTACKS_FILE)
    with open(CONFIRMED_ATTACKS_FILE, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(features.keys()))
        if not file_exists: writer.writeheader()
        writer.writerow(features)
    return jsonify({"success": True, "written": features})

# ===== RETRAIN ==============================================================
@app.route("/retrain", methods=["POST"])
def retrain_model():
    def _retrain():
        print("[RETRAIN] Starting …")
        result = subprocess.run(["python","train_model.py"], capture_output=True, text=True)
        if result.returncode == 0: print("[RETRAIN] Done")
        else: print("[RETRAIN] Error:", result.stderr[-300:])
    threading.Thread(target=_retrain, daemon=True).start()
    return jsonify({"success": True, "message": "Retraining started in background"})

# ===== PACKETS ==============================================================
@app.route("/packets")
def get_packets():
    with lock: return jsonify(packets)

def add_packet(data):
    with lock:
        packets.insert(0, data)
        if len(packets) > 50: packets.pop()

# ===== METRICS ==============================================================
@app.route("/metrics")
def get_metrics():
    with lock: m = dict(metrics)
    m["threats_blocked"] = len(get_blocked_view())
    return jsonify(m)

# ===== BLOCKED ==============================================================
from firewall import get_blocked_view, manual_unblock, observe as fw_observe

@app.route("/blocked")
def get_blocked():
    return jsonify(get_blocked_view())

@app.route("/block/<ip>", methods=["POST"])
def block_ip(ip):
    try:
        blocked = fw_observe(ip, "CRITICAL", "Manual block via dashboard")
        return jsonify({"success": True, "blocked": blocked})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/unblock/<ip>", methods=["POST"])
def unblock(ip):
    return jsonify({"success": manual_unblock(ip)})

# ===== EVENTS ===============================================================
@app.route("/events")
def get_events():
    with firewall_lock: return jsonify(list(EVENT_LOG[-50:]))

# ===== TRUSTED ==============================================================
from trust import get_trusted_ips, add_trusted_ip, remove_trusted_ip, get_mac_ip_table

@app.route("/trusted")
def get_trusted(): return jsonify(get_trusted_ips())

@app.route("/trusted/add/<ip>", methods=["POST"])
def add_trusted(ip):
    label = request.args.get("label","manual")
    return jsonify({"success": add_trusted_ip(ip, label)})

@app.route("/trusted/remove/<ip>", methods=["POST"])
def remove_trusted(ip):
    return jsonify({"success": remove_trusted_ip(ip)})

@app.route("/mac_table")
def get_mac_table(): return jsonify(get_mac_ip_table())

# ===== BASELINE =============================================================
@app.route("/baseline")
def get_baseline():
    try:
        from baseline import get_baseline_snapshot
        return jsonify(get_baseline_snapshot())
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ===== NETWORK SCAN (NEW) ===================================================
@app.route("/api/scan")
def api_scan():
    """Return all discovered hosts from ARP sweep + passive ARP."""
    hosts = _get_discovered_hosts()
    return jsonify(hosts)

@app.route("/api/ping/<ip>", methods=["GET","POST"])
def api_ping(ip):
    """Ping a single IP and return latency in ms."""
    result = _ping_single(ip)
    return jsonify(result)

@app.route("/api/ping_all", methods=["POST"])
def api_ping_all():
    """Kick off a background ping of all discovered hosts."""
    hosts = _get_discovered_hosts()
    def _do_pings():
        for ip in list(hosts.keys()):
            _ping_single(ip)
    threading.Thread(target=_do_pings, daemon=True).start()
    return jsonify({"success": True, "count": len(hosts)})

# ===== SCORES ===============================================================
@app.route("/scores")
def get_scores():
    from firewall import get_all_scores
    return jsonify(get_all_scores())

@app.route("/scanner")
def scanner_page():
    return send_from_directory(DASHBOARD_DIR, "scanner.html")
# ===== RUN ==================================================================
def run_server():
    app.run(host="0.0.0.0", port=5000, use_reloader=False)

def start_server():
    threading.Thread(target=run_server, daemon=True).start()

if __name__ == "__main__":
    run_server()