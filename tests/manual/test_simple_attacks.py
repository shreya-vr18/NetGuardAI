"""
simple_test.py — Test NetGuard using REAL TCP connections (no raw sockets needed)
No admin rights required. No Scapy raw packet issues.

Run while capture.py is running:
    python simple_test.py

What this triggers:
  - SSH Brute Force  → 50 connections to port 22  (HIGH alert)
  - Honeypot Probe   → hits ports 23, 3389, 4444  (CRITICAL alert)
  - Port Scan        → rapid connections to 100 ports (ML anomaly)
"""

import socket
import time
import threading
import requests

SERVER_URL = "http://127.0.0.1:5000"

# ── Auto-detect your correct LAN IP ──────────────────────────────────────────
def get_my_lan_ip():
    """Gets your actual LAN IP (not 127.0.0.1)"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

MY_IP = get_my_lan_ip()
print(f"[*] Targeting YOUR machine at: {MY_IP}")
print(f"[*] NetGuard dashboard: {SERVER_URL}\n")


# ── Helper: try to connect to a port (doesn't matter if refused) ──────────────
def knock(ip, port, timeout=0.3):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        s.close()
    except:
        pass  # Connection refused is fine — packet was still sent & captured


# ── Test 1: SSH Brute Force ───────────────────────────────────────────────────
def test_ssh_bruteforce():
    print("[TEST 1] SSH Brute Force → 50 rapid connections to port 22")
    print("         Expected: SSH Brute Force HIGH alert")
    for i in range(50):
        knock(MY_IP, 22)
        time.sleep(0.05)
    print("         Done ✓\n")


# ── Test 2: Honeypot Ports ────────────────────────────────────────────────────
def test_honeypot():
    honeypot_ports = [23, 3389, 1433, 5900, 4444, 31337]
    print(f"[TEST 2] Honeypot Probe → hitting ports {honeypot_ports}")
    print("         Expected: Honeypot CRITICAL alerts")
    for port in honeypot_ports:
        print(f"         Knocking port {port}...")
        knock(MY_IP, port)
        time.sleep(0.5)
    print("         Done ✓\n")


# ── Test 3: Port Scan (100 ports fast) ───────────────────────────────────────
def test_port_scan():
    print("[TEST 3] Port Scan → rapid probe of ports 1–150")
    print("         Expected: ML Anomaly / behavioral alert")
    for port in range(1, 151):
        knock(MY_IP, port, timeout=0.1)
    print("         Done ✓\n")


# ── Test 4: Flood simulation via rapid repeated connections ───────────────────
def test_flood():
    print("[TEST 4] Packet Flood → 500 rapid UDP-style connections to port 80")
    print("         Expected: Packet Flood HIGH alert")
    threads = []
    for i in range(500):
        t = threading.Thread(target=knock, args=(MY_IP, 80, 0.1))
        t.start()
        threads.append(t)
        if i % 100 == 0:
            print(f"         ...{i}/500")
        time.sleep(0.002)
    for t in threads:
        t.join(timeout=1)
    print("         Done ✓\n")


# ── Check alerts after test ───────────────────────────────────────────────────
def check_alerts():
    try:
        r = requests.get(f"{SERVER_URL}/alerts", timeout=5)
        alerts = r.json()
        print(f"\n[RESULTS] {len(alerts)} alerts in dashboard:")
        for a in alerts[:10]:  # show top 10
            severity = a.get('severity', a.get('type', '?'))
            src      = a.get('src_ip', a.get('ip', '?'))
            atype    = a.get('attack_type', a.get('type', '?'))
            print(f"  [{severity}]  {atype}  ←  {src}")
    except Exception as e:
        print(f"[!] Could not fetch alerts: {e}")


# ── Run all tests ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 55)
    print("  NetGuard Live Attack Simulation")
    print("=" * 55 + "\n")

    input("Press ENTER to start tests (make sure capture.py is running)...\n")

    test_honeypot()       # CRITICAL — easiest to trigger
    time.sleep(2)

    test_ssh_bruteforce() # HIGH
    time.sleep(2)

    test_port_scan()      # ML Anomaly
    time.sleep(2)

    test_flood()          # HIGH flood
    time.sleep(3)

    check_alerts()

    print("\n[✓] All tests complete!")
    print(f"[*] Open {SERVER_URL} → Alerts tab to see results")