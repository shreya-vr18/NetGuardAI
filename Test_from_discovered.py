"""
test_from_discovered.py — Simulate attacks FROM discovered IPs TO your machine

How it works:
  - Pulls discovered IPs from your running NetGuard server (/api/scan)
  - Crafts raw packets with those IPs as SOURCE using Scapy
  - Sends them to YOUR machine's IP
  - Your capture.py picks them up → IDS fires alerts

Run WHILE capture.py / server.py is running:
    python test_from_discovered.py

Requirements:
  - Run as Administrator (raw sockets need it)
  - pip install scapy requests
"""

import time
import socket
import requests
from scapy.all import IP, TCP, UDP, send, RandShort

# ── Config ────────────────────────────────────────────────────────────────────
SERVER_URL  = "http://127.0.0.1:5000"   # your running NetGuard server
MY_IP       = socket.gethostbyname(socket.gethostname())  # your own LAN IP
INTER_PKT   = 0.01   # seconds between packets (lower = more aggressive)

print(f"[*] Your IP (target): {MY_IP}")


# ── Step 1: Fetch discovered IPs from your scanner ────────────────────────────
def get_discovered_ips():
    try:
        r = requests.get(f"{SERVER_URL}/api/scan", timeout=5)
        hosts = r.json()
        ips = list(hosts.keys())
        print(f"[*] Fetched {len(ips)} discovered IPs from /api/scan")
        return ips
    except Exception as e:
        print(f"[!] Could not reach server: {e}")
        print("[*] Using hardcoded fallback IPs instead")
        return ["192.168.1.10", "192.168.1.20", "192.168.1.30"]


# ── Attack simulations ────────────────────────────────────────────────────────

def sim_port_scan(src_ip):
    """Rapidly probe many ports — triggers port scan detection."""
    print(f"  [PORT SCAN] from {src_ip} → {MY_IP}")
    for dst_port in range(20, 120):   # 100 ports
        pkt = IP(src=src_ip, dst=MY_IP) / TCP(sport=RandShort(), dport=dst_port, flags="S")
        send(pkt, verbose=False)
        time.sleep(INTER_PKT)


def sim_ssh_bruteforce(src_ip):
    """Many TCP connections to port 22 — triggers SSH brute force detection."""
    print(f"  [SSH BRUTE] from {src_ip} → {MY_IP}:22")
    for i in range(50):
        pkt = IP(src=src_ip, dst=MY_IP) / TCP(sport=RandShort(), dport=22, flags="S")
        send(pkt, verbose=False)
        time.sleep(INTER_PKT)


def sim_packet_flood(src_ip):
    """High volume UDP flood — triggers packet flood / DDoS detection."""
    print(f"  [FLOOD]     from {src_ip} → {MY_IP}")
    for i in range(3000):   # 3000 packets
        pkt = IP(src=src_ip, dst=MY_IP) / UDP(sport=RandShort(), dport=80) / (b"X" * 512)
        send(pkt, verbose=False)
        if i % 300 == 0:
            print(f"    ...{i}/3000 packets sent")


def sim_honeypot_probe(src_ip):
    """Hit known honeypot ports — triggers CRITICAL honeypot alert."""
    honeypot_ports = [23, 3389, 1433, 4444, 31337]
    print(f"  [HONEYPOT]  from {src_ip} → {MY_IP} ports {honeypot_ports}")
    for port in honeypot_ports:
        pkt = IP(src=src_ip, dst=MY_IP) / TCP(sport=RandShort(), dport=port, flags="S")
        send(pkt, verbose=False)
        time.sleep(0.1)


def sim_data_exfil(src_ip):
    """Large outbound data transfer — triggers data exfiltration detection."""
    print(f"  [EXFIL]     from {src_ip} → {MY_IP}")
    for i in range(200):
        pkt = IP(src=src_ip, dst=MY_IP) / TCP(sport=RandShort(), dport=443, flags="PA") / (b"A" * 1400)
        send(pkt, verbose=False)
        time.sleep(0.001)


# ── Main: run all simulations across discovered IPs ───────────────────────────
def main():
    ips = get_discovered_ips()

    if not ips:
        print("[!] No IPs found. Make sure your server is running.")
        return

    print(f"\n[*] Starting attack simulations targeting {MY_IP}")
    print(f"[*] Using {len(ips)} discovered IPs as fake sources\n")
    print("=" * 55)

    # Assign different attack types to different IPs
    attack_plan = [
        (sim_port_scan,       "Port Scan"),
        (sim_ssh_bruteforce,  "SSH Brute Force"),
        (sim_packet_flood,    "Packet Flood"),
        (sim_honeypot_probe,  "Honeypot Probe"),
        (sim_data_exfil,      "Data Exfiltration"),
    ]

    for i, ip in enumerate(ips):
        attack_fn, attack_name = attack_plan[i % len(attack_plan)]
        print(f"\n[{i+1}/{len(ips)}] {attack_name} from {ip}")
        attack_fn(ip)
        time.sleep(1)   # brief pause between IPs

    print("\n" + "=" * 55)
    print("[✓] Simulation complete!")
    print(f"[*] Check your dashboard at {SERVER_URL}")
    print("[*] Check /alerts and /events for triggered detections")


if __name__ == "__main__":
    main()