"""
scan.py — NetGuardAI Network Discovery & Ping Module

Provides:
  get_discovered_hosts()  → dict of {ip: host_info}
  ping_single(ip)         → {ip, ping_ms, reachable, hostname}

Injected into server.py via capture.py:
  import server
  server._get_discovered_hosts = get_discovered_hosts
  server._ping_single          = ping_single

How it works:
  1. ARP sweep on startup to find all live hosts on the LAN
  2. Passive ARP table from trust.py is also merged in
  3. ping_single() uses OS ping to measure round-trip latency
  4. Results are stored in DISCOVERED_HOSTS so the UI can poll /api/scan
"""

import subprocess
import threading
import time
import re
import socket
import platform

from scapy.all import ARP, Ether, srp, conf

# ── Shared state ─────────────────────────────────────────────────────────────
DISCOVERED_HOSTS = {}   # ip → {mac, hostname, ping_ms, reachable, first_seen, last_seen}
_lock = threading.Lock()

IS_WINDOWS = platform.system() == "Windows"

# ── ARP sweep ─────────────────────────────────────────────────────────────────
def arp_sweep(subnet: str, timeout: int = 3) -> dict:
    """
    Send ARP requests to every host in `subnet` (e.g. '192.168.1.0/24').
    Returns {ip: mac_address}.
    """
    print(f"[SCAN] ARP sweep on {subnet} …")
    conf.verb = 0
    try:
        ans, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet),
            timeout=timeout,
            verbose=False
        )
        results = {}
        for _, rcv in ans:
            results[rcv.psrc] = rcv.hwsrc
        print(f"[SCAN] Found {len(results)} hosts")
        return results
    except Exception as e:
        print(f"[SCAN] ARP sweep failed: {e}")
        return {}


# ── Reverse DNS ───────────────────────────────────────────────────────────────
def resolve_hostname(ip: str, timeout: float = 0.5) -> str:
    try:
        socket.setdefaulttimeout(timeout)
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""
    finally:
        socket.setdefaulttimeout(None)


# ── Ping ──────────────────────────────────────────────────────────────────────
def ping_single(ip: str) -> dict:
    """
    Ping an IP once and return latency.
    Result is stored in DISCOVERED_HOSTS so /api/scan shows updated ping_ms.
    """
    if IS_WINDOWS:
        cmd = ["ping", "-n", "1", "-w", "1000", ip]
    else:
        cmd = ["ping", "-c", "1", "-W", "1", ip]

    result = {"ip": ip, "ping_ms": None, "reachable": False, "hostname": ""}

    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
        output = out.stdout

        # Parse latency from ping output
        if IS_WINDOWS:
            # "Average = 12ms"  or  "time=12ms"
            m = re.search(r"(?:Average\s*=\s*|time[<=])(\d+)\s*ms", output, re.IGNORECASE)
        else:
            m = re.search(r"time[<=](\d+(?:\.\d+)?)\s*ms", output)

        if m:
            result["ping_ms"]   = float(m.group(1))
            result["reachable"] = True
        else:
            # Host unreachable / timeout — still mark as seen
            result["reachable"] = False

    except subprocess.TimeoutExpired:
        result["reachable"] = False
    except Exception as e:
        print(f"[PING] Error pinging {ip}: {e}")

    # Reverse DNS (non-blocking — best effort)
    result["hostname"] = resolve_hostname(ip)

    # Update shared table
    with _lock:
        existing = DISCOVERED_HOSTS.get(ip, {})
        DISCOVERED_HOSTS[ip] = {
            "mac":        existing.get("mac", "unknown"),
            "hostname":   result["hostname"] or existing.get("hostname", ""),
            "ping_ms":    result["ping_ms"],
            "reachable":  result["reachable"],
            "first_seen": existing.get("first_seen", time.time()),
            "last_seen":  time.time(),
            "last_pinged": time.time(),
        }

    return result


# ── Public: get snapshot ──────────────────────────────────────────────────────
def get_discovered_hosts() -> dict:
    with _lock:
        return dict(DISCOVERED_HOSTS)


# ── Background: initial sweep + periodic refresh ──────────────────────────────
def _merge_passive_arp():
    """Pull in any IPs seen passively via ARP sniffing (trust.py)."""
    try:
        from trust import MAC_IP_TABLE
        with _lock:
            for ip, info in MAC_IP_TABLE.items():
                if ip not in DISCOVERED_HOSTS:
                    DISCOVERED_HOSTS[ip] = {
                        "mac":        info.get("mac", "unknown"),
                        "hostname":   resolve_hostname(ip),
                        "ping_ms":    None,
                        "reachable":  True,
                        "first_seen": info.get("first_seen", time.time()),
                        "last_seen":  info.get("last_seen",  time.time()),
                        "last_pinged": None,
                    }
    except Exception as e:
        print(f"[SCAN] Could not merge passive ARP: {e}")


def _detect_local_subnet() -> str:
    """
    Best-effort: figure out our own IP and return the /24 subnet.
    e.g. 192.168.1.105 → '192.168.1.0/24'
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        parts = local_ip.split(".")
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    except Exception:
        return "192.168.1.0/24"


def _initial_sweep():
    subnet = _detect_local_subnet()
    print(f"[SCAN] Detected subnet: {subnet}")
    found = arp_sweep(subnet)

    now = time.time()
    with _lock:
        for ip, mac in found.items():
            DISCOVERED_HOSTS[ip] = {
                "mac":        mac,
                "hostname":   "",   # filled lazily by ping_single
                "ping_ms":    None,
                "reachable":  True,
                "first_seen": now,
                "last_seen":  now,
                "last_pinged": None,
            }

    _merge_passive_arp()

    # Ping all found hosts in background threads
    threads = [threading.Thread(target=ping_single, args=(ip,), daemon=True)
               for ip in list(found.keys())]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5)


def _refresh_loop():
    """Re-ping all known hosts every 30 s to keep latency fresh."""
    while True:
        time.sleep(30)
        _merge_passive_arp()
        hosts = list(get_discovered_hosts().keys())
        for ip in hosts:
            threading.Thread(target=ping_single, args=(ip,), daemon=True).start()
            time.sleep(0.1)   # slight stagger to avoid flooding


def start_scanner():
    """Call this once from capture.py to launch background scanning."""
    threading.Thread(target=_initial_sweep, daemon=True).start()
    threading.Thread(target=_refresh_loop,  daemon=True).start()
    print("[SCAN] Scanner started")


# ── Standalone test ───────────────────────────────────────────────────────────
if __name__ == "__main__":
    subnet = _detect_local_subnet()
    print(f"Detected subnet: {subnet}")
    hosts = arp_sweep(subnet)
    print(f"\nDiscovered {len(hosts)} host(s):")
    for ip, mac in hosts.items():
        r = ping_single(ip)
        ms = f"{r['ping_ms']:.1f} ms" if r["ping_ms"] else "timeout"
        hn = r["hostname"] or "(no rDNS)"
        print(f"  {ip:<18}  {mac}  {ms:<12}  {hn}")