import subprocess
import threading
import time

# ip -> {score, blocked, blocked_at, last_unblocked, reason, last_seen}
IP_STATE = {}
lock     = threading.Lock()
EVENT_LOG = []

# ===== TUNABLES =====
# Raised threshold from 3 → 6.  Previously a single CRITICAL event (score=3)
# instantly hit the threshold.  Now it takes 2 HIGH events or 1 CRITICAL + 1 MEDIUM
# before a block fires — much more appropriate for shared-WiFi environments.
SCORE_THRESHOLD  = 6
DECAY_WINDOW     = 60
COOLDOWN         = 60
IMMUNITY_WINDOW  = 10   # ignore re-block for 10s after unblock

# Severity → score increment mapping
SEVERITY_SCORE = {
    "CRITICAL": 3,
    "HIGH":     2,
    "MEDIUM":   1,
    "LOW":      1,
}


# ===== INTERNAL HELPERS =====
def _run(cmd):
    return subprocess.run(cmd, check=True, capture_output=True)

def _rule_name(ip):
    return f"NetGuard_Block_{ip}"

def _add_rule(ip):
    # Delete any existing rule first to avoid duplicates
    subprocess.run(
        ["netsh", "advfirewall", "firewall", "delete", "rule",
         f"name={_rule_name(ip)}"],
        capture_output=True
    )
    _run([
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={_rule_name(ip)}",
        "dir=in",
        "action=block",
        f"remoteip={ip}"
    ])

def _del_rule(ip):
    _run([
        "netsh", "advfirewall", "firewall", "delete", "rule",
        f"name={_rule_name(ip)}"
    ])


# ===== CORE: OBSERVE =====
def observe(ip, severity, reason):
    now = time.time()

    with lock:
        s = IP_STATE.setdefault(ip, {
            "score":          0,
            "blocked":        False,
            "blocked_at":     None,
            "last_unblocked": None,
            "reason":         None,
            "last_seen":      now
        })

        # ── DECAY: reduce score if IP has been quiet ─────────────────────────
        if now - s["last_seen"] > DECAY_WINDOW:
            s["score"] = max(0, s["score"] - 1)

        s["last_seen"] = now

        # ── IMMUNITY WINDOW: don't re-block immediately after unblock ─────────
        if s.get("last_unblocked") and (now - s["last_unblocked"] < IMMUNITY_WINDOW):
            return False

        # ── SCORING ───────────────────────────────────────────────────────────
        inc       = SEVERITY_SCORE.get(severity, 1)
        s["score"] += inc
        s["reason"] = reason

        print(f"SCORE {ip} = {s['score']}  (+{inc} for {severity})")

        # Log every score change so the event log is never empty ──────────────
        EVENT_LOG.append({
            "ip":     ip,
            "action": f"SCORED +{inc}",
            "time":   time.strftime("%H:%M:%S"),
            "reason": reason,
            "score":  s["score"]
        })
        if len(EVENT_LOG) > 200:
            EVENT_LOG.pop(0)

        # ── ALREADY BLOCKED ───────────────────────────────────────────────────
        if s["blocked"]:
            return False

        # ── MAC CONSISTENCY CHECK: detect DHCP reassignment before blocking ──
        # If the MAC changed since we first started accumulating score, a
        # different device is now using this IP. Reset so an innocent user
        # isn't blocked just because they inherited a suspicious IP.
        try:
            from trust import get_mac_for_ip
            current_mac = get_mac_for_ip(ip)
            if "last_mac" not in s:
                s["last_mac"] = current_mac
            elif current_mac != "unknown" and current_mac != s["last_mac"]:
                print(f"[MAC CHANGE] {ip}  old={s['last_mac']} → new={current_mac}"
                      f"  — different device, resetting score")
                s["score"]    = 0
                s["last_mac"] = current_mac
                return False
        except Exception:
            pass

        # ── BLOCK CONDITION ───────────────────────────────────────────────────
        if s["score"] >= SCORE_THRESHOLD:
            try:
                _add_rule(ip)
                s["blocked"]    = True
                s["blocked_at"] = now

                EVENT_LOG.append({
                    "ip":     ip,
                    "action": "BLOCKED",
                    "time":   time.strftime("%H:%M:%S"),
                    "reason": reason,
                    "score":  s["score"]
                })
                if len(EVENT_LOG) > 200:
                    EVENT_LOG.pop(0)

                print(f"[BLOCKED] {ip} score={s['score']}")
                return True

            except Exception as e:
                print("[FIREWALL ERROR]", e)
                return False

        return False


# ===== CORE: AUTO UNBLOCK =====
def tick_unblock():
    now       = time.time()
    to_unblock = []

    with lock:
        for ip, s in IP_STATE.items():
            if s["blocked"]:
                print(f"[CHECK] {ip} blocked_for={now - s['blocked_at']:.1f}s")
            if s["blocked"] and s["blocked_at"] and (now - s["blocked_at"] >= COOLDOWN):
                to_unblock.append(ip)

    for ip in to_unblock:
        try:
            print(f"[UNBLOCKING] {ip}")
            _del_rule(ip)

            with lock:
                s = IP_STATE[ip]
                s["blocked"]        = False
                s["blocked_at"]     = None
                s["score"]          = 1      # retain slight suspicion
                s["last_unblocked"] = now

                EVENT_LOG.append({
                    "ip":     ip,
                    "action": "UNBLOCKED",
                    "time":   time.strftime("%H:%M:%S"),
                    "reason": s["reason"]
                })
                if len(EVENT_LOG) > 200:
                    EVENT_LOG.pop(0)

            print(f"[AUTO UNBLOCKED] {ip}")

        except Exception as e:
            print("[UNBLOCK ERROR]", e)


# ===== MANUAL UNBLOCK =====
def manual_unblock(ip):
    with lock:
        if ip not in IP_STATE or not IP_STATE[ip]["blocked"]:
            return False

    try:
        _del_rule(ip)
        with lock:
            s = IP_STATE[ip]
            s["blocked"]        = False
            s["blocked_at"]     = None
            s["score"]          = 0
            s["last_unblocked"] = time.time()
        return True

    except Exception as e:
        print("[UNBLOCK ERROR]", e)
        return False


# ===== VIEW FOR UI =====
def get_blocked_view():
    with lock:
        return {
            ip: {
                "time":   time.strftime("%H:%M:%S", time.localtime(s["blocked_at"])),
                "reason": s["reason"],
                "score":  s["score"]
            }
            for ip, s in IP_STATE.items() if s["blocked"]
        }

def get_all_scores():
    """Return every tracked IP and its current risk score."""
    with lock:
        return {
            ip: {
                "score":   s["score"],
                "blocked": s["blocked"],
                "reason":  s["reason"]
            }
            for ip, s in IP_STATE.items()
        }