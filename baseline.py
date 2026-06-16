"""
baseline.py — Per-IP Behavioral Baseline

Fixes:
- MIN_SAMPLES raised to 40 (was 10) for stable averages on real networks
- ANOMALY_RATIO raised to 8.0 (was 3.0) to eliminate false positives
  from normal bursty traffic like video calls, OS updates, page loads
- Module is standalone so both capture.py and server.py share ONE instance
"""

import threading

IP_BASELINE   = {}
baseline_lock = threading.Lock()

ANOMALY_RATIO = 8.0    # must be 8x the rolling average to flag — not 3x
MIN_SAMPLES   = 40     # need 40 flows before baseline is trusted


def update_baseline(src_ip: str, bps: float, pkt_count: int):
    with baseline_lock:
        b = IP_BASELINE.setdefault(
            src_ip, {"avg_bps": 0.0, "avg_pkt": 0.0, "samples": 0}
        )
        n = b["samples"]
        b["avg_bps"] = (b["avg_bps"] * n + bps)       / (n + 1)
        b["avg_pkt"] = (b["avg_pkt"] * n + pkt_count) / (n + 1)
        b["samples"] += 1


def is_behaviorally_anomalous(src_ip: str, bps: float, pkt_count: int):
    with baseline_lock:
        b = IP_BASELINE.get(src_ip)
    if not b or b["samples"] < MIN_SAMPLES:
        return False, None

    bps_ratio = (bps       / b["avg_bps"]) if b["avg_bps"] > 0 else 0
    pkt_ratio = (pkt_count / b["avg_pkt"]) if b["avg_pkt"] > 0 else 0

    if bps_ratio > ANOMALY_RATIO or pkt_ratio > ANOMALY_RATIO:
        detail = (
            f"BPS={bps:.0f} ({bps_ratio:.1f}x normal)  "
            f"PKT={pkt_count} ({pkt_ratio:.1f}x normal)"
        )
        return True, detail
    return False, None


def get_baseline_snapshot() -> dict:
    with baseline_lock:
        return dict(IP_BASELINE)