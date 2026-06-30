"""
detect.py — Offline PCAP Detection

Run this on any .pcap file to get a detection report
without needing a live network interface.

Usage:
    python detect.py capture.pcap
    python detect.py capture.pcap --threshold 0.6
"""

import sys
import argparse
import joblib
import pandas as pd
import ipaddress
from features import parse_packets, group_into_flows, extract_features

# ===== CLI =====
parser = argparse.ArgumentParser(description="NetGuardAI Offline Detector")
parser.add_argument("pcap",       help="Path to .pcap file")
parser.add_argument("--model",    default="netguard_model.pkl", help="Model file")
parser.add_argument("--threshold",default=0.65, type=float,    help="ML confidence threshold")
parser.add_argument("--out",      default=None,                 help="Save results to CSV")
args = parser.parse_args()

FEATURE_COLS = ["src_port", "dst_port", "protocol", "duration",
                "pkt_count", "total_bytes", "mean_pkt_len",
                "max_pkt_len", "mean_iat", "bytes_per_sec"]

FLOOD_PKT_THRESHOLD = 2000
EXFIL_BPS_THRESHOLD = 5_000_000
SSH_PKT_THRESHOLD   = 40
HONEYPOT_PORTS      = {23, 3389, 1433, 5900, 4444, 31337}

def is_private(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False

# ── Load model ────────────────────────────────────────────────────────────────
print(f"Loading model from {args.model} …")
model = joblib.load(args.model)

# ── Extract features ──────────────────────────────────────────────────────────
print(f"Parsing {args.pcap} …")
raw_df   = parse_packets(args.pcap)
flows    = group_into_flows(raw_df)
feat_df  = extract_features(flows)
print(f"  Extracted {len(feat_df)} flows\n")

# ── Classify ──────────────────────────────────────────────────────────────────
X     = feat_df[FEATURE_COLS].astype(float)
preds = model.predict(X)
probs = model.predict_proba(X)[:, 1]

feat_df["ml_pred"]    = preds
feat_df["ml_conf"]    = probs.round(3)
feat_df["attack_type"] = "Normal"
feat_df["severity"]   = "-"

alerts = []

for idx, row in feat_df.iterrows():
    attack_type = None
    severity    = None

    if row["pkt_count"] > FLOOD_PKT_THRESHOLD:
        attack_type, severity = "Packet Flood",      "HIGH"
    elif row["bytes_per_sec"] > EXFIL_BPS_THRESHOLD:
        attack_type, severity = "Data Exfiltration", "HIGH"
    elif row["dst_port"] == 22 and row["pkt_count"] > SSH_PKT_THRESHOLD:
        attack_type, severity = "SSH Brute Force",   "HIGH"
    elif row["dst_port"] in HONEYPOT_PORTS:
        attack_type, severity = f"Honeypot:{int(row['dst_port'])}", "CRITICAL"
    elif row["ml_pred"] == 1 and row["ml_conf"] > args.threshold:
        attack_type, severity = "ML Anomaly",        "MEDIUM"

    if attack_type:
        feat_df.at[idx, "attack_type"] = attack_type
        feat_df.at[idx, "severity"]    = severity
        alerts.append({
            "src_ip":      row["src_ip"],
            "dst_ip":      row["dst_ip"],
            "dst_port":    int(row["dst_port"]),
            "attack_type": attack_type,
            "severity":    severity,
            "ml_conf":     row["ml_conf"],
            "pkt_count":   int(row["pkt_count"]),
            "bytes_per_sec": row["bytes_per_sec"],
            "is_private":  is_private(str(row["src_ip"]))
        })

# ── Report ────────────────────────────────────────────────────────────────────
SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "-": 4}
alerts.sort(key=lambda a: SEV_ORDER.get(a["severity"], 9))

print("=" * 65)
print(f"  NetGuardAI Offline Detection Report — {args.pcap}")
print("=" * 65)

if not alerts:
    print("  ✅ No threats detected.")
else:
    for a in alerts:
        priv_flag = " ⚠️ PRIVATE IP" if a["is_private"] else ""
        print(f"  [{a['severity']:8}]  {a['attack_type']:<25}"
              f"  {a['src_ip']}{priv_flag}")
        print(f"             → {a['dst_ip']}:{a['dst_port']}"
              f"  pkts={a['pkt_count']}  bps={a['bytes_per_sec']:.0f}"
              f"  ml_conf={a['ml_conf']:.2f}")
        print()

print(f"  Total flows  : {len(feat_df)}")
print(f"  Alerts       : {len(alerts)}")
critical = sum(1 for a in alerts if a["severity"] == "CRITICAL")
high     = sum(1 for a in alerts if a["severity"] == "HIGH")
medium   = sum(1 for a in alerts if a["severity"] == "MEDIUM")
print(f"  CRITICAL     : {critical}")
print(f"  HIGH         : {high}")
print(f"  MEDIUM       : {medium}")
print("=" * 65)

# ── Optional CSV export ───────────────────────────────────────────────────────
if args.out:
    feat_df.to_csv(args.out, index=False)
    print(f"\nFull results saved to {args.out}")