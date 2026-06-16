"""
train_model.py — NetGuardAI Model Training

Run manually:   python train_model.py
Auto-triggered: POST /retrain  (via server.py)

Data sources used (all merged before training):
  1. features.csv          — flows extracted from your real pcap
  2. confirmed_attacks.csv — true-positives confirmed via the dashboard
  3. Synthetic attacks      — injected so the model learns attack patterns
     even when real labeled attack flows are scarce
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib
import os

FEATURE_COLS = ["src_port", "dst_port", "protocol", "duration",
                "pkt_count", "total_bytes", "mean_pkt_len",
                "max_pkt_len", "mean_iat", "bytes_per_sec"]

# ── 1. Load base dataset ──────────────────────────────────────────────────────
print("Loading features.csv …")
df = pd.read_csv("features.csv")
print(f"  Base flows: {len(df)}")

# ── 2. Label base data ────────────────────────────────────────────────────────
def label_row(row):
    # CODESYS PLC ports found in your original capture
    if 1740 <= row["dst_port"] <= 1743:
        return 1
    return 0

df["label"] = df.apply(label_row, axis=1)

# ── 3. Merge confirmed real-world attacks from dashboard ──────────────────────
CONFIRMED_FILE = "confirmed_attacks.csv"
if os.path.exists(CONFIRMED_FILE):
    confirmed = pd.read_csv(CONFIRMED_FILE)
    # Keep only usable columns
    available = [c for c in FEATURE_COLS if c in confirmed.columns]
    confirmed = confirmed[available + (["label"] if "label" in confirmed.columns else [])]
    if "label" not in confirmed.columns:
        confirmed["label"] = 1   # confirmed = attack
    # Fill any missing feature columns with 0
    for col in FEATURE_COLS:
        if col not in confirmed.columns:
            confirmed[col] = 0
    print(f"  Confirmed real attacks: {len(confirmed)}")
    df = pd.concat([df, confirmed], ignore_index=True)
else:
    print("  No confirmed_attacks.csv yet — skipping (confirm alerts from dashboard to build this)")

# ── 4. Inject synthetic attack samples ────────────────────────────────────────
rng = np.random.default_rng(42)

def make_attacks(n, kind):
    if kind == "portscan":
        return pd.DataFrame({
            "src_ip":       "10.0.0.1", "dst_ip": "192.168.1.1",
            "src_port":     rng.integers(49152, 65535, n),
            "dst_port":     rng.integers(1, 65535, n),
            "protocol":     6,
            "duration":     rng.uniform(0.0001, 0.002, n),
            "pkt_count":    1,
            "total_bytes":  rng.integers(54, 60, n),
            "mean_pkt_len": 56.0,
            "max_pkt_len":  60,
            "mean_iat":     0.0,
            "bytes_per_sec":rng.uniform(20000, 80000, n),
            "label":        1
        })
    elif kind == "bruteforce":
        return pd.DataFrame({
            "src_ip":       "10.0.0.2", "dst_ip": "192.168.1.1",
            "src_port":     rng.integers(49152, 65535, n),
            "dst_port":     22,
            "protocol":     6,
            "duration":     rng.uniform(0.5, 3.0, n),
            "pkt_count":    rng.integers(15, 50, n),
            "total_bytes":  rng.integers(800, 3000, n),
            "mean_pkt_len": rng.uniform(60, 200, n),
            "max_pkt_len":  rng.integers(200, 600, n),
            "mean_iat":     rng.uniform(0.04, 0.12, n),
            "bytes_per_sec":rng.uniform(300, 2000, n),
            "label":        1
        })
    elif kind == "flood":
        return pd.DataFrame({
            "src_ip":       "45.0.0.1", "dst_ip": "192.168.1.1",
            "src_port":     rng.integers(1024, 65535, n),
            "dst_port":     rng.integers(1, 65535, n),
            "protocol":     17,
            "duration":     rng.uniform(1.0, 10.0, n),
            "pkt_count":    rng.integers(500, 5000, n),
            "total_bytes":  rng.integers(50000, 500000, n),
            "mean_pkt_len": rng.uniform(100, 1400, n),
            "max_pkt_len":  rng.integers(1000, 1500, n),
            "mean_iat":     rng.uniform(0.0001, 0.002, n),
            "bytes_per_sec":rng.uniform(50000, 800000, n),
            "label":        1
        })
    elif kind == "lateral":
        return pd.DataFrame({
            "src_ip":       "192.168.1.50", "dst_ip": "192.168.1.0",
            "src_port":     rng.integers(1024, 65535, n),
            "dst_port":     rng.integers(135, 445, n),
            "protocol":     6,
            "duration":     rng.uniform(0.001, 0.1, n),
            "pkt_count":    rng.integers(1, 5, n),
            "total_bytes":  rng.integers(60, 200, n),
            "mean_pkt_len": rng.uniform(60, 100, n),
            "max_pkt_len":  rng.integers(100, 200, n),
            "mean_iat":     rng.uniform(0.001, 0.05, n),
            "bytes_per_sec":rng.uniform(600, 3000, n),
            "label":        1
        })
    elif kind == "exfil":
        return pd.DataFrame({
            "src_ip":       "192.168.1.80", "dst_ip": "1.2.3.4",
            "src_port":     rng.integers(1024, 65535, n),
            "dst_port":     rng.integers(1, 1024, n),
            "protocol":     6,
            "duration":     rng.uniform(5.0, 30.0, n),
            "pkt_count":    rng.integers(500, 3000, n),
            "total_bytes":  rng.integers(5_000_000, 50_000_000, n),
            "mean_pkt_len": rng.uniform(1200, 1500, n),
            "max_pkt_len":  1500,
            "mean_iat":     rng.uniform(0.001, 0.005, n),
            "bytes_per_sec":rng.uniform(5_000_000, 20_000_000, n),
            "label":        1
        })

attacks = pd.concat([
    make_attacks(60, "portscan"),
    make_attacks(60, "bruteforce"),
    make_attacks(60, "flood"),
    make_attacks(60, "lateral"),
    make_attacks(60, "exfil"),
], ignore_index=True)

df_all = pd.concat([df, attacks], ignore_index=True)

normal_count = (df_all["label"] == 0).sum()
attack_count = (df_all["label"] == 1).sum()
print(f"\nTotal: {len(df_all)}  |  Normal: {normal_count}  |  Attack: {attack_count}")

# ── 5. Train ──────────────────────────────────────────────────────────────────
X = df_all[FEATURE_COLS].astype(float)
y = df_all["label"].astype(int)

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.25, random_state=42, stratify=y
)

model = RandomForestClassifier(
    n_estimators=150,
    class_weight="balanced",
    max_depth=20,
    random_state=42
)
model.fit(X_train, y_train)

# ── 6. Evaluate ───────────────────────────────────────────────────────────────
print("\nTest results:")
print(classification_report(y_test, model.predict(X_test),
                             target_names=["Normal", "Attack"]))

# Feature importance
importances = sorted(
    zip(FEATURE_COLS, model.feature_importances_),
    key=lambda x: x[1], reverse=True
)
print("Feature importances:")
for feat, score in importances:
    bar = "█" * int(score * 40)
    print(f"  {feat:<15} {bar}  {score:.4f}")

# ── 7. Save ───────────────────────────────────────────────────────────────────
joblib.dump(model, "netguard_model.pkl")
print("\n✅ Model saved as netguard_model.pkl")