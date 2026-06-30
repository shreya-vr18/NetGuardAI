# NetGuard AI

A real-time Network Intrusion Detection System (IDS) that sniffs live traffic
on a Windows machine, classifies flows as normal or malicious using a trained
Random Forest model plus a set of hand-written rules, auto-blocks high-risk
IPs at the Windows Firewall level, and surfaces everything on a live web
dashboard.

Built as a final-year B.Tech project. Designed to behave like a lightweight
SOC (Security Operations Center) tool: capture → feature extraction →
detection → response → reporting.

## Architecture

```
                 ┌──────────────┐
   WiFi adapter →│  capture.py  │  sniffs packets (Scapy), groups into
                 │  (backend)   │  5-tuple flows, extracts features
                 └──────┬───────┘
                        │
          ┌─────────────┼──────────────────┐
          ▼             ▼                  ▼
   ┌─────────────┐ ┌───────────┐   ┌──────────────┐
   │ rule engine │ │ ML model  │   │ trust.py     │
   │ (port scan, │ │ (Random   │   │ CDN allow-   │
   │ honeypot,   │ │ Forest on │   │ list, MAC/IP │
   │ exfil, ARP) │ │ flow      │   │ pairing      │
   └──────┬──────┘ │ features) │   └──────────────┘
          │         └────┬─────┘
          ▼              ▼
   ┌──────────────────────────┐
   │ firewall.py — scoring +  │  per-IP score with decay window;
   │ Windows Firewall blocking│  auto-unblocks after cooldown
   └─────────────┬────────────┘
                 ▼
   ┌──────────────────────────┐
   │ server.py — Flask API    │  /api/alerts /api/scan /api/ping /retrain
   └─────────────┬────────────┘
                 ▼
   ┌──────────────────────────┐
   │ dashboard/index.html     │  live polling dashboard (vanilla JS)
   └──────────────────────────┘
```

`detect.py` is a separate offline path: feed it a `.pcap` file and it runs
the same feature extraction + trained model on it without needing a live
NIC, which is what makes the system testable without a real attacker.

## Project layout

```
backend/              Flask API + IDS engine
  capture.py           live packet capture, flow grouping, rule engine, entry point
  server.py             Flask API (alerts, network scan, retrain)
  detect.py              offline detection on a .pcap file
  features.py             feature extraction shared by detect.py / train_model.py
  firewall.py              per-IP scoring + Windows Firewall block/unblock
  trust.py                  trusted IP/MAC allowlist + CDN detection
  baseline.py                per-IP behavioral baseline (bytes/sec, pkt count)
  scan.py                     ARP-based LAN host discovery + ping
  train_model.py                trains the Random Forest model
dashboard/             static HTML dashboards (main + network scanner)
streamlit_dashboard/   standalone Streamlit demo UI
models/                trained model artifact (netguard_model.pkl)
data/                   sample feature data + example trusted-IP config
tests/manual/            attack-simulation scripts used to manually test capture.py
docs/                      original project writeup
```

## Setup

```bash
git clone https://github.com/shreya-vr18/NetGuardAI.git
cd NetGuardAI
python -m venv venv
venv\Scripts\activate          # Windows
pip install -r requirements.txt

# Npcap is required for Scapy packet capture on Windows:
# https://npcap.com/#download

cp data/trustedip.example.json data/trustedip.json   # seed your local trusted-IP DB
```

## Running it

Live capture requires Administrator privileges (raw socket access) and a
Windows machine with Npcap installed.
```bash
cd backend
python server.py        # Flask API on :5000
python capture.py        # run as Administrator, in a second terminal
```

Open `dashboard/index.html` in a browser, or run the Streamlit demo instead:

```bash
cd streamlit_dashboard
streamlit run app.py
```

### Offline detection (no live NIC needed)

```bash
cd backend
python detect.py path/to/capture.pcap --threshold 0.65
```

### Retraining the model

```bash
cd backend
python train_model.py
```

Trains on `data/sample_features.csv` plus any `confirmed_attacks.csv` built
up from confirming alerts in the dashboard, merged with synthetic attack
samples so the model sees attack patterns even when real labeled attacks
are scarce.

## Testing

`tests/manual/` contains two scripts used to manually exercise the IDS
against itself while `capture.py` is running on the same machine:

- `test_simple_attacks.py` — fires real TCP connections (SSH brute force,
  honeypot probes, port scans) at the local server. No admin rights or raw
  sockets needed.
- `test_from_discovered.py` — crafts raw packets via Scapy using IPs pulled
  from `/api/scan`, to simulate attacks appearing to come from other hosts
  on the LAN. Requires Administrator privileges.

A `pytest` unit test suite for `features.py` and `trust.py`, plus CI via
GitHub Actions, is in progress.

## How detection works

Two layers run in parallel on every flow:

1. **Rule engine** (in `capture.py`) — explicit checks for port scans,
   honeypot port hits, SSH brute force, data exfiltration (private→public
   only), and lateral movement, with public-IP traffic exempted from
   "suspicious by default" tagging and known CDN ranges (`trust.py`)
   excluded entirely.
2. **ML model** — a Random Forest trained on flow-level features (duration,
   packet count, bytes/sec, mean packet length, mean inter-arrival time,
   etc.), used to catch anomalies the rules don't explicitly cover.

Either layer raising a flag increments a per-IP score in `firewall.py`; once
the score crosses a threshold within a decay window, the IP is blocked at
the Windows Firewall and auto-unblocked after a cooldown.

When an alert fires, `generate_soc_report()` builds a structured plain-text
report (attack type, severity, source/destination, indicators) for the
dashboard — currently template-based, not an LLM call.

## Known limitations / next steps

- No automated test suite yet — only manual attack-simulation scripts.
- Windows-only (Npcap dependency, `netsh` firewall calls).
- Model trained on a small sample dataset (`data/sample_features.csv`);
  accuracy numbers should be read as a proof of concept, not a benchmark.
- No Docker setup yet — everything runs as local Python processes.
