"""
features.py — Extract per-flow features from a .pcap file.

Used by:
  - detect.py  (offline detection)
  - train_model.py  (model training)

Output columns:
  src_ip, dst_ip, src_port, dst_port, protocol,
  duration, pkt_count, total_bytes, mean_pkt_len,
  max_pkt_len, mean_iat, bytes_per_sec
"""

from scapy.all import rdpcap, IP, TCP, UDP
import pandas as pd


def parse_packets(pcap_file):
    """Read a .pcap and return a flat DataFrame of individual packets."""
    packets = rdpcap(pcap_file)
    records = []

    for pkt in packets:
        if IP not in pkt:
            continue

        record = {
            "src_ip":    pkt[IP].src,
            "dst_ip":    pkt[IP].dst,
            "protocol":  pkt[IP].proto,
            "length":    len(pkt),
            "timestamp": float(pkt.time),
            "src_port":  0,
            "dst_port":  0,
            "tcp_flags": 0,
        }

        if TCP in pkt:
            record["src_port"]  = pkt[TCP].sport
            record["dst_port"]  = pkt[TCP].dport
            record["tcp_flags"] = int(pkt[TCP].flags)
        elif UDP in pkt:
            record["src_port"] = pkt[UDP].sport
            record["dst_port"] = pkt[UDP].dport

        records.append(record)

    df = pd.DataFrame(records)
    print(f"Parsed {len(df)} IP packets from {pcap_file}")
    return df


def group_into_flows(df):
    """Group packets into bidirectional flows."""
    flow_keys = ["src_ip", "dst_ip", "src_port", "dst_port", "protocol"]
    flows = df.groupby(flow_keys)
    print(f"Found {flows.ngroups} unique flows from {len(df)} packets")
    return flows


def extract_features(flows):
    """Compute statistical features for each flow."""
    feature_rows = []

    for flow_id, packets in flows:
        src_ip, dst_ip, src_port, dst_port, protocol = flow_id

        timestamps    = packets["timestamp"].sort_values()
        sizes         = packets["length"]

        duration      = timestamps.max() - timestamps.min()
        iats          = timestamps.diff().dropna()
        mean_iat      = iats.mean() if len(iats) > 0 else 0
        total_bytes   = sizes.sum()
        mean_pkt_len  = sizes.mean()
        max_pkt_len   = sizes.max()
        pkt_count     = len(packets)
        bytes_per_sec = total_bytes / duration if duration > 0 else 0

        feature_rows.append({
            "src_ip":        src_ip,
            "dst_ip":        dst_ip,
            "src_port":      src_port,
            "dst_port":      dst_port,
            "protocol":      protocol,
            "duration":      round(float(duration), 6),
            "pkt_count":     pkt_count,
            "total_bytes":   int(total_bytes),
            "mean_pkt_len":  round(float(mean_pkt_len), 2),
            "max_pkt_len":   int(max_pkt_len),
            "mean_iat":      round(float(mean_iat), 6),
            "bytes_per_sec": round(float(bytes_per_sec), 2),
        })

    return pd.DataFrame(feature_rows)


# ── Run standalone ────────────────────────────────────────────────────────────
if __name__ == "__main__":
    raw_df   = parse_packets("capture.pcap")
    flows    = group_into_flows(raw_df)
    features = extract_features(flows)

    features.to_csv("features.csv", index=False)
    print("\nFeature extraction complete!")
    print(f"Shape: {features.shape}")
    print(features.head())