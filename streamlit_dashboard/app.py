import streamlit as st
import time
import random

st.set_page_config(page_title="NetGuard AI", layout="wide")

st.title("🛡️ NetGuard AI — Real-Time IDS Dashboard")

# ===== SIDEBAR =====
st.sidebar.header("Attack Simulation")

attack = st.sidebar.selectbox(
    "Choose attack type",
    ["None", "Port Scan", "DDoS", "Data Exfiltration"]
)

start = st.sidebar.button("Start Simulation")

# ===== MAIN LAYOUT =====
col1, col2 = st.columns(2)

# ===== LIVE TRAFFIC =====
with col1:
    st.subheader("📡 Live Traffic Monitor")

    placeholder = st.empty()

    for i in range(20):
        traffic = random.randint(10, 100)
        placeholder.write(f"Packets/sec: {traffic}")
        time.sleep(0.5)

# ===== ALERT PANEL =====
with col2:
    st.subheader("🚨 Threat Analysis")

    if start:
        if attack == "Port Scan":
            st.error("Port scan detected!")
            st.write("AI Analysis: Multiple ports hit rapidly. Likely reconnaissance.")
        elif attack == "DDoS":
            st.error("DDoS attack detected!")
            st.write("AI Analysis: High packet rate flood. Possible denial of service.")
        elif attack == "Data Exfiltration":
            st.error("Data exfiltration detected!")
            st.write("AI Analysis: Unusual outbound data transfer spike.")
        else:
            st.success("No threats detected")