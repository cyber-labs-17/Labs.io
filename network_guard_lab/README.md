# 🚨 Intelligent Network Guard (`network_guard_lab`)

**Automated Real-Time Detection and Mitigation of ARP Spoofing and Rogue DHCP Servers**

---

## 📌 Overview
Standard Local Area Networks (LANs) rely on unencrypted, trust-based Layer 2 broadcast protocols. As a result, a single compromised or malicious host on the same subnet can execute **ARP Cache Poisoning** (Man-in-the-Middle) or deploy a **Rogue DHCP Server** to hijack network traffic.

**Intelligent Network Guard** is a lightweight, Python-based active defense system designed to monitor local broadcast traffic, maintain a trusted baseline state table, detect anomalies in real time, and trigger automated countermeasures.

---

## 🏗️ Lab Topology (3-Node Testbed)

```text
+-------------------------------------------------------------------+

|                     Isolated Virtual LAN / Bridge                 |
+-----------------+-------------------------------+-----------------+

                  |                               |
        +---------v---------+           +---------v---------+

        |   node1_guard     |           |   node2_victim    |
        | (Defense Monitor) |           |  (Legitimate Host)|
        +-------------------+           +-------------------+
                                                  ^
                                                  | Spoofed ARP /
                                                  | Rogue DHCP Offer
                                        +---------+---------+

                                        |  node3_attacker   |
                                        |  (Threat Actor)   |
                                        +-------------------+
```

---

## ⚙️ System Architecture

1. **Sniffer & Profiling Module (`sniffer` / `logger`)**
   * Captures raw Ethernet frames (`ARP` and `DHCP` packets) on the local interface.
   * Establishes a baseline mapping of legitimate `IP ↔ MAC` bindings and authorized DHCP server identifiers.
2. **Anomaly Detection Engine (`detector`)**
   * Tracks state-table drift in real time.
   * Flags unauthorized MAC address migrations (ARP spoofing) and unrecognized `DHCP OFFER` / `ACK` broadcasts.
   * Logs detection latency and alert metrics to CSV for performance evaluation.
3. **Automated Mitigation Handler (`mitigator`)**
   * Executes active containment measures upon threat confirmation—such as injecting corrective gratuitous ARP frames to restore victim ARP caches or isolating offending interfaces.

---

## 🚀 Getting Started

### Prerequisites
* Linux environment (Ubuntu VM or Docker multi-node setup)
* Python 3.8+ with `scapy` installed
* Root / `CAP_NET_RAW` privileges for packet sniffing and frame injection

### Quick Setup
```bash
# 1. Clone the repository
git clone https://github.com
cd Labs.io/network_guard_lab

# 2. Install dependencies
pip install scapy

# 3. Run the guard module (requires sudo/root for raw sockets)
sudo python3 main.py
```

---

## 📊 Evaluation Metrics
* **Detection Latency:** Time elapsed between malicious frame injection and anomaly flag.
* **False Positive Rate:** Accuracy under normal network churn (legitimate lease renewals and new host joins).
* **Recovery Time:** Time required to restore clean IP-to-MAC bindings on `node2_victim`.

---

## ⚠️ Disclaimer
This project is built strictly for educational research and defensive network security testing inside isolated virtual labs.
