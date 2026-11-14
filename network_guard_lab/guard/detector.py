import time
from collections import defaultdict, deque
import config

class AnomalyDetector:
    def __init__(self):
        self.ip_mac_baseline = {
            "192.168.50.2": "fa:15:12:25:59:c9",
            "192.168.50.10": "42:e9:2c:a7:ad:1b",
            "192.168.50.99": "ca:42:b5:bf:6a:7b"
        }
        self.last_seen = {ip: time.time() for ip in self.ip_mac_baseline}
        self.arp_reply_history = defaultdict(lambda: deque(maxlen=100))
        self.dhcp_offer_history = defaultdict(lambda: deque(maxlen=50))

    def evaluate_arp(self, src_ip, src_mac, op):
        src_mac = src_mac.lower()
        score = 0
        reasons = []
        now = time.time()

        # Feature 1: MAC Migration Delta & Rapid Drift Check
        if src_ip in self.ip_mac_baseline and self.ip_mac_baseline[src_ip] != src_mac:
            score += config.WEIGHT_MAC_MIGRATION
            reasons.append(f"MAC drift for {src_ip}: {self.ip_mac_baseline[src_ip]} -> {src_mac}")
            if (now - self.last_seen.get(src_ip, 0)) < 10.0:
                score += config.WEIGHT_RAPID_DRIFT
                reasons.append("Rapid MAC migration (<10s)")

        # Feature 2: Sliding-Window Frame Velocity
        if op == 2:
            self.arp_reply_history[src_mac].append(now)
            recent_replies = [t for t in self.arp_reply_history[src_mac] if now - t <= config.WINDOW_SECONDS]
            if len(recent_replies) > config.ARP_BURST_LIMIT:
                score += config.WEIGHT_FRAME_VELOCITY
                reasons.append(f"ARP velocity spike ({len(recent_replies)} pkts/{config.WINDOW_SECONDS}s)")

        if score < config.ANOMALY_THRESHOLD and src_ip != "0.0.0.0":
            self.ip_mac_baseline[src_ip] = src_mac
            self.last_seen[src_ip] = now

        return score, reasons

    def evaluate_dhcp(self, server_ip, lease_time):
        score = 0
        reasons = []
        now = time.time()

        # Feature 1: Unauthorized DHCP Server Check
        if server_ip not in config.TRUSTED_DHCP_IPS:
            score += config.WEIGHT_ROGUE_DHCP
            reasons.append(f"Unauthorized DHCP server {server_ip}")

        # Feature 2: Abnormally Short Lease Time
        if lease_time is not None and lease_time < config.MIN_SAFE_LEASE:
            score += config.WEIGHT_SHORT_LEASE
            reasons.append(f"Short lease duration ({lease_time}s)")

        # Feature 3: DHCP Offer Burst Rate
        self.dhcp_offer_history[server_ip].append(now)
        recent_offers = [t for t in self.dhcp_offer_history[server_ip] if now - t <= config.WINDOW_SECONDS]
        if len(recent_offers) > config.DHCP_BURST_LIMIT:
            score += config.WEIGHT_DHCP_BURST
            reasons.append(f"DHCP offer burst ({len(recent_offers)} pkts/{config.WINDOW_SECONDS}s)")

        return score, reasons
