import csv
import os
from datetime import datetime
import config

class SecurityLogger:
    def __init__(self):
        os.makedirs(os.path.dirname(config.LOG_FILE), exist_ok=True)
        file_exists = os.path.isfile(config.LOG_FILE)
        with open(config.LOG_FILE, mode="a", newline="") as f:
            writer = csv.writer(f)
            if not file_exists:
                writer.writerow([
                    "Timestamp", "Protocol", "Attacker_MAC", "Target_IP",
                    "Anomaly_Score", "Reasons", "Action_Taken", "Latency_ms"
                ])

    def log_event(self, protocol, attacker_mac, target_ip, score, reasons, action, latency_ms):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        reason_str = " | ".join(reasons)
        print(f"[{ts}] ALERT ({protocol}) Score={score} | MAC={attacker_mac} | {reason_str} -> {action} ({latency_ms:.2f}ms)")
        with open(config.LOG_FILE, mode="a", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([ts, protocol, attacker_mac, target_ip, score, reason_str, action, f"{latency_ms:.2f}"])
