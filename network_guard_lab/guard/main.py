import time
from scapy.all import sniff, Ether, ARP, IP, BOOTP, DHCP
import config
from detector import AnomalyDetector
from mitigator import ActiveMitigator
from logger import SecurityLogger

detector = AnomalyDetector()
mitigator = ActiveMitigator()
logger = SecurityLogger()

def extract_dhcp_options(dhcp_options):
    msg_type = None
    lease_time = None
    server_id = None
    for opt in dhcp_options:
        if isinstance(opt, tuple) and len(opt) >= 2:
            if opt[0] == "message-type":
                msg_type = opt[1]
            elif opt[0] == "lease_time":
                lease_time = opt[1]
            elif opt[0] == "server_id":
                server_id = opt[1]
    return msg_type, lease_time, server_id

def packet_callback(pkt):
    start_time = time.perf_counter()

    if pkt.haslayer(Ether) and pkt[Ether].src.lower() == config.GATEWAY_MAC.lower():
        if pkt.haslayer(ARP) and pkt[ARP].psrc == config.GATEWAY_IP:
            return

    if pkt.haslayer(ARP):
        arp = pkt[ARP]
        score, reasons = detector.evaluate_arp(arp.psrc, arp.hwsrc, arp.op)
        if score >= config.ANOMALY_THRESHOLD:
            legit_mac = detector.ip_mac_baseline.get(arp.psrc, config.GATEWAY_MAC)
            action = mitigator.mitigate_arp(arp.hwsrc, arp.pdst, arp.hwdst, arp.psrc, legit_mac)
            latency_ms = (time.perf_counter() - start_time) * 1000
            logger.log_event("ARP", arp.hwsrc, arp.psrc, score, reasons, action, latency_ms)

    elif pkt.haslayer(DHCP) and pkt.haslayer(BOOTP):
        msg_type, lease_time, server_id = extract_dhcp_options(pkt[DHCP].options)
        if msg_type in (2, 5):
            src_ip = server_id or (pkt[IP].src if pkt.haslayer(IP) else "0.0.0.0")
            score, reasons = detector.evaluate_dhcp(src_ip, lease_time)
            if score >= config.ANOMALY_THRESHOLD:
                action = mitigator.mitigate_dhcp(pkt[Ether].src, pkt[BOOTP].chaddr, src_ip, pkt[BOOTP].xid)
                latency_ms = (time.perf_counter() - start_time) * 1000
                logger.log_event("DHCP", pkt[Ether].src, src_ip, score, reasons, action, latency_ms)

if __name__ == "__main__":
    print(f"[*] Intelligent Network Guard ACTIVE on {config.INTERFACE} ({config.GATEWAY_IP} / {config.GATEWAY_MAC})")
    sniff(
        iface=config.INTERFACE,
        filter="arp or (udp and (port 67 or 68))",
        prn=packet_callback,
        store=False
    )
