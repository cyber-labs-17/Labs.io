import subprocess
from scapy.all import Ether, ARP, IP, UDP, BOOTP, DHCP, sendp
import config

class ActiveMitigator:
    def __init__(self):
        self.iface = config.INTERFACE
        self.blocked_macs = set()

    def block_mac_iptables(self, attacker_mac):
        mac = attacker_mac.lower()
        if mac not in self.blocked_macs and mac != config.GATEWAY_MAC.lower():
            subprocess.run(
                ["iptables-legacy", "-A", "INPUT", "-m", "mac", "--mac-source", mac, "-j", "DROP"],
                check=False
            )
            self.blocked_macs.add(mac)

    def mitigate_arp(self, attacker_mac, target_ip, target_mac, spoofed_ip, legitimate_mac):
        self.block_mac_iptables(attacker_mac)
        dst_mac = target_mac if target_mac != "00:00:00:00:00:00" else "ff:ff:ff:ff:ff:ff"
        corrective_pkt = Ether(dst=dst_mac, src=legitimate_mac) / ARP(
            op=2,
            psrc=spoofed_ip,
            hwsrc=legitimate_mac,
            pdst=target_ip,
            hwdst=dst_mac
        )
        sendp(corrective_pkt, iface=self.iface, count=5, inter=0.05, verbose=False)
        return f"Blocked MAC {attacker_mac} via iptables + sent 5 corrective ARP frames for {spoofed_ip}"

    def mitigate_dhcp(self, attacker_mac, client_mac_bytes, rogue_server_ip, xid):
        self.block_mac_iptables(attacker_mac)
        nak_pkt = (
            Ether(dst="ff:ff:ff:ff:ff:ff") /
            IP(src=rogue_server_ip, dst="255.255.255.255") /
            UDP(sport=67, dport=68) /
            BOOTP(op=2, yiaddr="0.0.0.0", siaddr=rogue_server_ip, chaddr=client_mac_bytes, xid=xid) /
            DHCP(options=[("message-type", "nak"), ("server_id", rogue_server_ip), "end"])
        )
        sendp(nak_pkt, iface=self.iface, count=3, inter=0.05, verbose=False)
        return f"Blocked MAC {attacker_mac} + injected 3 DHCP NAKs against rogue server {rogue_server_ip}"
