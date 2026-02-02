from scapy.all import sniff, IP, conf
import sys

print("Testing Packet Sniffing...")
print(f"Scapy config: {conf.iface}")

def packet_callback(packet):
    if packet.haslayer(IP):
        print(f"Captured: {packet[IP].src} -> {packet[IP].dst}")
        sys.exit(0) # Exit after 1 packet

try:
    print("Waiting for packets... (generate some traffic if this hangs)")
    sniff(prn=packet_callback, store=0, count=1, timeout=10)
    print("Test finished.")
except Exception as e:
    print(f"Sniffing FAILED: {e}")
    print("\nAttempting to assist:")
    print("1. Are you running as Administrator?")
    print("2. Is Npcap installed? (https://npcap.com/#download)")
    print("   (Make sure 'Install Npcap in WinPcap API-compatible Mode' is checked)")
