from scapy.all import sniff
from core.storage import results

def packet_callback(packet):
    if packet.haslayer("IP"):
        src = packet["IP"].src
        dst = packet["IP"].dst
        proto = packet["IP"].proto
        line = f"[SNF] {src} → {dst} | Proto: {proto}"
        print(line)
        results["sniff"].append(line)

def start_sniffing():
    print("[*] Sniffing réseau en cours... (Thread parallèle)")
    try:
        sniff(filter="ip", prn=packet_callback, store=0)
    except PermissionError:
        print("[!] Permission denied. Essayez avec sudo.")
