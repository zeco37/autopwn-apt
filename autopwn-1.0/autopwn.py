#!/usr/bin/env python3

import os
import importlib
import sys
from rich.console import Console
from rich.table import Table

required_modules = [
    "nmap", "requests", "bs4", "scapy", "colorama", "rich", "dns", "builtwith"
]

missing = []
for module in required_modules:
    try:
        importlib.import_module(module)
    except ImportError:
        missing.append(module)

if missing:
    print("\n\033[91m[!] Les modules suivants sont manquants :\033[0m")
    for m in missing:
        print(f"   - {m}")
    print("\n\033[93m[!] Veuillez les installer avec la commande suivante :\033[0m\n")
    print("   pip install " + " ".join(set(missing)))
    sys.exit(1)

from scanner.port_scanner import scan_ports
from bruteforce.bruteforce import bruteforce_dirs
from spoofing.arp_spoof import launch_arp_spoof
from sniffer.live_sniffer import start_sniffing
from dns_enum.dns_enum import enumerate_dns
from web_tech.web_tech_detect import detect_technologies
from payloads.payload_gen import generate_payload
from listener.listener_meterpreter import start_listener

console = Console()

def show_banner():
    console.print("""[bold cyan]
 █████╗ ██╗   ██╗████████╗ ██████╗ ██████╗ ██╗    ██╗███╗   ██╗
██╔══██╗██║   ██║╚══██╔══╝██╔═══██╗██╔══██╗██║    ██║████╗  ██║
███████║██║   ██║   ██║   ██║   ██║██████╔╝██║ █╗ ██║██╔██╗ ██║
██╔══██║██║   ██║   ██║   ██║   ██║██╔═══╝ ██║███╗██║██║╚██╗██║
██║  ██║╚██████╔╝   ██║   ╚██████╔╝██║     ╚███╔███╔╝██║ ╚████║
╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝ ╚═╝      ╚══╝╚══╝ ╚═╝  ╚═══╝
[/bold cyan]
[orange3]========================= AutoPwn v1.0 =========================[/orange3]
[green]                   Developed by Zakaria BEALIOUI [/green]
[orange3]================================================================[/orange3]
""")
    console.print("              [green]Automated Pentest & Exploit Framework[/green]\n")

def main_menu():
    while True:
        os.system("clear")
        show_banner()

        table = Table(title="[bold]AutoPwn - Menu Principal[/bold]", show_lines=True)
        table.add_column("ID", justify="center", style="cyan")
        table.add_column("Modes", style="magenta")
        table.add_row("1", "Port Scanning & Vulnerability Detection")
        table.add_row("2", "Network Sniffing")
        table.add_row("3", "ARP Spoofing (MITM)")
        table.add_row("4", "Directory Bruteforce")
        table.add_row("5", "DNS Enumeration")
        table.add_row("6", "Web Technology Detection")
        table.add_row("7", "Payload Generator")
        table.add_row("8", "Meterpreter Listener")
        table.add_row("0", "Quit")
        console.print(table)

        choix = input("[>] Choose an option : ").strip()

        if choix == "1":
            ip = input("IP cible : ")
            full = input("Vulnerability Detection ? (y/n) : ").lower() == "y"
            scan_ports(ip, vuln_scan=full)

        elif choix == "2":
            start_sniffing()

        elif choix == "3":
            target_ip = input("🔴 IP de la cible: ").strip()
            spoofed_ip = input("🔴 IP usurpée (ex: gateway): ").strip()
            launch_arp_spoof(target_ip, spoofed_ip)

        elif choix == "4":
            url = input("Target URL : ")
            wordlist = input("Path to wordlist : ")
            threads_input = input("Number of threads [default=200] : ").strip()
            try:
                threads = int(threads_input) if threads_input else 200
            except ValueError:
                threads = 200
                print("[!] Invalid thread count. Using default = 200")

            bruteforce_dirs(url, wordlist, max_threads=threads)

        elif choix == "5":
            domaine = input("Domain name : ")
            enumerate_dns(domaine)

        elif choix == "6":
            url = input("Website URL : ")
            detect_technologies(url)

        elif choix == "7":
            generate_payload()

        elif choix == "8":
            ip = input("🔹 LHOST (Your listening IP) : ").strip()
            port = input("🔹 LPORT (Listening Port) : ").strip()
            payload = input("🔹 PAYLOAD (ex: windows/x64/meterpreter/reverse_tcp) : ").strip()
            print(f"\n[✓] Starting listener on {ip}:{port} with payload : {payload}")
            start_listener(ip, port, payload)

        elif choix == "0":
            break

        else:
            print("[!] Invalid choice")

        input("\nPress Enter to continue...")

if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user. Exiting…")
