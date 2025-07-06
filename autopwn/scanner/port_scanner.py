import nmap
import time, sys, threading
from core.storage import results

def show_progress(flag):
    i = 0
    bar_length = 20
    while flag["running"]:
        percent = min(i, 100)
        bar_count = (percent * bar_length) // 100
        bar = "[" + "#" * bar_count + "-" * (bar_length - bar_count) + "]"
        sys.stdout.write(f"\r⏳ Analyse en cours {bar} {percent}%")
        sys.stdout.flush()
        time.sleep(1)
        i += 5
    sys.stdout.write("\r✅ Analyse terminée.                    \n")

def scan_ports(target, port_range=(1, 1000), vuln_scan=False):
    nm = nmap.PortScanner()
    ports = f"{port_range[0]}-{port_range[1]}"
    args = f"-sS -sV -sC -O -T5 -p {ports}"
    if vuln_scan:
        args += " --script vuln"

    print(f"\n🛠️  Lancement de l’analyse de l’hôte {target}...")

    try:
        flag = {"running": True}
        threading.Thread(target=show_progress, args=(flag,), daemon=True).start()

        nm.scan(hosts=target, arguments=args)

        flag["running"] = False
        time.sleep(0.2)

        if target not in nm.all_hosts():
            print("[!] Hôte injoignable.")
            return [], []

        print(f"\nRésultats pour {target} :\n")

        table = []
        vuln_data = []

        for proto in nm[target].all_protocols():
            for port in nm[target][proto]:
                info = nm[target][proto][port]
                table.append({
                    "port": port,
                    "proto": proto,
                    "state": info.get("state", ""),
                    "name": info.get("name", ""),
                    "version": info.get("version", ""),
                    "product": info.get("product", ""),
                    "extrainfo": info.get("extrainfo", "")
                })

        print("| Port | Proto | État | Service      | Version")
        print("|------|--------|------|---------------|-------------------------")
        for row in table:
            service_full = f"{row['name']} {row['product']} {row['version']} {row['extrainfo']}".strip()
            print(f"| {row['port']:<4} | {row['proto']:<6} | {row['state']:<4} | {row['name']:<13} | {service_full}")

        results["scan"].append(f"Scan sur {target} :")
        for row in table:
            results["scan"].append(
                f"  - Port {row['port']}/{row['proto']} → {row['state']} | {row['name']} {row['product']} {row['version']}"
            )

        if "osmatch" in nm[target]:
            os_guesses = nm[target]["osmatch"]
            if os_guesses:
                os_detected = os_guesses[0]["name"]
                print(f"\n[+] OS détecté : {os_detected}")
                results["scan"].append(f"→ Système détecté : {os_detected}")

        if vuln_scan:
            found_vulns = False
            vuln_data.append("→ Résultats vulnérabilités (hostscript) :")

            if "hostscript" in nm[target]:
                print("\n[!] Vulnérabilités détectées (host):")
                for script in nm[target]["hostscript"]:
                    found_vulns = True
                    print(f"  - {script['id']} → {script['output']}")
                    results["scan"].append(f"  - {script['id']} → {script['output']}")
                    vuln_data.append(f"  - {script['id']} → {script['output']}")

            for proto in nm[target].all_protocols():
                for port in nm[target][proto]:
                    scripts = nm[target][proto][port].get("script", {})
                    for script_name, result in scripts.items():
                        found_vulns = True
                        print(f"[!] {script_name} sur port {port} → {result}")
                        results["scan"].append(f"  - {script_name} (port {port}) → {result}")
                        vuln_data.append(f"  - {script_name} (port {port}) → {result}")

            if not found_vulns:
                print("\n[✓] Aucun service vulnérable détecté.")
                results["scan"].append("→ Aucun service vulnérable détecté.")
                vuln_data.append("→ Aucun service vulnérable détecté.")

        return table, vuln_data

    except Exception as e:
        print(f"[!] Erreur pendant le scan : {e}")
        return [], []
