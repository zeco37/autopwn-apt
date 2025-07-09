# modules/dns_enum.py
import dns.resolver
import dns.query
import dns.zone

def try_zone_transfer(domain, nameservers):
    print("\n=== 🔓 Vérification de Zone Transfer (AXFR) ===")
    for ns in nameservers:
        ns = ns.rstrip('.')
        try:
            z = dns.zone.from_xfr(dns.query.xfr(ns, domain, timeout=5))
            names = z.nodes.keys()
            print(f"[+] Zone Transfer RÉUSSI depuis : {ns}")
            for n in names:
                print(f"  - {z[n].to_text(n)}")
        except Exception as e:
            print(f"[-] Zone Transfer échoué sur {ns} : {e}")

def enumerate_dns(domain):
    print(f"\n=== DNS Enumeration pour : {domain} ===")
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
    results = []

    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            for rdata in answers:
                results.append(f"[{record_type}] {rdata.to_text()}")
        except Exception as e:
            results.append(f"[{record_type}] Erreur ou pas de données : {e}")

    print("\nRésultats :\n")
    for line in results:
        print(line)

    # 🔎 Extraction des NS et tentative de Zone Transfer
    try:
        ns_answers = dns.resolver.resolve(domain, 'NS')
        ns_records = [rdata.to_text() for rdata in ns_answers]
        try_zone_transfer(domain, ns_records)
    except:
        print("\n[!] Impossible d'extraire les NS pour tester le Zone Transfer.")

    # 💾 Sauvegarde optionnelle
    save = input("\nSauvegarder dans un fichier ? (y/n): ").strip().lower()
    if save == 'y':
        filename = f"dns_enum_{domain.replace('.', '_')}.txt"
        with open(filename, "w") as f:
            f.write('\n'.join(results))
        print(f"[+] Sauvegardé sous: {filename}")
