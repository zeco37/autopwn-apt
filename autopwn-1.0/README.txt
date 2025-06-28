##############################################################
#                       AutoPwn - 1.0                        #
#            Outil d'Automatisation de Pentesting            #
#                Auteur : zakaria / zeco37                   #
##############################################################

📌 DESCRIPTION :
AutoPwn est un outil en ligne de commande développé en Python 3, 
conçu pour automatiser plusieurs étapes de test d'intrusion (pentest).
Il propose une interface interactive permettant d'exécuter différents 
modules (scan, sniffing, spoofing, brute force, payloads, etc.)

📁 STRUCTURE DU PROJET :
Le projet est structuré comme suit :

├── autopwn.py             → Script principal
├── setup_autopwn.sh       → Script d'installation global
├── scanner/               → Module de scan réseau
├── spoofing/              → Module d'ARP spoofing
├── sniffing/              → Module de sniff réseau
├── bruteforce/            → Brute force (DIRS)
├── exploits/              → Scripts d'exploitation
├── payloads/              → Générateurs de payloads personnalisés
├── core/                  → Fonctions internes & helpers
├── listener/              → Listener pour payloads Meterpreter
├── dns_enum/              → Enumération DNS
├── hash_id/               → Identification de hash
├── web_tech/              → Détection de technologies web

🛠 INSTALLATION :
1. Exécutez le script d'installation automatique :
   $ chmod +x setup_autopwn.sh
   $ sudo ./setup_autopwn.sh

2. Cela installera le script dans /opt/autopwn et créera un alias global :
   ➤ Commande utilisable depuis n'importe où : `autopwn`

3. En cas de suppression ou de fichier manquant, le script propose 
   une réinstallation automatique à partir du repo GitHub.

📋 PRÉREQUIS :
- Python 3.x
- OS testé : Kali Linux (fonctionne également sur Debian)

✅ UTILISATION :
Lancez simplement la commande :

   $ sudo autopwn

Puis suivez l’interface et choisissez les modules que vous souhaitez utiliser.

🌐 GITHUB :
https://github.com/zeco37/autopwn-apt

📌 AUTEUR :
Zakaria BELALIOUI - zeco37
Contact : zecodscrd@gmail.com

📅 VERSION :
v1.0 – Juin 2025

##############################################################
