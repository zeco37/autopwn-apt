# 🛠️ AutoPwn - v1.0

**AutoPwn** est un outil de pentesting automatisé développé en Python 3, permettant d'exécuter divers modules de sécurité à travers une interface CLI professionnelle, simple et puissante.

---

## 🚀 Fonctionnalités Principales

- 🔎 **Scan de Ports** (TCP, OS, détection de vulnérabilités)
- 🕵️‍♂️ **Sniffing de trafic réseau**
- 🧑‍💻 **ARP Spoofing** (MITM)
- 🔐 **Bruteforce** (DIRS)
- 🧬 **Identification de Hash**
- 🌐 **Énumération DNS**
- 🏗 **Détection de technologies Web**
- 💣 **Générateur de payloads** (reverse shell, .exe, etc.)
- 🎧 **Listener Meterpreter** personnalisé
- 💥 **Modules d’exploitation** (exploits personnalisés)

---

## 📁 Structure du Projet
```bash
autopwn-1.0/
├── autopwn.py # Script principal (menu CLI)
├── setup_autopwn.sh # Script d'installation global
├── scanner/ # Scan de ports, vulnérabilités
├── spoofing/ # ARP Spoofing / MITM
├── sniffer/ # Sniffing de paquets
├── bruteforce/ # Bruteforce FTP, SSH, HTTP...
├── exploits/ # Modules d’exploitation
├── payloads/ # Générateur de payloads
├── core/ # Fonctions internes de base
├── listener/ # Listener Meterpreter custom
├── dns_enum/ # Énumération DNS
├── hash_id/ # Identification de hash
├── web_tech/ # Détection de technologies Web
```
---

### 📦 Dépendances

AutoPwn utilise Python 3. Assurez-vous que `pip` est installé.

Modules Python requis :
- `nmap`, `requests`, `bs4`, `scapy`, `colorama`, `rich`, `dnspython`, `builtwith`

> Ces modules seront automatiquement installés lors du setup.

### 🛠️ Installation automatique :

```bash
git clone https://github.com/zeco37/autopwn-apt.git
cd autopwn-apt/autopwn-1.0
chmod +x setup_autopwn.sh
sudo ./setup_autopwn.sh
# Une fois installé :
  $ sudo autopwn
```
### 🧠 À propos

🧑‍💻 **Développé par** : Zakaria BELALIOUI

📧 **Contact** : zecodscrd@gmail.com

📜 **Licence** : MIT

### 📸 Aperçu

![image](https://github.com/user-attachments/assets/60b1fccd-c6dc-40f8-826e-6aa90d78c0e1)

### ❗ Avertissement

Cet outil est à but éducatif uniquement. L’auteur décline toute responsabilité en cas d’usage abusif ou illégal.

---

© 2025 Zakaria BEALIOUI. Tous droits réservés.

Ce projet est distribué sous la licence MIT. Voir le fichier LICENSE pour plus d’informations.

