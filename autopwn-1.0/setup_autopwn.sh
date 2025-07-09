#!/bin/bash

# Variables
INSTALL_DIR="/opt/autopwn"
LAUNCHER="/usr/local/bin/autopwn"
REPO_URL="https://github.com/zeco37/autopwn-apt.git"
REPO_SUBDIR="autopwn-1.0"
MAIN_FILE="autopwn.py"
REQUIRED_FILES=("autopwn.py" "setup_autopwn.sh")
REQUIRED_DIRS=("scanner" "spoofing" "payloads" "core" "listener" "sniffer" "dns_enum" "web_tech" "bruteforce" "hash_id")

REQUIRED_PY_MODULES=(requests concurrent.futures hashlib re dns subprocess os nmap time sys threading builtwith scapy colorama rich bs4)

echo "\n🔧 AutoPwn Setup – Lancement global..."

mkdir -p "$INSTALL_DIR"

# Vérification des fichiers
MISSING=0
cd "$INSTALL_DIR" 2>/dev/null || exit 1

for f in "${REQUIRED_FILES[@]}"; do
    if [[ ! -f "$f" ]]; then
        echo "[!] Fichier manquant : $f"
        MISSING=1
    fi
done

for d in "${REQUIRED_DIRS[@]}"; do
    if [[ ! -d "$d" ]]; then
        echo "[!] Dossier manquant : $d"
        MISSING=1
    fi
done

# Si fichiers manquants → re-clone complet
if [[ "$MISSING" == 1 ]]; then
    echo -e "\n⚠️ Des fichiers sont manquants ou modifiés. Voulez-vous réinstaller AutoPwn ? (yes/no)"
    read -r answer
    if [[ "$answer" == "yes" ]]; then
        echo "[+] Téléchargement et installation d'AutoPwn…"
        cd /opt || { echo "[-] Erreur : Impossible d'accéder à /opt"; exit 1; }
        sudo rm -rf "$INSTALL_DIR"
        git clone "$REPO_URL" "$INSTALL_DIR" || { echo "[-] Erreur : Clone échoué."; exit 1; }

        if [[ ! -d "$INSTALL_DIR/$REPO_SUBDIR" ]]; then
            echo "[-] Erreur : Dossier $REPO_SUBDIR non trouvé après le clonage."
            exit 1
        fi

        # Déplacer contenu du sous-dossier vers /opt/autopwn
        mv "$INSTALL_DIR/$REPO_SUBDIR"/* "$INSTALL_DIR/"
        rm -rf "$INSTALL_DIR/$REPO_SUBDIR"

        if [[ ! -f "$INSTALL_DIR/$MAIN_FILE" ]]; then
            echo "[-] Erreur : Le fichier principal $MAIN_FILE est introuvable après le clonage."
            exit 1
        fi
    else
        echo "✖️ Installation annulée."
        exit 0
    fi
else
    echo "✅ AutoPwn est déjà installé et à jour."
fi

# Vérification et installation des requirements Python
echo "\n📦 Vérification des modules Python..."
for mod in "${REQUIRED_PY_MODULES[@]}"; do
    python3 -c "import $mod" 2>/dev/null || pip install $mod || pip3 install $mod || sudo apt install -y python3-$mod
done

# Création du lanceur global
echo "[*] Création du lanceur global..."
echo -e "#!/bin/bash\npython3 \"$INSTALL_DIR/$MAIN_FILE\" \"\$@\"" | sudo tee "$LAUNCHER" >/dev/null
sudo chmod +x "$LAUNCHER"

echo -e "✅ Installation terminée. Vous pouvez lancer AutoPwn avec : \033[1mautopwn\033[0m"
