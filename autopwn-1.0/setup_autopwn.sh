#!/bin/bash

# Variables
INSTALL_DIR="/opt/autopwn"
LAUNCHER="/usr/local/bin/autopwn"
REPO_URL="https://github.com/zeco37/autopwn-apt.git"
REPO_SUBDIR="autopwn-1.0"
MAIN_FILE="autopwn.py"
REQUIRED_FILES=("autopwn.py" "setup_autopwn.sh")
REQUIRED_DIRS=("scanner" "spoofing" "payloads" "core" "listener" "sniffer" "dns_enum" "web_tech" "bruteforce" "exploits" "hash_id")

echo "🔧 AutoPwn Setup – Lancement global sans python3"

# Create install dir if doesn't exist
mkdir -p "$INSTALL_DIR"

# Vérification des fichiers
cd "$INSTALL_DIR" 2>/dev/null || exit 1
MISSING=0

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

# Si fichiers manquants → demande de réinstallation
if [[ "$MISSING" == 1 ]]; then
    echo -e "\n⚠️ Des fichiers sont manquants ou modifiés. Voulez-vous réinstaller AutoPwn ? (yes/no)"
    read -r answer
    if [[ "$answer" == "yes" ]]; then
        echo "[+] Téléchargement et installation d'AutoPwn…"
        rm -rf "$INSTALL_DIR"
        git clone "$REPO_URL" "$INSTALL_DIR"
        cd "$INSTALL_DIR/$REPO_SUBDIR" || { echo "[-] Erreur : Chemin invalide."; exit 1; }

        # Déplacer tous les fichiers vers /opt/autopwn
        mv * ../..
        cd ../..
        rm -rf "$INSTALL_DIR/$REPO_SUBDIR"

        if [[ ! -f "$MAIN_FILE" ]]; then
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

# Création du lanceur global
echo "[*] Création du lanceur global…"
echo -e "#!/bin/bash\npython3 \"$INSTALL_DIR/$MAIN_FILE\" \"\$@\"" | sudo tee "$LAUNCHER" >/dev/null
sudo chmod +x "$LAUNCHER"

echo -e "✅ Installation terminée. Vous pouvez lancer AutoPwn avec : \033[1mautopwn\033[0m"
