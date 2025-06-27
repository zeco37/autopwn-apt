#!/bin/bash

# Chemin du script en cours
SCRIPT_PATH="$(readlink -f "$0")"
SCRIPT_DIR="$(dirname "$SCRIPT_PATH")"

# Vérifier si autopwn.py existe dans le même dossier
if [ ! -f "$SCRIPT_DIR/autopwn.py" ]; then
    echo "❌ Erreur : autopwn.py est introuvable dans $SCRIPT_DIR"
    echo "Assurez-vous que autopwn.py et ce script sont dans le même dossier."
    exit 1
fi

# Copier le projet vers /opt/autopwn
echo "📦 Copie du projet dans /opt/autopwn ..."
sudo mkdir -p /opt/autopwn
sudo cp -r "$SCRIPT_DIR/"* /opt/autopwn/

# Créer le lanceur global
echo "⚙️ Création du lanceur global /usr/local/bin/autopwn ..."
echo '#!/bin/bash' | sudo tee /usr/local/bin/autopwn > /dev/null
echo 'python3 /opt/autopwn/autopwn.py "$@"' | sudo tee -a /usr/local/bin/autopwn > /dev/null
sudo chmod +x /usr/local/bin/autopwn

echo "✅ Installation terminée ! Vous pouvez exécuter AutoPwn depuis n’importe où avec la commande : autopwn"
