import json
import os

results = {
    "scan": [],
    "sniff": [],
    "spoof": [],
    "smb": []
}

SAVE_PATH = "core/results.json"

def load_results():
    if os.path.exists(SAVE_PATH):
        try:
            with open(SAVE_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
                for key in results:
                    if key in data:
                        results[key] = data[key]
        except:
            pass  # Ignorer si fichier corrompu

def save_results():
    try:
        with open(SAVE_PATH, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"[!] Erreur lors de la sauvegarde : {e}")
