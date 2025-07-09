import requests
from bs4 import BeautifulSoup
import subprocess

def crack_md5_online(hash_value):
    try:
        url = f"https://md5hashing.net/hash/md5/{hash_value}"
        headers = {
            "User-Agent": "Mozilla/5.0"
        }

        print(f"[🌐] Test via md5hashing.net...")
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code != 200:
            print(f"[✘] Erreur HTTP : {response.status_code}")
            return None

        soup = BeautifulSoup(response.text, "html.parser")
        boxes = soup.find_all("div", class_="hash-box")

        for box in boxes:
            text = box.get_text(strip=True)
            if text and hash_value not in text:
                return text

        print("[x] Aucun résultat via md5hashing.net.")
        return None

    except Exception as e:
        print(f"[!] Erreur md5hashing.net : {e}")
        return None


def crackstation(hash_value):
    try:
        print("[🌐] Test via crackstation.net...")
        url = "https://crackstation.net/"
        session = requests.Session()
        data = {
            "hashes": hash_value,
            "submit": "Crack Hashes"
        }
        response = session.post(url, data=data, timeout=15)
        soup = BeautifulSoup(response.text, "html.parser")
        result_div = soup.find("div", class_="results")

        if result_div:
            text = result_div.get_text()
            if ":" in text:
                return text.split(":")[-1].strip()

        print("[x] Aucun résultat via crackstation.net.")
        return None

    except Exception as e:
        print(f"[!] Erreur crackstation.net : {e}")
        return None


def john_local(hash_value):
    try:
        print("[⚙️] Test via John the Ripper...")
        with open("temp_hash.txt", "w") as f:
            f.write(f"{hash_value}\n")

        result = subprocess.run(["john", "temp_hash.txt"], capture_output=True, text=True)
        output = subprocess.run(["john", "--show", "temp_hash.txt"], capture_output=True, text=True)

        if ":" in output.stdout:
            return output.stdout.split(":")[1].strip()
        return None

    except Exception as e:
        print(f"[!] Erreur John: {e}")
        return None


def auto_crack_hash(hash_value):
    for method in [crack_md5_online, crackstation, john_local]:
        result = method(hash_value)
        if result:
            print(f"[✓] Hash trouvé : {result}")
            return result
    print("[⚠] Aucun résultat trouvé dans les outils disponibles.")
    return None
