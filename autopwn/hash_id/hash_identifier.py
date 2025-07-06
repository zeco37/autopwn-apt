import requests
from bs4 import BeautifulSoup

def crack_md5_online(hash_value):
    try:
        url = f"https://md5hashing.net/hash/md5/{hash_value}"
        headers = {
            "User-Agent": "Mozilla/5.0"
        }

        print(f"[🔗] Accès à l'URL : {url}")
        response = requests.get(url, headers=headers, timeout=10)

        if response.status_code != 200:
            print(f"[✘] Erreur HTTP : {response.status_code}")
            return

        soup = BeautifulSoup(response.content, "html.parser")
        decoded_span = soup.find("span", id="decodedValue")

        if decoded_span:
            value = decoded_span.text.strip()
            if value:
                print(f"[✓] Hash trouvé : {value}")
                return
        print("[✘] open the link above")

    except Exception as e:
        print(f"[!] Erreur lors du déchiffrement : {str(e)}")
