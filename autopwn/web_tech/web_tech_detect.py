import builtwith
import requests
import re

def detect_technologies(url):
    if not url.startswith("http"):
        url = "http://" + url

    print(f"🌐 Analyse de {url}...")

    try:
        response = requests.get(url, timeout=10)
        headers = response.headers
        html = response.text.lower()

        techs = set()

        # -------- Analyse avec builtwith
        try:
            bw = builtwith.parse(url)
            for category, items in bw.items():
                for item in items:
                    techs.add(f"{category}: {item}")
        except Exception:
            pass  # on continue

        # -------- Analyse des headers
        server = headers.get("Server")
        powered = headers.get("X-Powered-By")

        if server:
            techs.add(f"Server: {server}")
        if powered:
            techs.add(f"X-Powered-By: {powered}")

        # -------- Détection manuelle dans le HTML
        if "wp-content" in html or "wordpress" in html:
            techs.add("CMS: WordPress")
        if "drupal.js" in html:
            techs.add("CMS: Drupal")
        if "joomla" in html:
            techs.add("CMS: Joomla")
        if "shopify" in html:
            techs.add("E-commerce: Shopify")
        if "react" in html or "react-dom" in html:
            techs.add("JS: React")
        if "vue.js" in html:
            techs.add("JS: Vue.js")
        if "angular" in html:
            techs.add("JS: Angular")
        if "jquery" in html:
            techs.add("JS: jQuery")

        # -------- Affichage
        if techs:
            print("\n🧠 Technologies détectées :")
            for t in techs:
                print(f"  → {t}")
        else:
            print("❌ Aucune technologie détectée.")
    except requests.exceptions.RequestException as e:
        print(f"[!] Erreur de connexion : {e}")
    except Exception as e:
        print(f"[!] Erreur lors de l'analyse : {e}")
