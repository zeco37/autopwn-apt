# modules/hash_id.py
import re

HASH_PATTERNS = [
    ("MD5", r"^[a-f0-9]{32}$"),
    ("SHA-1", r"^[a-f0-9]{40}$"),
    ("SHA-256", r"^[a-f0-9]{64}$"),
    ("SHA-512", r"^[a-f0-9]{128}$"),
    ("bcrypt", r"^\$2[aby]?\$.{56}$"),
    ("NTLM", r"^[A-F0-9]{32}$"),
    ("MySQL5", r"^\*[A-F0-9]{40}$"),
    ("DES(Unix)", r"^[a-zA-Z0-9/.]{13}$"),
    ("LDAP MD5", r"^\{MD5\}[a-zA-Z0-9+/=]+$"),
    ("LDAP SHA", r"^\{SHA\}[a-zA-Z0-9+/=]+$"),
    ("CRC32", r"^[A-F0-9]{8}$"),
    ("RIPEMD-160", r"^[a-f0-9]{40}$"),
]

def identify_hash(hash_value):
    matches = []
    for algo, pattern in HASH_PATTERNS:
        if re.fullmatch(pattern, hash_value, re.IGNORECASE):
            matches.append(algo)
    return matches
