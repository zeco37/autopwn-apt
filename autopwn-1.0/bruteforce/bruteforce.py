import requests
import concurrent.futures
import hashlib
import re

headers = {"User-Agent": "Mozilla/5.0"}
visited_hashes = set()
test_path_cache = set()
printed_tags = set()

def get_response_info(url):
    try:
        r = requests.get(url, timeout=5, headers=headers, allow_redirects=True)
        return r, r.status_code
    except requests.exceptions.RequestException:
        return None, None

def extract_fingerprint(response):
    headers_of_interest = ['Content-Type', 'Content-Length', 'Server']
    fp = tuple((h, response.headers.get(h)) for h in headers_of_interest)
    size = len(response.content)
    content_hash = hashlib.sha256(response.content).hexdigest()
    tags = count_html_tags(response.text)
    return fp, size, content_hash, tags

def count_html_tags(html):
    return len(re.findall(r'</?[a-zA-Z]+', html))

def get_baseline_info(base_url):
    fake_path = f"{base_url.rstrip('/')}/fake_654321_notfound"
    r, status = get_response_info(fake_path)

    if r:
        size = len(r.content)
        tags = count_html_tags(r.text)

        print(f"[✔] Test de baseline: Status {status} - Size: {size} - Tags: {tags}")
        if size < 50:
            print("[⚠] Baseline très petite. Risque de faux positifs.")

        return extract_fingerprint(r)

    print("[⛔] Aucune réponse reçue pour tester la baseline.")
    return None, 0, None, 0

def test_path(url, baseline_fp, baseline_size, baseline_hash, baseline_tags):
    if url in test_path_cache:
        return None
    test_path_cache.add(url)

    r, status_code = get_response_info(url)
    if r and status_code not in [403, 404]:
        current_fp, size, content_hash, tags = extract_fingerprint(r)

        if current_fp == baseline_fp and (abs(size - baseline_size) < 50 or content_hash == baseline_hash):
            return None

        if tags in printed_tags and tags != 0:
            return None

        visited_hashes.add(content_hash)
        printed_tags.add(tags)
        print(f"[{status_code}] {url}  → Size: {size} | Tags: {tags}")
        return (url, status_code, size)
    return None

def bruteforce_dirs(base_url, wordlist_path, visited=None, level=0, max_threads=200):
    if not base_url.startswith("http"):
        base_url = "http://" + base_url
    if visited is None:
        visited = set()

    indent = "    " * level
    print(f"\n📁 [DIRS] Bruteforce sur : {base_url}")
    baseline_fp, baseline_size, baseline_hash, baseline_tags = get_baseline_info(base_url)
    print(f"{indent}↪ Baseline size: {baseline_size} bytes | Tags: {baseline_tags}")

    # ❗️ما نوقفش الفحص إذا كانت baseline غير متوفرة
    if baseline_fp is None:
        print(f"{indent}[⚠] Baseline absente. Le scan continue quand même...\n")

    try:
        with open(wordlist_path, "r") as f:
            words = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print("[!] Fichier introuvable.")
        return

    targets = []
    for word in words:
        url = f"{base_url.rstrip('/')}/{word.lstrip('/')}"
        if url not in visited:
            visited.add(url)
            targets.append(url)

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        results = executor.map(lambda u: test_path(u, baseline_fp, baseline_size, baseline_hash, baseline_tags), targets)

    for result in results:
        if result:
            url, code, size = result
            word = url.rstrip('/').split('/')[-1]
            if code == 200 and '.' not in word and size > 100:
                bruteforce_dirs(url, wordlist_path, visited, level + 1, max_threads)
