import requests
import concurrent.futures
import hashlib
import re

MAX_THREADS = 100
headers = {"User-Agent": "Mozilla/5.0"}

visited_hashes = set()
test_path_cache = set()
printed_tags = set()  # ⬅️ باش نمنعو التكرار حسب عدد Tags


def get_response_info(url):
    try:
        r = requests.get(url, timeout=5, headers=headers, allow_redirects=True)
        return r, r.status_code
    except requests.exceptions.RequestException:
        return None, None


def extract_fingerprint(response):
    headers_of_interest = ['Content-Type', 'Content-Length', 'Server']
    fp = tuple((h, response.headers.get(h)) for h in headers_of_interest)
    size = int(response.headers.get('Content-Length', 0))
    content_hash = hashlib.sha256(response.content).hexdigest()
    tags = count_html_tags(response.text)
    return fp, size, content_hash, tags


def count_html_tags(html):
    return len(re.findall(r'</?[a-zA-Z]+', html))


def get_baseline_info(base_url):
    fake_path = f"{base_url.rstrip('/')}/fake_654321_notfound"
    r, _ = get_response_info(fake_path)
    if r:
        return extract_fingerprint(r)
    return None, 0, None, 0


def test_path(url, baseline_fp, baseline_size, baseline_hash, baseline_tags):
    if url in test_path_cache:
        return None
    test_path_cache.add(url)

    r, status_code = get_response_info(url)
    if r and status_code not in [403, 404]:
        current_fp, size, content_hash, tags = extract_fingerprint(r)

        # ⛔️ حذف الردود لي مطابقة لصفحة الخطأ
        if current_fp == baseline_fp and (abs(size - baseline_size) < 50 or content_hash == baseline_hash):
            return None

        # ✅ حذف الردود المكررة من حيث عدد Tags
        if tags in printed_tags:
            return None

        visited_hashes.add(content_hash)
        printed_tags.add(tags)
        print(f"[{status_code}] {url}  → Size: {size} | Tags: {tags}")
        return (url, status_code)
    return None


def bruteforce_dirs(base_url, wordlist_path, visited=None, level=0):
    if not base_url.startswith("http"):
        base_url = "http://" + base_url
    if visited is None:
        visited = set()

    indent = "    " * level
    print(f"\n📁 [DIRS] Bruteforce sur : {base_url}")
    baseline_fp, baseline_size, baseline_hash, baseline_tags = get_baseline_info(base_url)
    print(f"{indent}↪ Baseline size: {baseline_size} bytes | Tags: {baseline_tags}")

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

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        results = executor.map(lambda u: test_path(u, baseline_fp, baseline_size, baseline_hash, baseline_tags), targets)

    for result in results:
        if result:
            url, code = result
            word = url.rstrip('/').split('/')[-1]
            if code == 200 and '.' not in word:
                bruteforce_dirs(url, wordlist_path, visited, level + 1)
