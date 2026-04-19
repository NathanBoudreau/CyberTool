import hashlib
import os
import threading

WORDLISTS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'wordlists')

USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
]
_ua_lock = threading.Lock()
_ua_index = 0


def next_user_agent():
    global _ua_index
    with _ua_lock:
        ua = USER_AGENTS[_ua_index % len(USER_AGENTS)]
        _ua_index += 1
    return ua


def load_wordlist(filename, custom_path=None):
    path = custom_path if custom_path else os.path.join(WORDLISTS_DIR, filename)
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            return [l.strip() for l in f if l.strip() and not l.startswith('#')]
    except FileNotFoundError:
        return None


def hash_word(word, algo):
    try:
        b = word.encode('utf-8', errors='replace')
        if algo == 'md5':    return hashlib.md5(b).hexdigest()
        if algo == 'sha1':   return hashlib.sha1(b).hexdigest()
        if algo == 'sha256': return hashlib.sha256(b).hexdigest()
        if algo == 'sha512': return hashlib.sha512(b).hexdigest()
    except Exception:
        pass
    return None


def detect_hash_algo(hash_val):
    hex_chars = set('0123456789abcdef')
    if not all(c in hex_chars for c in hash_val.lower()):
        return None
    return {32: 'md5', 40: 'sha1', 64: 'sha256', 128: 'sha512'}.get(len(hash_val))


def make_proxies(proxy_url):
    if not proxy_url:
        return None
    return {'http': proxy_url, 'https': proxy_url}
