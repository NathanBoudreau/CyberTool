from modules.utils import load_wordlist, hash_word, detect_hash_algo


def stream_crack(hash_val, algo='auto', custom_wordlist=None):
    if not hash_val:
        yield {'type': 'error', 'message': 'No hash provided'}
        return

    hash_val = hash_val.strip().lower()

    if algo == 'auto':
        algo = detect_hash_algo(hash_val)
        if not algo:
            yield {'type': 'error', 'message': 'Cannot auto-detect hash type — specify algorithm manually'}
            return
        yield {'type': 'info', 'message': f'Auto-detected: {algo.upper()} ({len(hash_val)} hex chars)'}

    if algo not in ('md5', 'sha1', 'sha256', 'sha512'):
        yield {'type': 'error', 'message': f'Unsupported algorithm: {algo}'}
        return

    passwords = load_wordlist('passwords.txt', custom_path=custom_wordlist)
    if passwords is None:
        yield {'type': 'error', 'message': 'Wordlist not found — check wordlists/passwords.txt'}
        return

    # Deduplicate while preserving order
    seen = set()
    passwords = [p for p in passwords if not (p in seen or seen.add(p))]

    total = len(passwords)
    yield {'type': 'info', 'message': f'Loaded {total} passwords · cracking {algo.upper()}...'}

    for i, word in enumerate(passwords):
        h = hash_word(word, algo)
        if h == hash_val:
            yield {'type': 'found', 'password': word, 'algo': algo, 'hash': hash_val}
            yield {'type': 'complete', 'found': True, 'tried': i + 1, 'total': total}
            return

        # Fix #9: yield progress including final batch
        if i % 20 == 0 or i == total - 1:
            pct = int(((i + 1) / total) * 100)
            yield {'type': 'progress', 'percent': pct, 'tried': i + 1, 'total': total, 'current': word}

    yield {'type': 'complete', 'found': False, 'tried': total, 'total': total}
