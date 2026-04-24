import uuid
import requests
import concurrent.futures
import urllib3
from modules.utils import load_wordlist, next_user_agent, make_proxies

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

INTERESTING_CODES = {200, 201, 204, 301, 302, 307, 308, 401, 403, 405, 500}

# How similar (in bytes) a response size must be to the baseline to be considered a soft-404.
_SIZE_TOLERANCE = 10


def _detect_baseline(session, base_url):
    """Request a guaranteed-nonexistent path to detect soft-404 behaviour.

    Returns (status, size) of the canary response, or (None, None) on error.
    """
    canary = f"{base_url}/{uuid.uuid4().hex}/{uuid.uuid4().hex}"
    try:
        resp = session.get(canary, timeout=5, allow_redirects=False)
        return resp.status_code, len(resp.content)
    except Exception:
        return None, None


def _is_baseline_match(status, size, baseline_status, baseline_size):
    """Return True if this response looks like the soft-404 baseline."""
    if baseline_status is None:
        return False
    if status != baseline_status:
        return False
    # Allow a small size window to account for minor dynamic content differences.
    return abs(size - baseline_size) <= _SIZE_TOLERANCE


def stream_scan(base_url, state, custom_wordlist=None, proxy=None, verify_ssl=False,
                recursive=False, max_depth=2, extensions=None):
    if not base_url.startswith(('http://', 'https://')):
        base_url = 'http://' + base_url

    base_url = base_url.rstrip('/')

    paths = load_wordlist('common_dirs.txt', custom_path=custom_wordlist)
    if paths is None:
        yield {'type': 'error', 'message': 'Directory wordlist not found at wordlists/common_dirs.txt'}
        return

    # Fix #18: build extension list from parameter
    ext_list = ['']
    if extensions:
        ext_list += [f'.{e.lstrip(".")}' for e in extensions.split(',') if e.strip()]

    # Expand paths with extensions
    expanded = []
    for p in paths:
        for ext in ext_list:
            expanded.append(p + ext)
    paths = expanded

    all_found = []
    scanned_urls = set()

    def _scan_base(target_url, depth=0):
        nonlocal paths
        total = len(paths)
        found = []
        checked = 0

        yield {'type': 'info', 'message': f'Scanning {total} paths on {target_url}...' + (f' [depth {depth}]' if depth else '')}

        session = requests.Session()
        session.verify = verify_ssl
        # Fix #18: rotate user agents
        session.headers['User-Agent'] = next_user_agent()
        # Fix #17: apply proxy
        if proxy:
            session.proxies = make_proxies(proxy)

        baseline_status, baseline_size = _detect_baseline(session, target_url)

        def check(path):
            url = f"{target_url}/{path.lstrip('/')}"
            if url in scanned_urls:
                return url, None, 0, ''
            scanned_urls.add(url)
            try:
                resp = session.get(url, timeout=5, allow_redirects=False)
                status = resp.status_code
                size = len(resp.content)
                if _is_baseline_match(status, size, baseline_status, baseline_size):
                    return url, None, 0, ''
                return url, status, size, resp.headers.get('Content-Type', '')
            except Exception:
                return url, None, 0, ''

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(check, path): path for path in paths}
            for future in concurrent.futures.as_completed(futures):
                url, status, size, ctype = future.result()
                checked += 1

                if status and status in INTERESTING_CODES:
                    entry = {'url': url, 'status': status, 'size': size, 'type': ctype}
                    found.append(entry)
                    all_found.append(entry)
                    yield {'type': 'found', 'url': url, 'status': status, 'size': size, 'content_type': ctype}

                if checked % 50 == 0 or checked == total:
                    yield {
                        'type': 'progress',
                        'checked': checked,
                        'total': total,
                        'percent': int(checked / total * 100)
                    }

        # Fix #20: recursive scan on discovered directories
        if recursive and depth < max_depth:
            dir_urls = [e['url'] for e in found
                        if e['status'] in (200, 301, 302, 307, 308, 403)
                        and not e['url'].rstrip('/').endswith(tuple(
                            f'.{x}' for x in ['php', 'asp', 'aspx', 'html', 'htm', 'js', 'css', 'txt', 'xml', 'json']
                        ))]
            for dir_url in dir_urls[:10]:  # cap recursive targets to avoid runaway
                yield from _scan_base(dir_url.rstrip('/'), depth=depth + 1)

        return found

    yield from _scan_base(base_url)

    state['target_url'] = base_url
    yield {'type': 'complete', 'found': all_found, 'total_checked': len(scanned_urls)}
