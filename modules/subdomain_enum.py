import socket
import concurrent.futures
import requests
from modules.utils import load_wordlist, next_user_agent

# Known takeover fingerprints: service → response substring indicating unclaimed
TAKEOVER_FINGERPRINTS = {
    'github':    "There isn't a GitHub Pages site here",
    'heroku':    'No such app',
    'shopify':   "Sorry, this shop is currently unavailable",
    'fastly':    'Fastly error: unknown domain',
    'pantheon':  "404 error unknown site",
    'tumblr':    'Whatever you were looking for doesn\'t currently exist',
    'wpengine':  'The site you were looking for couldn\'t be found',
    'ghost':     'The thing you were looking for is no longer here',
    'surge':     'project not found',
    'azure':     'Error 404 - Web app not found',
    'amazonaws': 'NoSuchBucket',
    'bitbucket': 'Repository not found',
    'zendesk':   'Help Center Closed',
    'readme':    'Project doesnt exist',
    'cargo':     'If you\'re moving your domain away from Cargo',
    'feedpress': 'The feed has not been found',
    'helprace':  'Alias not configured',
    'uservoice': 'This UserVoice subdomain is currently available',
    'statuspage': 'You are being redirected',
}


def _check_takeover(fqdn, ip):
    """Return takeover hint string if subdomain appears vulnerable, else None."""
    try:
        resp = requests.get(
            f'http://{fqdn}',
            timeout=5,
            allow_redirects=True,
            verify=False,
            headers={'User-Agent': next_user_agent()}
        )
        body = resp.text.lower()
        for service, fingerprint in TAKEOVER_FINGERPRINTS.items():
            if fingerprint.lower() in body:
                return f'Possible {service} takeover'
    except Exception:
        pass
    return None


def stream_scan(target, state, custom_wordlist=None):
    words = load_wordlist('subdomains.txt', custom_path=custom_wordlist)
    if words is None:
        yield {'type': 'error', 'message': 'Subdomain wordlist not found at wordlists/subdomains.txt'}
        return

    total = len(words)
    found = []
    checked = 0

    yield {'type': 'info', 'message': f'Checking {total} subdomains against {target}...'}

    def check(sub):
        fqdn = f"{sub}.{target}"
        try:
            ip = socket.gethostbyname(fqdn)
            # Fix #15: check for subdomain takeover
            takeover = _check_takeover(fqdn, ip)
            return fqdn, ip, takeover
        except socket.gaierror:
            return fqdn, None, None
        except Exception:
            return fqdn, None, None

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(check, sub): sub for sub in words}
        for future in concurrent.futures.as_completed(futures):
            fqdn, ip, takeover = future.result()
            checked += 1

            if ip:
                entry = {'subdomain': fqdn, 'ip': ip, 'takeover': takeover}
                found.append(entry)
                yield {'type': 'found', 'subdomain': fqdn, 'ip': ip, 'takeover': takeover}

            if checked % 50 == 0 or checked == total:
                yield {
                    'type': 'progress',
                    'checked': checked,
                    'total': total,
                    'percent': int(checked / total * 100)
                }

    state['subdomains'] = found
    if not state.get('target_domain'):
        state['target_domain'] = target

    yield {'type': 'complete', 'found': found, 'total_checked': total}
