import requests
import socket
from urllib.parse import urlparse
import urllib3
from modules.utils import next_user_agent, make_proxies

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SECURITY_HEADERS = [
    {
        'name': 'Strict-Transport-Security',
        'description': 'Forces HTTPS — prevents downgrade attacks',
        'recommended': 'max-age=31536000; includeSubDomains',
        'type': 'required',
    },
    {
        'name': 'Content-Security-Policy',
        'description': 'Controls which resources the browser can load',
        'recommended': "default-src 'self'",
        'type': 'required',
    },
    {
        'name': 'X-Frame-Options',
        'description': 'Prevents clickjacking attacks',
        'recommended': 'DENY or SAMEORIGIN',
        'type': 'required',
    },
    {
        'name': 'X-Content-Type-Options',
        'description': 'Prevents MIME-type sniffing',
        'recommended': 'nosniff',
        'type': 'required',
    },
    {
        'name': 'Referrer-Policy',
        'description': 'Controls referrer information sent with requests',
        'recommended': 'strict-origin-when-cross-origin',
        'type': 'required',
    },
    {
        'name': 'Permissions-Policy',
        'description': 'Controls browser feature access',
        'recommended': 'camera=(), microphone=(), geolocation=()',
        'type': 'required',
    },
    {
        'name': 'X-XSS-Protection',
        'description': 'Legacy XSS filter (deprecated but still checked)',
        'recommended': '1; mode=block',
        'type': 'optional',
    },
    {
        'name': 'Server',
        'description': 'Server software disclosure — should be hidden',
        'recommended': 'Remove or obscure this header',
        'type': 'info_leak',
    },
    {
        'name': 'X-Powered-By',
        'description': 'Technology disclosure — should be removed',
        'recommended': 'Remove this header',
        'type': 'info_leak',
    },
    {
        'name': 'X-AspNet-Version',
        'description': 'ASP.NET version disclosure',
        'recommended': 'Remove this header',
        'type': 'info_leak',
    },
]


def analyze(url, state, proxy=None, verify_ssl=False):
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    try:
        resp = requests.get(
            url, timeout=10,
            verify=verify_ssl,      # Fix #2: configurable SSL verification
            allow_redirects=True,
            proxies=make_proxies(proxy) if proxy else None,    # Fix #17: proxy support
            headers={'User-Agent': next_user_agent()}           # Fix #18: UA rotation
        )
    except requests.exceptions.RequestException as e:
        return {'error': str(e)}

    headers_lower = {k.lower(): v for k, v in resp.headers.items()}
    results = []
    score = 0
    max_score = 6  # required headers only

    for hdr in SECURITY_HEADERS:
        name = hdr['name']
        value = headers_lower.get(name.lower(), '')
        present = bool(value)

        if hdr['type'] == 'info_leak':
            status = 'warn' if present else 'good'
        elif hdr['type'] == 'required':
            status = 'good' if present else 'missing'
            if present:
                score += 1
        else:
            status = 'good' if present else 'optional'

        results.append({
            'header': name,
            'value': value,
            'status': status,
            'description': hdr['description'],
            'recommended': hdr['recommended'],
        })

    try:
        hostname = urlparse(url).hostname
        resolved_ip = socket.gethostbyname(hostname)
        if not state.get('target_ip'):
            state['target_ip'] = resolved_ip
        if not state.get('target_domain'):
            state['target_domain'] = hostname
    except Exception:
        resolved_ip = ''

    state['target_url'] = url

    pct = score / max_score
    if pct >= 0.9:
        grade = 'A'
    elif pct >= 0.75:
        grade = 'B'
    elif pct >= 0.5:
        grade = 'C'
    elif pct >= 0.3:
        grade = 'D'
    else:
        grade = 'F'

    return {
        'url': resp.url,
        'status_code': resp.status_code,
        'headers': results,
        'all_headers': dict(resp.headers),
        'score': score,
        'max_score': max_score,
        'grade': grade,
        'resolved_ip': resolved_ip,
    }
