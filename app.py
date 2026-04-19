from flask import Flask, render_template, request, jsonify, Response
import json
import os
import html as html_mod
import datetime
import threading
import time
import shlex
import re
from collections import defaultdict

app = Flask(__name__)
app.secret_key = os.environ.get('CYBERTOOL_SECRET') or os.urandom(32)

# Fix #4: thread-safe global state
_state_lock = threading.Lock()
state = {
    'target_ip': '',
    'target_domain': '',
    'target_url': '',
    'open_ports': [],
    'subdomains': [],
    'last_updated': None
}

os.makedirs('reports', exist_ok=True)
os.makedirs('logs', exist_ok=True)
os.makedirs(os.path.join('wordlists', 'custom'), exist_ok=True)
LOG_FILE = os.path.join('logs', 'activity.log')

# Fix #3: simple in-memory rate limiter
_rate_data = defaultdict(list)
_rate_lock = threading.Lock()

def _check_rate(key, max_calls=10, window=60):
    now = time.time()
    with _rate_lock:
        calls = [t for t in _rate_data[key] if now - t < window]
        _rate_data[key] = calls
        if len(calls) >= max_calls:
            return False
        _rate_data[key].append(now)
        return True

# Fix #5: safe reports path resolver
_REPORTS_ABS = os.path.abspath('reports')

def _safe_report_path(filename):
    safe = os.path.basename(filename)
    full = os.path.abspath(os.path.join('reports', safe))
    if not full.startswith(_REPORTS_ABS + os.sep):
        return None
    return full


# Fix #1 & #7: proper nmap command validation using shlex + whitelist chars
_NMAP_SAFE_ARG = re.compile(
    r'^(-{1,2}[a-zA-Z][a-zA-Z0-9_-]*(?:=[^\s;|&`$<>()]*)?'
    r'|[a-zA-Z0-9][a-zA-Z0-9._\-/]*'
    r'|\d{1,5}(?:-\d{1,5})?(?:,\d{1,5}(?:-\d{1,5})?)*'
    r'|/\d{1,2})$'
)

def _validate_nmap_cmd(cmd):
    try:
        parts = shlex.split(cmd)
    except ValueError as e:
        return None, f'Invalid command syntax: {e}'
    if not parts or parts[0].lower() != 'nmap':
        return None, "Command must start with 'nmap'"
    safe = ['nmap']
    for arg in parts[1:]:
        # Reject any arg containing shell metacharacters (even embedded)
        if any(c in arg for c in (';', '&&', '||', '|', '`', '$', '>', '<', '(', ')', '\n', '\r', '"', "'")):
            return None, f"Unsafe character in argument: {repr(arg)}"
        if not _NMAP_SAFE_ARG.match(arg):
            return None, f"Argument not allowed: {repr(arg)}"
        safe.append(arg)
    return safe, None


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/state', methods=['GET'])
def get_state():
    with _state_lock:
        return jsonify(dict(state))


@app.route('/api/state', methods=['POST'])
def update_state():
    data = request.json or {}
    with _state_lock:
        for key in data:
            if key in state:
                state[key] = data[key]
        state['last_updated'] = datetime.datetime.now().isoformat()
    return jsonify({'ok': True, 'state': dict(state)})


@app.route('/api/ports/scan')
def port_scan():
    from modules.port_scanner import stream_scan
    if not _check_rate('port_scan', max_calls=5, window=60):
        return jsonify({'error': 'Rate limit exceeded — wait 60 seconds'}), 429
    target = request.args.get('target', '').strip()
    ports = request.args.get('ports', '1-1024').strip()
    threads = min(int(request.args.get('threads', 100)), 500)

    if not target:
        return jsonify({'error': 'No target specified'}), 400

    def generate():
        try:
            for event in stream_scan(target, ports, threads, state):
                yield f"data: {json.dumps(event)}\n\n"
        except GeneratorExit:
            pass

    return Response(generate(), mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})


@app.route('/api/ssl/inspect', methods=['POST'])
def ssl_inspect():
    from modules.ssl_inspector import inspect
    data = request.json or {}
    host = data.get('host', '').strip()
    if not host:
        return jsonify({'error': 'No host specified'}), 400
    try:
        port = int(data.get('port', 443))
    except (ValueError, TypeError):
        port = 443
    return jsonify(inspect(host, port))


@app.route('/api/headers/analyze', methods=['POST'])
def analyze_headers():
    from modules.web_headers import analyze
    data = request.json or {}
    url = data.get('url', '').strip()
    if not url:
        return jsonify({'error': 'No URL specified'}), 400
    proxy = data.get('proxy', '').strip() or None
    verify_ssl = bool(data.get('verify_ssl', False))
    result = analyze(url, state, proxy=proxy, verify_ssl=verify_ssl)
    return jsonify(result)


@app.route('/api/dns/lookup', methods=['POST'])
def dns_lookup():
    from modules.dns_lookup import lookup
    data = request.json or {}
    target = data.get('target', '').strip()
    if not target:
        return jsonify({'error': 'No target specified'}), 400
    result = lookup(target, state)
    return jsonify(result)


@app.route('/api/vulns/check', methods=['POST'])
def vuln_check():
    from modules.vuln_scanner import check
    data = request.json or {}
    ip      = data.get('ip', '').strip()
    port    = data.get('port', 0)
    service = data.get('service', '').strip()
    live    = data.get('live', False)
    result  = check(ip, port, service, state, live=live)
    return jsonify(result)


@app.route('/api/nmap/check')
def nmap_check():
    import shutil
    found = shutil.which('nmap') is not None
    return jsonify({'available': found})


@app.route('/api/nmap/run')
def nmap_run():
    import subprocess
    import shutil
    cmd = request.args.get('cmd', '').strip()

    def generate():
        if not shutil.which('nmap'):
            yield f"data: {json.dumps({'type': 'error', 'line': 'nmap not found. Install nmap and ensure it is on your PATH.'})}\n\n"
            return

        # Fix #1 & #7: validate command through whitelist parser
        safe_cmd, err = _validate_nmap_cmd(cmd)
        if err:
            yield f"data: {json.dumps({'type': 'error', 'line': f'Command rejected: {err}'})}\n\n"
            return

        try:
            proc = subprocess.Popen(
                safe_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )
            for line in proc.stdout:
                line = line.rstrip()
                if line:
                    yield f"data: {json.dumps({'type': 'line', 'line': line})}\n\n"
            proc.wait()
            yield f"data: {json.dumps({'type': 'done', 'code': proc.returncode})}\n\n"
        except Exception as e:
            yield f"data: {json.dumps({'type': 'error', 'line': str(e)})}\n\n"

    return Response(generate(), mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})


@app.route('/api/subdomains/scan')
def subdomain_scan():
    from modules.subdomain_enum import stream_scan
    if not _check_rate('subdomain_scan', max_calls=3, window=60):
        return jsonify({'error': 'Rate limit exceeded — wait 60 seconds'}), 429
    target = request.args.get('target', '').strip()
    if not target:
        return jsonify({'error': 'No target specified'}), 400
    custom_wl = request.args.get('wordlist', '').strip() or None
    if custom_wl:
        custom_wl = os.path.join('wordlists', 'custom', os.path.basename(custom_wl))

    def generate():
        try:
            for event in stream_scan(target, state, custom_wordlist=custom_wl):
                yield f"data: {json.dumps(event)}\n\n"
        except GeneratorExit:
            pass

    return Response(generate(), mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})


@app.route('/api/dirs/scan')
def dir_scan():
    from modules.dir_bruteforce import stream_scan
    if not _check_rate('dir_scan', max_calls=3, window=60):
        return jsonify({'error': 'Rate limit exceeded — wait 60 seconds'}), 429
    url = request.args.get('url', '').strip()
    if not url:
        return jsonify({'error': 'No URL specified'}), 400
    custom_wl = request.args.get('wordlist', '').strip() or None
    if custom_wl:
        custom_wl = os.path.join('wordlists', 'custom', os.path.basename(custom_wl))
    proxy = request.args.get('proxy', '').strip() or None
    verify_ssl = request.args.get('verify_ssl', 'false').lower() == 'true'
    recursive = request.args.get('recursive', 'false').lower() == 'true'
    max_depth = min(int(request.args.get('depth', 2)), 5)
    extensions = request.args.get('extensions', '').strip() or None

    def generate():
        try:
            for event in stream_scan(url, state, custom_wordlist=custom_wl,
                                     proxy=proxy, verify_ssl=verify_ssl,
                                     recursive=recursive, max_depth=max_depth,
                                     extensions=extensions):
                yield f"data: {json.dumps(event)}\n\n"
        except GeneratorExit:
            pass

    return Response(generate(), mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})


@app.route('/api/hash/identify', methods=['POST'])
def hash_identify():
    from modules.hash_tools import identify
    data = request.json or {}
    result = identify(data.get('hash', '').strip())
    return jsonify(result)


@app.route('/api/encode', methods=['POST'])
def encode():
    from modules.encoder import process
    data = request.json or {}
    result = process(data.get('text', ''), data.get('operation', 'encode'), data.get('encoding', 'base64'))
    return jsonify(result)


@app.route('/api/reports/save', methods=['POST'])
def save_report():
    data = request.json or {}
    ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    tool = re.sub(r'[^\w\-]', '_', data.get('tool', 'unknown'))
    filename = f"reports/report_{tool}_{ts}.json"
    with open(filename, 'w') as f:
        json.dump(data, f, indent=2)
    return jsonify({'ok': True, 'file': filename})


@app.route('/api/reports/delete', methods=['POST'])
def delete_report():
    filename = (request.json or {}).get('filename', '')
    # Fix #5: verify path stays inside reports/
    filepath = _safe_report_path(filename)
    if not filepath:
        return jsonify({'error': 'Invalid filename'}), 400
    if os.path.exists(filepath):
        os.remove(filepath)
        return jsonify({'ok': True})
    return jsonify({'error': 'not found'}), 404


@app.route('/api/reports/delete-all', methods=['POST'])
def delete_all_reports():
    deleted = 0
    for f in os.listdir('reports'):
        if f.endswith('.json') or f.endswith('.md'):
            os.remove(os.path.join('reports', f))
            deleted += 1
    return jsonify({'ok': True, 'deleted': deleted})


@app.route('/api/reports/list')
def list_reports():
    files = sorted(
        [f for f in os.listdir('reports') if f.endswith('.json')],
        reverse=True
    )
    return jsonify(files)


@app.route('/api/reports/<path:filename>')
def get_report(filename):
    # Fix #5: validate path
    filepath = _safe_report_path(filename)
    if not filepath:
        return jsonify({'error': 'Invalid filename'}), 400
    if os.path.exists(filepath):
        with open(filepath) as f:
            return jsonify(json.load(f))
    return jsonify({'error': 'not found'}), 404


@app.route('/api/web/brute')
def web_brute():
    from modules.web_brute import stream_brute
    url            = request.args.get('url', '').strip()
    username_field = request.args.get('user_field', 'username').strip()
    password_field = request.args.get('pass_field', 'password').strip()
    username       = request.args.get('username', '').strip()
    proxy          = request.args.get('proxy', '').strip() or None
    verify_ssl     = request.args.get('verify_ssl', 'false').lower() == 'true'
    custom_wl      = request.args.get('wordlist', '').strip() or None
    if custom_wl:
        custom_wl = os.path.join('wordlists', 'custom', os.path.basename(custom_wl))

    if not url:
        return jsonify({'error': 'No URL specified'}), 400

    # Fix #3: rate limit brute force endpoint
    if not _check_rate('web_brute', max_calls=5, window=60):
        return jsonify({'error': 'Rate limit exceeded — wait 60 seconds'}), 429

    def generate():
        try:
            for event in stream_brute(url, username_field, password_field, username,
                                      state, custom_wordlist=custom_wl,
                                      proxy=proxy, verify_ssl=verify_ssl):
                yield f"data: {json.dumps(event)}\n\n"
        except GeneratorExit:
            pass

    return Response(generate(), mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})


@app.route('/api/sqli/scan')
def sqli_scan():
    from modules.sqli_scanner import stream_scan, stream_scan_auto
    url = request.args.get('url', '').strip()
    param = request.args.get('param', '').strip()
    method = request.args.get('method', 'GET').strip().upper()
    proxy = request.args.get('proxy', '').strip() or None
    verify_ssl = request.args.get('verify_ssl', 'false').lower() == 'true'

    if not url:
        return jsonify({'error': 'URL required'}), 400
    if not param:
        return jsonify({'error': 'Parameter name required'}), 400

    if not _check_rate('sqli', max_calls=5, window=60):
        return jsonify({'error': 'Rate limit exceeded — wait 60 seconds'}), 429

    def generate():
        try:
            if param == 'auto':
                gen = stream_scan_auto(url, method=method, state=state,
                                       proxy=proxy, verify_ssl=verify_ssl)
            else:
                gen = stream_scan(url, param, method=method, state=state,
                                  proxy=proxy, verify_ssl=verify_ssl)
            for event in gen:
                yield f"data: {json.dumps(event)}\n\n"
        except GeneratorExit:
            pass

    return Response(generate(), mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})


@app.route('/api/sqli/params')
def sqli_params():
    from modules.sqli_scanner import _load_params
    return jsonify(_load_params())


@app.route('/api/wordlist/upload', methods=['POST'])
def upload_wordlist():
    # Fix #16: custom wordlist upload
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    f = request.files['file']
    if not f.filename:
        return jsonify({'error': 'No filename'}), 400
    safe_name = re.sub(r'[^\w\-_.]', '_', os.path.basename(f.filename))
    if not safe_name.endswith('.txt'):
        safe_name += '.txt'
    save_path = os.path.join('wordlists', 'custom', safe_name)
    f.save(save_path)
    with open(save_path) as wf:
        count = sum(1 for l in wf if l.strip() and not l.startswith('#'))
    return jsonify({'ok': True, 'filename': safe_name, 'count': count})


@app.route('/api/wordlist/list')
def list_wordlists():
    custom_dir = os.path.join('wordlists', 'custom')
    built_in = ['common_dirs.txt', 'subdomains.txt', 'passwords.txt']
    custom = [f for f in os.listdir(custom_dir) if f.endswith('.txt')]
    return jsonify({'built_in': built_in, 'custom': custom})


@app.route('/api/wordlist/delete', methods=['POST'])
def delete_wordlist():
    filename = request.json.get('filename', '').strip() if request.is_json else ''
    if not filename:
        return jsonify({'error': 'No filename provided'}), 400
    safe_name = os.path.basename(filename)
    path = os.path.abspath(os.path.join('wordlists', 'custom', safe_name))
    if not path.startswith(os.path.abspath(os.path.join('wordlists', 'custom'))):
        return jsonify({'error': 'Invalid path'}), 400
    if not os.path.isfile(path):
        return jsonify({'error': 'File not found'}), 404
    os.remove(path)
    return jsonify({'ok': True})


def _generate_nmap_md(data):
    ts     = data.get('timestamp', 'Unknown')
    cmd    = data.get('command', '')
    ip     = data.get('state', {}).get('target_ip', data.get('target', ''))
    domain = data.get('state', {}).get('target_domain', '')
    output = data.get('output', '')
    lines  = [
        '# Nmap Scan Report', '',
        f'**Date:** {ts}',
        f'**Target:** {ip}' + (f'  ({domain})' if domain else ''),
        f'**Command:** `{cmd}`', '',
        '## Raw Output', '', '```', output.strip(), '```', '',
    ]
    return '\n'.join(lines)


@app.route('/api/reports/save-nmap', methods=['POST'])
def save_nmap_report():
    data = request.json or {}
    ts   = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    base = f'nmap_{ts}'

    json_path = os.path.join('reports', base + '.json')
    with open(json_path, 'w') as f:
        json.dump(data, f, indent=2)

    md_content = _generate_nmap_md(data)
    md_path = os.path.join('reports', base + '.md')
    with open(md_path, 'w') as f:
        f.write(md_content)

    return jsonify({'ok': True, 'json_file': base + '.json', 'md_file': base + '.md'})


def _generate_report_md(data):
    tool = data.get('tool', 'unknown')
    ts   = data.get('timestamp', '')
    try:
        ts = datetime.datetime.fromisoformat(ts).strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        pass
    ip     = (data.get('state') or {}).get('target_ip', '—')
    domain = (data.get('state') or {}).get('target_domain', '—')
    labels = {
        'port-scanner': 'Port Scan Report', 'dns': 'DNS / WHOIS Report',
        'subdomains': 'Subdomain Enumeration Report', 'headers': 'HTTP Header Analysis Report',
        'dirs': 'Directory Brute Force Report', 'web-brute': 'Web Login Brute Force Report',
        'session': 'Full Session Report', 'nmap': 'Nmap Scan Report',
        'sqli': 'SQL Injection Scan Report',
    }
    title = labels.get(tool, f'{tool} Report')
    L = [f'# {title}', '', f'**Date:** {ts}', f'**Target IP:** {ip}', f'**Domain:** {domain}', '']

    if tool == 'port-scanner':
        ports = data.get('open_ports', [])
        L += [f'## Summary', f'- Open ports found: {len(ports)}', '']
        if ports:
            L += ['## Open Ports', '', '| Port | Service | Banner |', '|------|---------|--------|']
            for p in ports:
                L.append(f'| {p["port"]} | {p.get("service","—")} | {str(p.get("banner","—"))[:60]} |')
            L.append('')

    elif tool == 'dns':
        dd = data.get('dns_data') or {}
        L += ['## DNS Records', '']
        for k, v in [('IP', dd.get('ip')), ('Reverse DNS', dd.get('reverse_dns')),
                     ('MX Records', ', '.join(dd.get('mx_records') or [])),
                     ('NS Records', ', '.join(dd.get('ns_records') or []))]:
            if v: L.append(f'- **{k}:** {v}')
        w = dd.get('whois') or {}
        if w:
            L += ['', '## WHOIS', '']
            for k, v in [('Registrar', w.get('registrar')), ('Org', w.get('org')),
                         ('Country', w.get('country')), ('Created', w.get('creation_date')),
                         ('Expires', w.get('expiration_date'))]:
                if v: L.append(f'- **{k}:** {v}')
        L.append('')

    elif tool == 'subdomains':
        found = data.get('subdomain_data') or []
        L += [f'## Summary', f'- Subdomains found: {len(found)}', '']
        if found:
            L += ['## Discovered Subdomains', '', '| Subdomain | IP | Takeover? |', '|-----------|----|-----------|']
            for s in found:
                L.append(f'| {s.get("subdomain","—")} | {s.get("ip","—")} | {s.get("takeover") or "—"} |')
            L.append('')

    elif tool == 'headers':
        hd = data.get('headers_data') or {}
        L += ['## Summary', f'- Grade: **{hd.get("grade","?")}**',
              f'- Score: {hd.get("score","?")}/{hd.get("max_score","?")}', '']
        hdrs = hd.get('headers') or []
        if hdrs:
            L += ['## Security Headers', '', '| Header | Status | Value |', '|--------|--------|-------|']
            for h in hdrs:
                L.append(f'| {h.get("header","—")} | {h.get("status","—")} | {str(h.get("value","—"))[:60]} |')
            L.append('')

    elif tool == 'dirs':
        found = data.get('dir_data') or []
        L += [f'## Summary', f'- Paths found: {len(found)}', '']
        if found:
            L += ['## Discovered Paths', '', '| Status | URL | Size |', '|--------|-----|------|']
            for f in found:
                L.append(f'| {f.get("status","—")} | {f.get("url","—")} | {f.get("size",0)} |')
            L.append('')

    elif tool == 'sqli':
        findings = data.get('findings') or []
        L += [f'## Summary', f'- Findings: {len(findings)}',
              f'- Severity: {data.get("severity","—")}', '']
        if findings:
            L += ['## Findings', '', '| Payload | Type | Detail |', '|---------|------|--------|']
            for f in findings:
                L.append(f'| `{f.get("payload","—")}` | {f.get("type","—")} | {f.get("detail","—")} |')
            L.append('')

    elif tool == 'nmap':
        L += [f'## Command', '', f'```', data.get('command', ''), '```', '',
              '## Output', '', '```', (data.get('output') or '').strip(), '```', '']

    elif tool == 'session':
        ports = data.get('open_ports') or []
        subs  = data.get('subdomains') or []
        L += ['## Session Summary', f'- Open ports: {len(ports)}', f'- Subdomains: {len(subs)}', '']

    else:
        L += ['## Raw Data', '', '```json', json.dumps(data, indent=2), '```', '']

    return '\n'.join(L)


@app.route('/api/reports/export-md/<path:filename>')
def export_report_md(filename):
    path = _safe_report_path(filename)
    if not path or not os.path.exists(path):
        return jsonify({'error': 'not found'}), 404
    with open(path) as f:
        data = json.load(f)
    md_content = _generate_report_md(data)
    safe = os.path.basename(path)
    md_name = re.sub(r'[^\w\-_.]', '_', safe.replace('.json', '.md'))
    from flask import Response as FlaskResponse
    return FlaskResponse(
        md_content,
        mimetype='text/markdown',
        headers={'Content-Disposition': f"attachment; filename=\"{md_name}\""}
    )


@app.route('/api/reports/export-html/<path:filename>')
def export_report_html(filename):
    path = _safe_report_path(filename)
    if not path or not os.path.exists(path):
        return jsonify({'error': 'not found'}), 404
    with open(path) as f:
        data = json.load(f)

    H = html_mod.escape  # alias for brevity
    tool = data.get('tool', 'unknown')
    ts = data.get('timestamp', '')
    ip = (data.get('state') or {}).get('target_ip', '')
    domain = (data.get('state') or {}).get('target_domain', '')

    if tool == 'port-scanner':
        ports = data.get('open_ports', [])
        rows_html = ''.join(
            f'<tr><td>{H(str(p["port"]))}</td><td>{H(p.get("service","—"))}</td>'
            f'<td style="color:#4caf50">OPEN</td>'
            f'<td style="font-size:12px;color:#888">{H(str(p.get("banner","—"))[:80])}</td></tr>'
            for p in ports
        )
        table = f'<table><thead><tr><th>Port</th><th>Service</th><th>Status</th><th>Banner</th></tr></thead><tbody>{rows_html}</tbody></table>'
    elif tool == 'subdomains':
        found = data.get('subdomain_data', [])
        rows_html = ''.join(
            f'<tr><td>{H(s.get("subdomain","—"))}</td><td>{H(s.get("ip","—"))}</td>'
            f'<td style="color:{"#f44336" if s.get("takeover") else "#888"}">{H(s.get("takeover") or "—")}</td></tr>'
            for s in found
        )
        table = f'<table><thead><tr><th>Subdomain</th><th>IP</th><th>Takeover?</th></tr></thead><tbody>{rows_html}</tbody></table>'
    elif tool == 'dirs':
        found = data.get('dir_data', [])
        rows_html = ''.join(
            f'<tr><td>{H(str(f.get("status","—")))}</td><td style="font-family:monospace">{H(f.get("url","—"))}</td>'
            f'<td>{H(str(f.get("size",0)))}</td></tr>'
            for f in found
        )
        table = f'<table><thead><tr><th>Status</th><th>URL</th><th>Size</th></tr></thead><tbody>{rows_html}</tbody></table>'
    elif tool == 'sqli':
        findings = data.get('findings', [])
        rows_html = ''.join(
            f'<tr><td><code>{H(f.get("payload",""))}</code></td><td>{H(f.get("type",""))}</td>'
            f'<td>{H(f.get("detail",""))}</td></tr>'
            for f in findings
        )
        table = f'<table><thead><tr><th>Payload</th><th>Type</th><th>Detail</th></tr></thead><tbody>{rows_html}</tbody></table>'
    else:
        table = f'<pre>{H(json.dumps(data, indent=2))}</pre>'

    report_html = f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>CyberTool Report — {H(tool)}</title>
<style>
body{{font-family:monospace;background:#0d0d0d;color:#e0e0e0;margin:0;padding:24px}}
h1{{color:#00bcd4;border-bottom:1px solid #333;padding-bottom:8px}}
.meta{{color:#888;font-size:13px;margin-bottom:24px}}
table{{width:100%;border-collapse:collapse;margin-top:16px}}
th{{background:#1a1a1a;color:#00bcd4;padding:8px 12px;text-align:left;font-size:13px}}
td{{padding:7px 12px;border-bottom:1px solid #222;font-size:13px}}
tr:hover td{{background:#111}}
code{{background:#1a1a1a;padding:2px 6px;border-radius:3px;color:#80deea}}
pre{{background:#111;padding:16px;border-radius:4px;overflow-x:auto;font-size:12px}}
</style></head>
<body>
<h1>CyberTool — {H(tool.replace('-',' ').title())} Report</h1>
<div class="meta">
  Generated: {H(ts)} &nbsp;|&nbsp; Target: {H(ip or domain or '—')}
</div>
{table}
</body></html>"""

    from flask import Response as FlaskResponse
    safe = os.path.basename(path)
    html_name = re.sub(r'[^\w\-_.]', '_', safe.replace('.json', '.html'))
    return FlaskResponse(
        report_html,
        mimetype='text/html',
        headers={'Content-Disposition': f"attachment; filename=\"{html_name}\""}
    )


@app.route('/api/reports/download/<path:filename>')
def download_report_file(filename):
    from flask import send_file
    safe = os.path.basename(filename)
    if not safe.endswith('.md'):
        return jsonify({'error': 'Only .md files can be downloaded'}), 400
    path = os.path.abspath(os.path.join('reports', safe))
    if os.path.exists(path):
        return send_file(path, as_attachment=True, download_name=safe)
    return jsonify({'error': 'not found'}), 404


@app.route('/api/logs/append', methods=['POST'])
def log_append():
    entry = (request.json or {}).get('entry', '').strip()
    if entry:
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(entry + '\n')
    return jsonify({'ok': True})


@app.route('/api/logs/read')
def log_read():
    try:
        with open(LOG_FILE, 'r', encoding='utf-8') as f:
            lines = [l.rstrip() for l in f.readlines() if l.strip()]
        return jsonify({'lines': lines, 'count': len(lines)})
    except FileNotFoundError:
        return jsonify({'lines': [], 'count': 0})


@app.route('/api/logs/clear', methods=['POST'])
def log_clear():
    open(LOG_FILE, 'w').close()
    return jsonify({'ok': True})


@app.route('/api/logs/download')
def log_download():
    from flask import send_file as sf
    if os.path.exists(LOG_FILE):
        return sf(os.path.abspath(LOG_FILE), as_attachment=True, download_name='cybertool_activity.log')
    return jsonify({'error': 'No log file yet'}), 404


@app.route('/api/cve/search', methods=['POST'])
def cve_search():
    from modules.vuln_scanner import VULN_DB
    query = ((request.json or {}).get('query', '')).strip().lower()
    results = []
    if not query:
        return jsonify({'results': [], 'count': 0})
    for port, entry in VULN_DB.items():
        service_name = entry.get('name', '').lower()
        keywords = entry.get('service_keywords', [])
        port_match    = str(port) == query
        service_match = query in service_name or any(query in k for k in keywords)
        cve_matches   = [c for c in entry.get('cves', [])
                         if query in c[0].lower() or query in c[2].lower()]
        if port_match or service_match or cve_matches:
            cves_src = entry.get('cves', []) if (port_match or service_match) else cve_matches
            results.append({
                'port':         port,
                'service':      entry.get('name', ''),
                'severity':     entry.get('severity', 'info'),
                'issues':       entry.get('issues', []),
                'cves':         [{'id': c[0], 'severity': c[1], 'description': c[2]} for c in cves_src],
                'default_creds':[{'user': c[0], 'pass': c[1]} for c in entry.get('default_creds', [])],
                'nmap_scripts': entry.get('nmap_scripts', []),
                'remediation':  entry.get('remediation', ''),
            })
    return jsonify({'results': results, 'query': query, 'count': len(results)})


@app.route('/api/cve/all')
def cve_all():
    from modules.vuln_scanner import VULN_DB
    results = []
    for port, entry in VULN_DB.items():
        results.append({
            'port':          port,
            'service':       entry.get('name', ''),
            'severity':      entry.get('severity', 'info'),
            'issues':        entry.get('issues', []),
            'cves':          [{'id': c[0], 'severity': c[1], 'description': c[2]} for c in entry.get('cves', [])],
            'default_creds': [{'user': c[0], 'pass': c[1]} for c in entry.get('default_creds', [])],
            'nmap_scripts':  entry.get('nmap_scripts', []),
            'remediation':   entry.get('remediation', ''),
            'cve_count':     len(entry.get('cves', [])),
            'issue_count':   len(entry.get('issues', [])),
        })
    results.sort(key=lambda x: x['port'])
    return jsonify({'results': results, 'count': len(results)})


@app.route('/api/robots')
def fetch_robots():
    import urllib.request
    from urllib.parse import urljoin, urlparse
    import re
    url = request.args.get('url', '').strip()
    if not url:
        return jsonify({'error': 'No URL provided'})
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    if not url.startswith(('http://', 'https://')):
        return jsonify({'error': 'Only http/https URLs are supported'})
    parsed = urlparse(url)
    base   = f"{parsed.scheme}://{parsed.netloc}"
    result = {'base': base, 'robots_raw': None, 'robots_error': None,
              'disallow': [], 'allow': [], 'sitemaps': [],
              'sitemap_urls': [], 'sitemap_error': None}
    try:
        req = urllib.request.Request(urljoin(base, '/robots.txt'),
                                     headers={'User-Agent': 'CyberTool/1.0'})
        with urllib.request.urlopen(req, timeout=8) as r:
            content = r.read().decode('utf-8', errors='replace')
            result['robots_raw'] = content
            for line in content.splitlines():
                line = line.strip()
                lc = line.lower()
                if lc.startswith('disallow:'):
                    p = line[9:].strip()
                    if p: result['disallow'].append(p)
                elif lc.startswith('allow:'):
                    p = line[6:].strip()
                    if p and p != '/': result['allow'].append(p)
                elif lc.startswith('sitemap:'):
                    p = line[8:].strip()
                    if p: result['sitemaps'].append(p)
    except Exception as e:
        result['robots_error'] = str(e)
    sm_url = result['sitemaps'][0] if result['sitemaps'] else urljoin(base, '/sitemap.xml')
    try:
        req = urllib.request.Request(sm_url, headers={'User-Agent': 'CyberTool/1.0'})
        with urllib.request.urlopen(req, timeout=8) as r:
            sm = r.read().decode('utf-8', errors='replace')
            result['sitemap_urls'] = re.findall(r'<loc>(.*?)</loc>', sm, re.IGNORECASE)[:150]
    except Exception as e:
        result['sitemap_error'] = str(e)
    return jsonify(result)


@app.route('/api/hash/crack')
def hash_crack():
    from modules.hash_cracker import stream_crack
    hash_val = request.args.get('hash', '').strip()
    algo     = request.args.get('algo', 'auto').strip()
    custom_wl = request.args.get('wordlist', '').strip() or None
    if custom_wl:
        custom_wl = os.path.join('wordlists', 'custom', os.path.basename(custom_wl))

    if not hash_val:
        return jsonify({'error': 'No hash provided'}), 400

    # Fix #3: rate limit hash cracking
    if not _check_rate('hash_crack', max_calls=10, window=60):
        return jsonify({'error': 'Rate limit exceeded — wait 60 seconds'}), 429

    def generate():
        try:
            for event in stream_crack(hash_val, algo, custom_wordlist=custom_wl):
                yield f"data: {json.dumps(event)}\n\n"
        except GeneratorExit:
            pass

    return Response(generate(), mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})


@app.route('/api/connectivity')
def connectivity():
    import socket
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect(('8.8.8.8', 53))
        sock.close()
        return jsonify({'online': True})
    except Exception:
        return jsonify({'online': False})


if __name__ == '__main__':
    print("\n  CYBERTOOL running at http://localhost:5000\n")
    app.run(debug=False, port=5000, threaded=True)
