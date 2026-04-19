import socket
import subprocess
import platform


def lookup(target, state):
    result = {}

    try:
        ip = socket.gethostbyname(target)
        result['ip'] = ip
        result['is_ip_input'] = (target == ip)
    except socket.gaierror as e:
        result['ip'] = None
        result['error'] = str(e)
        return result

    try:
        addr_info = socket.getaddrinfo(target, None)
        all_ips = list(dict.fromkeys(info[4][0] for info in addr_info))
        result['all_ips'] = all_ips
    except Exception:
        result['all_ips'] = [ip] if ip else []

    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        result['reverse_dns'] = hostname
    except Exception:
        result['reverse_dns'] = None

    mx, mx_error = _get_mx(target)
    result['mx_records'] = mx
    if mx_error:
        result['mx_error'] = mx_error

    ns, ns_error = _get_ns(target)
    result['ns_records'] = ns
    if ns_error:
        result['ns_error'] = ns_error

    result['whois'] = _get_whois(target)

    state['target_ip'] = ip
    if not result['is_ip_input']:
        state['target_domain'] = target
    if not state.get('target_url') and not result['is_ip_input']:
        state['target_url'] = f'http://{target}'

    return result


def _run_cmd(cmd, timeout=5):
    # Fix #12: return both output and error message instead of silently failing
    try:
        out = subprocess.check_output(
            cmd, stderr=subprocess.DEVNULL, timeout=timeout, text=True
        )
        return out, None
    except FileNotFoundError:
        return '', f"Tool not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return '', f"Command timed out after {timeout}s"
    except subprocess.CalledProcessError as e:
        return '', f"Command failed: {e}"
    except Exception as e:
        return '', str(e)


def _get_mx(domain):
    system = platform.system()
    if system == 'Windows':
        out, err = _run_cmd(['nslookup', '-type=MX', domain])
        if err:
            return [], err
        # Fix #12: improved Windows nslookup parsing
        lines = []
        for line in out.splitlines():
            line = line.strip()
            if 'mail exchanger' in line.lower():
                # Windows format: "domain  MX preference = 10, mail exchanger = mail.example.com"
                if 'mail exchanger =' in line.lower():
                    parts = line.lower().split('mail exchanger =')
                    if len(parts) > 1:
                        lines.append(parts[1].strip())
                else:
                    lines.append(line)
    else:
        out, err = _run_cmd(['dig', '+short', 'MX', domain])
        if err:
            return [], err
        lines = [l.strip() for l in out.splitlines() if l.strip()]
    return lines[:10], None


def _get_ns(domain):
    system = platform.system()
    if system == 'Windows':
        out, err = _run_cmd(['nslookup', '-type=NS', domain])
        if err:
            return [], err
        # Fix #12: improved Windows nslookup NS parsing
        lines = []
        for line in out.splitlines():
            line = line.strip()
            if 'nameserver' in line.lower():
                if '=' in line:
                    parts = line.split('=')
                    if len(parts) > 1:
                        lines.append(parts[-1].strip())
                else:
                    lines.append(line)
    else:
        out, err = _run_cmd(['dig', '+short', 'NS', domain])
        if err:
            return [], err
        lines = [l.strip() for l in out.splitlines() if l.strip()]
    return lines[:10], None


def _get_whois(target):
    try:
        import whois
        w = whois.whois(target)
        return {
            'registrar': str(w.registrar) if w.registrar else None,
            'creation_date': str(w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date) if w.creation_date else None,
            'expiration_date': str(w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date) if w.expiration_date else None,
            'updated_date': str(w.updated_date[0] if isinstance(w.updated_date, list) else w.updated_date) if hasattr(w, 'updated_date') and w.updated_date else None,
            'name_servers': list(w.name_servers)[:5] if w.name_servers else [],
            'org': str(w.org) if hasattr(w, 'org') and w.org else None,
            'country': str(w.country) if hasattr(w, 'country') and w.country else None,
            'status': str(w.status[0] if isinstance(w.status, list) else w.status) if hasattr(w, 'status') and w.status else None,
        }
    except Exception:
        return None
