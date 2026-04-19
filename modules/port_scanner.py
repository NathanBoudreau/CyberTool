import socket
import concurrent.futures

SERVICES = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
    80: 'HTTP', 110: 'POP3', 111: 'RPC', 135: 'RPC', 139: 'NetBIOS',
    143: 'IMAP', 389: 'LDAP', 443: 'HTTPS', 445: 'SMB', 465: 'SMTPS',
    514: 'Syslog', 587: 'SMTP', 636: 'LDAPS', 873: 'Rsync',
    993: 'IMAPS', 995: 'POP3S', 1080: 'SOCKS', 1194: 'OpenVPN',
    1433: 'MSSQL', 1521: 'Oracle', 1723: 'PPTP', 2049: 'NFS',
    2181: 'Zookeeper', 2375: 'Docker', 2376: 'Docker-TLS',
    3000: 'Dev-HTTP', 3306: 'MySQL', 3389: 'RDP', 4444: 'Metasploit',
    4848: 'GlassFish', 5000: 'Dev-HTTP', 5432: 'PostgreSQL',
    5900: 'VNC', 5985: 'WinRM', 6379: 'Redis', 6443: 'K8s-API',
    7001: 'WebLogic', 8000: 'Dev-HTTP', 8008: 'HTTP-Alt',
    8080: 'HTTP-Proxy', 8081: 'HTTP-Alt', 8443: 'HTTPS-Alt',
    8888: 'Jupyter', 9000: 'SonarQube', 9090: 'Prometheus',
    9200: 'Elasticsearch', 9300: 'ES-Transport', 9443: 'HTTPS-Alt',
    10000: 'Webmin', 11211: 'Memcached', 27017: 'MongoDB',
    27018: 'MongoDB', 28017: 'MongoDB-Web',
}

TOP_100 = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 389, 443, 445,
    465, 514, 587, 636, 873, 993, 995, 1080, 1194, 1433, 1521, 1723,
    2049, 2181, 2375, 2376, 3000, 3306, 3389, 4444, 4848, 5000, 5432,
    5900, 5985, 6379, 6443, 7001, 8000, 8008, 8080, 8081, 8443, 8888,
    9000, 9090, 9200, 9300, 9443, 10000, 11211, 27017, 27018, 28017,
]


def parse_ports(port_str):
    if port_str == 'top100':
        return sorted(TOP_100)
    ports = []
    for part in port_str.split(','):
        part = part.strip()
        if '-' in part:
            try:
                start, end = part.split('-', 1)
                start, end = int(start), int(end)
                # Fix #6: reject reversed ranges
                if start > end:
                    continue
                ports.extend(range(start, end + 1))
            except ValueError:
                pass
        elif part.isdigit():
            ports.append(int(part))
    return sorted(set(p for p in ports if 1 <= p <= 65535))


def scan_port(ip, port, timeout=0.5):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return port, result == 0
    except Exception:
        return port, False


def grab_banner(ip, port, timeout=2):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        if port in (80, 8080, 8000, 8008, 8081):
            sock.send(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
        banner = sock.recv(512).decode('utf-8', errors='ignore').strip()
        sock.close()
        for line in banner.split('\n'):
            line = line.strip()
            if line:
                return line[:150]
    except Exception:
        pass
    return ''


def stream_scan(target, port_str, max_workers, state):
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror as e:
        yield {'type': 'error', 'message': f'Cannot resolve {target}: {e}'}
        return

    yield {'type': 'info', 'message': f'Resolved {target} → {ip}'}

    state['target_ip'] = ip
    if target != ip:
        state['target_domain'] = target

    ports = parse_ports(port_str)
    if not ports:
        yield {'type': 'error', 'message': 'No valid ports specified. Check your port range (e.g. start must be ≤ end).'}
        return

    total = len(ports)
    open_ports = []
    scanned = 0

    yield {'type': 'info', 'message': f'Scanning {total} ports with {max_workers} threads...'}

    BANNER_PORTS = {21, 22, 25, 80, 443, 8080, 8443, 3306, 5432, 6379, 27017}

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(max_workers, 500)) as executor:
        futures = {executor.submit(scan_port, ip, port): port for port in ports}
        for future in concurrent.futures.as_completed(futures):
            port, is_open = future.result()
            scanned += 1

            if is_open:
                service = SERVICES.get(port, 'Unknown')
                banner = grab_banner(ip, port) if port in BANNER_PORTS else ''
                entry = {'port': port, 'service': service, 'banner': banner}
                open_ports.append(entry)
                open_ports.sort(key=lambda x: x['port'])
                yield {'type': 'open', 'port': port, 'service': service, 'banner': banner}

            if scanned % 100 == 0 or scanned == total:
                yield {
                    'type': 'progress',
                    'scanned': scanned,
                    'total': total,
                    'percent': int(scanned / total * 100)
                }

    state['open_ports'] = open_ports
    yield {
        'type': 'complete',
        'open_ports': open_ports,
        'ip': ip,
        'total_scanned': total
    }
