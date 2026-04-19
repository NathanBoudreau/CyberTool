import ssl
import socket
import datetime


def inspect(host, port=443):
    host = host.strip()
    # Strip scheme if present
    for scheme in ('https://', 'http://'):
        if host.startswith(scheme):
            host = host[len(scheme):]
    host = host.split('/')[0]

    result = {'host': host, 'port': port}

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                der  = ssock.getpeercert(binary_form=True)
                result['protocol'] = ssock.version()
                result['cipher']   = ssock.cipher()  # (name, protocol, bits)
    except ConnectionRefusedError:
        return {'error': f'Connection refused on port {port}'}
    except socket.timeout:
        return {'error': f'Connection timed out connecting to {host}:{port}'}
    except socket.gaierror as e:
        return {'error': f'DNS resolution failed: {e}'}
    except Exception as e:
        return {'error': str(e)}

    # Subject
    subject = dict(x[0] for x in cert.get('subject', []))
    issuer  = dict(x[0] for x in cert.get('issuer', []))
    result['subject'] = {
        'cn':  subject.get('commonName'),
        'org': subject.get('organizationName'),
        'country': subject.get('countryName'),
    }
    result['issuer'] = {
        'cn':  issuer.get('commonName'),
        'org': issuer.get('organizationName'),
        'country': issuer.get('countryName'),
    }

    # SANs
    sans = []
    for typ, val in cert.get('subjectAltName', []):
        if typ == 'DNS':
            sans.append(val)
    result['sans'] = sans

    # Validity dates
    fmt = '%b %d %H:%M:%S %Y %Z'
    not_before = cert.get('notBefore', '')
    not_after  = cert.get('notAfter', '')
    result['not_before'] = not_before
    result['not_after']  = not_after

    now = datetime.datetime.utcnow()
    try:
        expiry = datetime.datetime.strptime(not_after, fmt)
        days_left = (expiry - now).days
        result['days_until_expiry'] = days_left
        if days_left < 0:
            result['expiry_status'] = 'expired'
        elif days_left <= 30:
            result['expiry_status'] = 'expiring_soon'
        else:
            result['expiry_status'] = 'valid'
    except Exception:
        result['days_until_expiry'] = None
        result['expiry_status'] = 'unknown'

    # Weak protocol / cipher warnings
    warnings = []
    proto = result.get('protocol', '')
    if proto in ('SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1'):
        warnings.append(f'Weak protocol in use: {proto}')
    cipher_name = result['cipher'][0] if result.get('cipher') else ''
    cipher_bits = result['cipher'][2] if result.get('cipher') else 0
    if cipher_bits and cipher_bits < 128:
        warnings.append(f'Weak cipher key size: {cipher_bits} bits')
    if 'RC4' in cipher_name or 'DES' in cipher_name or 'NULL' in cipher_name:
        warnings.append(f'Insecure cipher: {cipher_name}')
    result['warnings'] = warnings

    # Self-signed check
    result['self_signed'] = (
        subject.get('commonName') == issuer.get('commonName') and
        subject.get('organizationName') == issuer.get('organizationName')
    )

    return result
