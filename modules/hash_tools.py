import re

PATTERNS = [
    (r'^[a-f0-9]{8}$', 'CRC32'),
    (r'^[a-f0-9]{16}$', 'MySQL323 / Half-MD5'),
    (r'^[a-f0-9]{32}$', 'MD5 / NTLM'),
    (r'^[a-f0-9]{40}$', 'SHA-1 / MySQL5'),
    (r'^[a-f0-9]{56}$', 'SHA-224'),
    (r'^[a-f0-9]{64}$', 'SHA-256'),
    (r'^[a-f0-9]{96}$', 'SHA-384'),
    (r'^[a-f0-9]{128}$', 'SHA-512'),
    (r'^\$2[ayb]\$.{56}$', 'bcrypt'),
    (r'^\$1\$.{1,8}\$.{22}$', 'MD5-crypt'),
    (r'^\$5\$.+\$.{43}$', 'SHA-256-crypt'),
    (r'^\$6\$.+\$.{86}$', 'SHA-512-crypt'),
    (r'^\$apr1\$', 'Apache MD5'),
    (r'^[a-f0-9]{32}:[a-f0-9]{32}$', 'MD5 with salt'),
    (r'^sha1\$[a-zA-Z0-9]+\$[a-f0-9]{40}$', 'Django SHA-1'),
    (r'^pbkdf2_sha256\$.+', 'Django PBKDF2-SHA256'),
    (r'^pbkdf2_sha512\$.+', 'Django PBKDF2-SHA512'),
    (r'^[a-zA-Z0-9+/]{43}=$', 'SHA-256 Base64'),
    (r'^[a-zA-Z0-9+/]{88}==$', 'SHA-512 Base64'),
    (r'^\{SHA\}[a-zA-Z0-9+/]+=*$', 'SSHA (LDAP)'),
    (r'^[a-zA-Z0-9./]{13}$', 'DES-crypt'),
    (r'^[0-9a-f]{32}:[0-9a-f]{3}$', 'MD5 with 3-char salt'),
]


def identify(hash_str):
    hash_str = hash_str.strip()
    matches = []

    for pattern, name in PATTERNS:
        if re.match(pattern, hash_str, re.IGNORECASE):
            matches.append(name)

    is_hex = all(c in '0123456789abcdefABCDEF' for c in hash_str) if hash_str else False
    char_type = 'hex' if is_hex else 'mixed/base64'

    if not matches:
        matches = [f'Unknown (length: {len(hash_str)}, chars: {char_type})']

    return {
        'hash': hash_str,
        'length': len(hash_str),
        'possible_types': matches,
        'is_hex': is_hex,
        'char_type': char_type,
    }
