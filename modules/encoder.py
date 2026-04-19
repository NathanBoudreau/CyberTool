import base64
import urllib.parse
import html
from modules.utils import hash_word


def process(text, operation, encoding):
    try:
        if encoding == 'base64':
            if operation == 'encode':
                result = base64.b64encode(text.encode('utf-8')).decode()
            else:
                result = base64.b64decode(text.encode()).decode('utf-8', errors='replace')

        elif encoding == 'base32':
            if operation == 'encode':
                result = base64.b32encode(text.encode('utf-8')).decode()
            else:
                result = base64.b32decode(text.upper().encode()).decode('utf-8', errors='replace')

        elif encoding == 'base58':
            alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
            if operation == 'encode':
                num = int.from_bytes(text.encode(), 'big')
                result = ''
                while num:
                    num, rem = divmod(num, 58)
                    result = alphabet[rem] + result
                result = result or '1'
            else:
                num = 0
                for char in text:
                    idx = alphabet.find(char)
                    if idx == -1:
                        return {'error': f'Invalid Base58 character: {char}'}
                    num = num * 58 + idx
                result = num.to_bytes((num.bit_length() + 7) // 8, 'big').decode('utf-8', errors='replace')

        elif encoding == 'hex':
            if operation == 'encode':
                result = text.encode('utf-8').hex()
            else:
                result = bytes.fromhex(text.replace(' ', '')).decode('utf-8', errors='replace')

        elif encoding == 'url':
            if operation == 'encode':
                result = urllib.parse.quote(text, safe='')
            else:
                result = urllib.parse.unquote(text)

        elif encoding == 'url_full':
            if operation == 'encode':
                result = ''.join(f'%{b:02X}' for b in text.encode('utf-8'))
            else:
                result = urllib.parse.unquote(text)

        elif encoding == 'html':
            if operation == 'encode':
                result = html.escape(text)
            else:
                result = html.unescape(text)

        elif encoding == 'binary':
            if operation == 'encode':
                result = ' '.join(format(ord(c), '08b') for c in text)
            else:
                bits = text.split()
                result = ''.join(chr(int(b, 2)) for b in bits)

        elif encoding == 'octal':
            if operation == 'encode':
                result = ' '.join(format(ord(c), 'o') for c in text)
            else:
                result = ''.join(chr(int(o, 8)) for o in text.split())

        elif encoding == 'rot13':
            result = text.translate(str.maketrans(
                'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
                'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm'
            ))

        elif encoding == 'caesar':
            shift = 13
            result = ''
            for c in text:
                if c.isalpha():
                    base = ord('A') if c.isupper() else ord('a')
                    op = 1 if operation == 'encode' else -1
                    result += chr((ord(c) - base + op * shift) % 26 + base)
                else:
                    result += c

        elif encoding in ('md5', 'sha1', 'sha256', 'sha512'):
            # Fix #10: use shared hash utility instead of duplicate code
            result = hash_word(text, encoding)
            if result is None:
                return {'error': f'Hashing failed for {encoding}'}

        else:
            return {'error': f'Unknown encoding: {encoding}'}

        return {'result': result, 'encoding': encoding, 'operation': operation}

    except Exception as e:
        return {'error': str(e)}
