"""
Basic unit tests for CyberTool modules.
Run with: python -m pytest tests/ -v
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from modules.utils import hash_word, detect_hash_algo, load_wordlist, next_user_agent
from modules.port_scanner import parse_ports
from modules.hash_tools import identify
from modules.encoder import process


# ─── utils ───────────────────────────────────────────────────────────

def test_hash_word_md5():
    assert hash_word('password', 'md5') == '5f4dcc3b5aa765d61d8327deb882cf99'

def test_hash_word_sha1():
    assert hash_word('password', 'sha1') == '5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8'

def test_hash_word_sha256():
    result = hash_word('hello', 'sha256')
    assert len(result) == 64

def test_hash_word_unknown_algo():
    assert hash_word('test', 'crc32') is None

def test_detect_hash_algo_md5():
    assert detect_hash_algo('5f4dcc3b5aa765d61d8327deb882cf99') == 'md5'

def test_detect_hash_algo_sha1():
    assert detect_hash_algo('5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8') == 'sha1'

def test_detect_hash_algo_sha256():
    assert detect_hash_algo('a' * 64) == 'sha256'

def test_detect_hash_algo_sha512():
    assert detect_hash_algo('b' * 128) == 'sha512'

def test_detect_hash_algo_none():
    assert detect_hash_algo('notahash') is None

def test_next_user_agent_rotates():
    ua1 = next_user_agent()
    ua2 = next_user_agent()
    assert isinstance(ua1, str) and len(ua1) > 10
    assert ua1 != ua2  # should rotate


# ─── port_scanner ────────────────────────────────────────────────────

def test_parse_ports_single():
    assert parse_ports('80') == [80]

def test_parse_ports_range():
    assert parse_ports('80-82') == [80, 81, 82]

def test_parse_ports_reversed_range_rejected():
    # Fix #6: reversed range should produce nothing
    assert parse_ports('1000-500') == []

def test_parse_ports_mixed():
    result = parse_ports('22,80-82,443')
    assert 22 in result and 80 in result and 81 in result and 82 in result and 443 in result

def test_parse_ports_top100():
    result = parse_ports('top100')
    assert len(result) > 50
    assert 80 in result and 443 in result

def test_parse_ports_out_of_range():
    assert parse_ports('0') == []
    assert parse_ports('65536') == []

def test_parse_ports_deduplicates():
    result = parse_ports('80,80,80')
    assert result.count(80) == 1


# ─── hash_tools ──────────────────────────────────────────────────────

def test_identify_md5():
    result = identify('5f4dcc3b5aa765d61d8327deb882cf99')
    assert any('MD5' in t for t in result['possible_types'])

def test_identify_sha1():
    result = identify('5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8')
    assert any('SHA-1' in t for t in result['possible_types'])

def test_identify_bcrypt():
    # Valid bcrypt format: $2b$NN$<53 chars base64>
    result = identify('$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/lewEFnNfTJlBNiJlG')
    assert any('bcrypt' in t for t in result['possible_types'])

def test_identify_unknown():
    result = identify('notahash')
    assert 'Unknown' in result['possible_types'][0]


# ─── encoder ─────────────────────────────────────────────────────────

def test_encode_base64():
    r = process('hello', 'encode', 'base64')
    assert r['result'] == 'aGVsbG8='

def test_decode_base64():
    r = process('aGVsbG8=', 'decode', 'base64')
    assert r['result'] == 'hello'

def test_encode_hex():
    r = process('AB', 'encode', 'hex')
    assert r['result'] == '4142'

def test_encode_md5_uses_shared_util():
    r = process('password', 'encode', 'md5')
    assert r['result'] == '5f4dcc3b5aa765d61d8327deb882cf99'

def test_encode_url():
    r = process('hello world', 'encode', 'url')
    assert r['result'] == 'hello%20world'

def test_encode_rot13_roundtrip():
    r1 = process('Hello World', 'encode', 'rot13')
    r2 = process(r1['result'], 'encode', 'rot13')
    assert r2['result'] == 'Hello World'

def test_unknown_encoding():
    r = process('test', 'encode', 'nonexistent')
    assert 'error' in r
