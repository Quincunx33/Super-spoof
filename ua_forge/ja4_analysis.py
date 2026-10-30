"""JA4 ClientHello fingerprints following FoxIO's public JA4 algorithm.

Transport-specific parsing is handled by quic_analysis and dtls_analysis.
Reference: https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md
JA4 TLS is BSD-3-Clause. This independently written parser does not implement JA4+.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
from .tls_analysis import _u16, _vector, _grease


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode('ascii')).hexdigest()[:12] if text else '000000000000'


def _hex(values) -> str:
    return ','.join(f'{v:04x}' for v in values if not _grease(v))


@dataclass(frozen=True)
class JA4Result:
    ja4: str
    ja4_r: str
    tls_version: str
    has_sni: bool
    alpn: str
    ciphers: tuple[int, ...]
    extensions: tuple[int, ...]
    signature_algorithms: tuple[int, ...]
    def as_dict(self): return asdict(self)


def _handshake(data: bytes) -> bytes:
    if len(data) >= 5 and data[0] == 22:
        n = _u16(data, 3)
        if len(data) < 5+n: raise ValueError('truncated TLS record')
        data = data[5:5+n]
    if len(data) < 4 or data[0] != 1: raise ValueError('expected ClientHello')
    n = int.from_bytes(data[1:4], 'big')
    if n > 1_000_000 or len(data) < 4+n: raise ValueError('incomplete/oversized ClientHello')
    return data[4:4+n]


def _alpn_name(raw: bytes) -> str:
    if not raw: return '00'
    first, last = raw[0], raw[-1]
    def ascii_alnum(v): return (48 <= v <= 57 or 65 <= v <= 90 or 97 <= v <= 122)
    if ascii_alnum(first) and ascii_alnum(last):
        return chr(first) + chr(last)
    return f'{first:02x}'[0] + f'{last:02x}'[-1]


def _calculate_transport_ja4(data: bytes, *, transport: str) -> JA4Result:
    """Compute JA4 from a normalized ClientHello, with transport-specific fields."""
    if transport not in ('t', 'q', 'd'): raise ValueError('invalid JA4 transport')
    b = _handshake(data)
    if len(b) < 35: raise ValueError('truncated ClientHello')
    legacy_version = _u16(b, 0)
    idx = 34
    _, idx = _vector(b, idx, 1)  # legacy session ID
    if transport == 'd':
        _, idx = _vector(b, idx, 1)  # DTLS-specific legacy cookie
    raw_ciphers, idx = _vector(b, idx, 2)
    if len(raw_ciphers) % 2 or not raw_ciphers: raise ValueError('invalid cipher suites')
    ciphers = [int.from_bytes(raw_ciphers[k:k+2], 'big') for k in range(0, len(raw_ciphers), 2)]
    comp, idx = _vector(b, idx, 1)
    if not comp: raise ValueError('empty compression methods')
    exts = []
    sigs = []
    versions = []
    alpn = b''
    if idx < len(b):
        raw_exts, idx = _vector(b, idx, 2)
        if idx != len(b): raise ValueError('trailing ClientHello bytes')
        j = 0
        while j < len(raw_exts):
            if j+4 > len(raw_exts): raise ValueError('truncated TLS extension header')
            kind, length = _u16(raw_exts, j), _u16(raw_exts, j+2)
            j += 4
            if j+length > len(raw_exts): raise ValueError('truncated extension data')
            body = raw_exts[j:j+length]
            j += length
            exts.append(kind)
            if kind == 43:  # supported_versions
                vec, end = _vector(body, 0, 1)
                if end != len(body) or len(vec) % 2 or not vec: raise ValueError('invalid supported_versions')
                versions = [int.from_bytes(vec[k:k+2], 'big') for k in range(0,len(vec),2)]
            elif kind == 13:  # signature_algorithms
                vec, end = _vector(body, 0, 2)
                if end != len(body) or len(vec) % 2: raise ValueError('invalid signature_algorithms')
                sigs = [int.from_bytes(vec[k:k+2], 'big') for k in range(0,len(vec),2)]
            elif kind == 16:  # ALPN: ProtocolNameList
                vec, end = _vector(body, 0, 2)
                if end != len(body): raise ValueError('invalid ALPN length')
                if vec:
                    alpn, consumed = _vector(vec, 0, 1)
                    if not alpn or consumed > len(vec): raise ValueError('invalid first ALPN name')
    non_grease_versions = [v for v in versions if not _grease(v)]
    # DTLS wire versions count downward (feff -> fefd -> fefc), unlike TLS.
    version = (min(non_grease_versions) if transport == 'd' else max(non_grease_versions)) if non_grease_versions else legacy_version
    versions_map = {0x0304:'13', 0x0303:'12', 0x0302:'11', 0x0301:'10',
                    0x0300:'s3', 0x0002:'s2', 0xfeff:'d1', 0xfefd:'d2', 0xfefc:'d3'}
    v = versions_map.get(version, '00')
    clean_ciphers = [n for n in ciphers if not _grease(n)]
    clean_exts = [n for n in exts if not _grease(n)]
    clean_sigs = [n for n in sigs if not _grease(n)]
    a = f'{transport}{v}{"d" if 0 in clean_exts else "i"}{min(len(clean_ciphers),99):02d}{min(len(clean_exts),99):02d}{_alpn_name(alpn)}'
    b_raw = _hex(sorted(clean_ciphers))
    e_raw = _hex(sorted(n for n in clean_exts if n not in (0,16)))
    s_raw = _hex(clean_sigs)
    c_raw = e_raw + ('_' + s_raw if s_raw else '')
    ja4 = a + '_' + _sha(b_raw) + '_' + _sha(c_raw) if e_raw else a + '_' + _sha(b_raw) + '_000000000000'
    raw = a + '_' + b_raw + '_' + e_raw + ('_' + s_raw if s_raw else '')
    return JA4Result(ja4, raw, v, 0 in clean_exts, _alpn_name(alpn), tuple(clean_ciphers), tuple(clean_exts), tuple(clean_sigs))


def calculate_ja4(data: bytes, *, transport: str = 't') -> JA4Result:
    """Calculate JA4 for a raw TLS-over-TCP ClientHello or TLS record.

    QUIC/DTLS require dedicated record/packet decoding first; use
    calculate_quic_ja4() or calculate_dtls_ja4() instead of changing transport.
    """
    if transport != 't':
        raise ValueError('Use calculate_quic_ja4() or calculate_dtls_ja4() for UDP transports')
    return _calculate_transport_ja4(data, transport='t')


def ja4_diagnostic(data: bytes) -> dict:
    """Backwards-compatible dictionary wrapper for TLS-over-TCP JA4."""
    result = calculate_ja4(data)
    return {**result.as_dict(), 'standard_ja4': result.ja4,
            'standard_compliant': True, 'scope': 'TLS over TCP only'}
