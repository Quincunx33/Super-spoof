"""Offline TLS ClientHello JA3 analysis for user-supplied captures. Not packet interception."""
from __future__ import annotations
import hashlib
from dataclasses import dataclass, asdict


def _u16(b: bytes, i: int) -> int:
    if i + 2 > len(b): raise ValueError("truncated TLS field")
    return int.from_bytes(b[i:i+2], "big")


def _vector(b: bytes, i: int, size: int):
    if i + size > len(b): raise ValueError("truncated vector length")
    n = int.from_bytes(b[i:i+size], "big")
    j = i + size
    if j + n > len(b): raise ValueError("truncated vector")
    return b[j:j+n], j+n


def _grease(v: int) -> bool:
    return (v & 0x0f0f) == 0x0a0a and (v >> 8) == (v & 255)

@dataclass(frozen=True)
class JA3Observation:
    ja3: str
    md5: str
    tls_legacy_version: int
    extensions: tuple[int, ...]
    def as_dict(self): return asdict(self)


def parse_client_hello(data: bytes) -> JA3Observation:
    """Accept a complete TLS record or raw handshake containing a ClientHello.

    TLS 1.3 commonly uses legacy_version=771; JA3 is not JA4.
    """
    if len(data) >= 5 and data[0] == 22:
        length = _u16(data, 3)
        if len(data) < 5 + length: raise ValueError("truncated TLS record")
        data = data[5:5+length]
    if len(data) < 4 or data[0] != 1: raise ValueError("expected ClientHello handshake")
    n = int.from_bytes(data[1:4], "big")
    if len(data) < n + 4: raise ValueError("truncated ClientHello")
    b = data[4:4+n]
    if len(b) < 35: raise ValueError("truncated ClientHello body")
    ver = _u16(b, 0)
    i = 34
    session, i = _vector(b, i, 1)
    ciphers, i = _vector(b, i, 2)
    if len(ciphers) % 2: raise ValueError("invalid cipher vector")
    cs = [int.from_bytes(ciphers[k:k+2], "big") for k in range(0, len(ciphers), 2)]
    compression, i = _vector(b, i, 1)
    ext_ids, groups, formats = [], [], []
    if i < len(b):
        ext_data, i = _vector(b, i, 2)
        if i != len(b): raise ValueError("trailing ClientHello data")
        j = 0
        while j < len(ext_data):
            if j + 4 > len(ext_data): raise ValueError("truncated extension")
            typ, size = _u16(ext_data, j), _u16(ext_data, j+2)
            j += 4
            if j + size > len(ext_data): raise ValueError("truncated extension payload")
            val = ext_data[j:j+size]; j += size
            ext_ids.append(typ)
            if typ == 10:
                vals, end = _vector(val, 0, 2)
                if end != len(val) or len(vals) % 2: raise ValueError("invalid supported groups")
                groups = [int.from_bytes(vals[k:k+2], "big") for k in range(0,len(vals),2)]
            elif typ == 11:
                vals, end = _vector(val, 0, 1)
                if end != len(val): raise ValueError("invalid point formats")
                formats = list(vals)
    def join(vals): return "-".join(str(x) for x in vals if not _grease(x))
    ja3 = ",".join([str(ver), join(cs), join(ext_ids), join(groups), join(formats)])
    return JA3Observation(ja3, hashlib.md5(ja3.encode("ascii")).hexdigest(), ver, tuple(ext_ids))
