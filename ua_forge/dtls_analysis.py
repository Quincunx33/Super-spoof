"""DTLS 1.0/1.2/1.3 unencrypted ClientHello extraction and JA4-D diagnostics.

Input: UDP payloads, not Ethernet/IP frames. Only initial plaintext epoch-0
handshake records are supported. Fragmented handshakes are reassembled with
bounds and overlap checks; no traffic is sent or decrypted.

RFC 6347 sections 4.1 and 4.2.2, RFC 9147 sections 5.2 and 5.3.
"""
from __future__ import annotations
from collections.abc import Iterable
from .ja4_analysis import JA4Result, _calculate_transport_ja4


def _u24(data: bytes) -> int:
    return int.from_bytes(data, 'big')


def extract_dtls_client_hello(datagrams: bytes | Iterable[bytes], *,
                              max_hello: int = 131072, max_datagrams: int = 256) -> bytes | None:
    """Return canonical 4-byte TLS-style handshake header + DTLS ClientHello body.

    None means not enough fragments, or no plaintext ClientHello was observed.
    Malformed input or conflicting fragments raise ValueError.
    """
    if not 1 <= max_hello <= 1_048_576 or not 1 <= max_datagrams <= 4096:
        raise ValueError('invalid resource bounds')
    if isinstance(datagrams, bytes): datagrams = [datagrams]
    chunks: dict[tuple[int, int], dict[int, int]] = {}
    count = 0
    for datagram in datagrams:
        count += 1
        if count > max_datagrams: raise ValueError('too many datagrams')
        if not isinstance(datagram, bytes): raise TypeError('DTLS datagrams must be bytes')
        pos = 0
        while pos < len(datagram):
            if len(datagram)-pos < 13: raise ValueError('truncated DTLS record header')
            kind, version = datagram[pos], int.from_bytes(datagram[pos+1:pos+3], 'big')
            epoch = int.from_bytes(datagram[pos+3:pos+5], 'big')
            length = int.from_bytes(datagram[pos+11:pos+13], 'big')
            pos += 13
            if pos+length > len(datagram): raise ValueError('truncated DTLS record')
            record = datagram[pos:pos+length]
            pos += length
            if kind != 22 or epoch != 0: continue
            if version not in (0xfeff,0xfefd,0xfefc):
                raise ValueError('unsupported DTLS record version')
            cursor = 0
            while cursor < len(record):
                if len(record)-cursor < 12: raise ValueError('truncated DTLS handshake header')
                typ = record[cursor]
                total = _u24(record[cursor+1:cursor+4])
                seq = int.from_bytes(record[cursor+4:cursor+6], 'big')
                off = _u24(record[cursor+6:cursor+9])
                frag_len = _u24(record[cursor+9:cursor+12])
                cursor += 12
                if frag_len > len(record)-cursor: raise ValueError('truncated DTLS fragment')
                fragment = record[cursor:cursor+frag_len]
                cursor += frag_len
                if typ != 1: continue
                if not 1 <= total <= max_hello: raise ValueError('invalid DTLS ClientHello length')
                if off+frag_len > total: raise ValueError('DTLS fragment exceeds handshake length')
                bucket = chunks.setdefault((seq,total), {})
                for j, val in enumerate(fragment):
                    prev = bucket.get(off+j)
                    if prev is not None and prev != val:
                        raise ValueError('conflicting DTLS handshake retransmission')
                    bucket[off+j] = val
    for (seq,total), bucket in sorted(chunks.items()):
        if len(bucket) == total:
            body = bytes(bucket[k] for k in range(total))
            return b'\x01' + total.to_bytes(3,'big') + body
    return None


def calculate_dtls_ja4(datagrams: bytes | Iterable[bytes]) -> JA4Result:
    """Parse plaintext DTLS ClientHello in UDP payloads and compute JA4-D."""
    hello = extract_dtls_client_hello(datagrams)
    if hello is None: raise ValueError('DTLS ClientHello incomplete or not present')
    return _calculate_transport_ja4(hello, transport='d')
