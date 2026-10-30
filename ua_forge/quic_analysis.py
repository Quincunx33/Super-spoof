"""Read-only QUIC v1/v2 Initial packet inspection for authorized diagnostics.

Accepts one or more raw UDP datagram payloads carrying *client* QUIC Initial
packets. Removes Initial header protection, authenticates AES-128-GCM payloads,
reassembles CRYPTO frame offsets and extracts TLS ClientHello. Initial keys
are public/derivable (RFC 9001); this does not decrypt protected QUIC sessions.

RFC 9000, RFC 9001, RFC 9369. Python cryptography is an optional dependency.
"""
from __future__ import annotations
from collections.abc import Iterable
import hashlib
import hmac
from dataclasses import dataclass
from .ja4_analysis import JA4Result, _calculate_transport_ja4
from .tcp_reassembly import reassemble_segments

_VERSION = {
    0x00000001: (bytes.fromhex('38762cf7f55934b34d179ae6a4c80cadccbb7f0a'), 'quic', 0),
    0x6b3343cf: (bytes.fromhex('0dede3def700a6db819381be6e269dcbf9bd2ed9'), 'quicv2', 1),
}


def _varint(data: bytes, at: int) -> tuple[int, int]:
    if at >= len(data): raise ValueError('truncated QUIC varint')
    n = 1 << (data[at] >> 6)
    if at+n > len(data): raise ValueError('truncated QUIC varint')
    return int.from_bytes(data[at:at+n], 'big') & ((1 << (n*8-2))-1), at+n


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    out, previous = b'', b''
    for i in range(1, (length+31)//32+1):
        previous = hmac.new(prk, previous+info+bytes([i]), hashlib.sha256).digest()
        out += previous
    return out[:length]


def _label(secret: bytes, label: str, length: int) -> bytes:
    key_label = b'tls13 ' + label.encode('ascii')
    info = length.to_bytes(2,'big') + bytes([len(key_label)])+key_label+b'\x00'
    return _hkdf_expand(secret,info,length)


@dataclass(frozen=True)
class InitialKeys:
    key: bytes
    iv: bytes
    hp: bytes


def derive_initial_keys(dcid: bytes, *, version: int = 1,
                        direction: str = 'client') -> InitialKeys:
    """Derive public QUIC Initial keys (not 1-RTT traffic secrets)."""
    if version not in _VERSION: raise ValueError('QUIC version not supported')
    if not isinstance(dcid, bytes) or len(dcid) > 20: raise ValueError('invalid destination connection ID')
    if direction not in ('client','server'): raise ValueError('direction must be client/server')
    salt, prefix, _ = _VERSION[version]
    initial = hmac.new(salt, dcid, hashlib.sha256).digest()
    secret = _label(initial, direction+' in', 32)
    return InitialKeys(_label(secret,prefix+' key',16),
                       _label(secret,prefix+' iv',12),
                       _label(secret,prefix+' hp',16))


def _decode_packet_number(truncated: int, length: int, largest: int) -> int:
    expected = largest+1
    window = 1 << (8*length)
    half = window//2
    candidate = (expected & ~(window-1)) | truncated
    if candidate <= expected-half and candidate < (1<<62)-window: return candidate+window
    if candidate > expected+half and candidate >= window: return candidate-window
    return candidate


def _read_crypto_frames(plaintext: bytes, *, max_hello: int) -> list[tuple[int, bytes]]:
    frames: list[tuple[int,bytes]] = []
    pos = 0
    while pos < len(plaintext):
        kind, pos = _varint(plaintext,pos)
        if kind in (0,1): continue  # PADDING / PING
        if kind == 6:  # CRYPTO
            offset, pos = _varint(plaintext,pos)
            n, pos = _varint(plaintext,pos)
            if offset+n > max_hello: raise ValueError('QUIC CRYPTO range exceeds configured maximum')
            if pos+n > len(plaintext): raise ValueError('truncated QUIC CRYPTO frame')
            frames.append((offset,plaintext[pos:pos+n])); pos += n
        elif kind in (2,3): # ACK / ACK with ECN
            _, pos = _varint(plaintext,pos)  # largest acknowledged
            _, pos = _varint(plaintext,pos)  # ack delay
            count, pos = _varint(plaintext,pos)
            _, pos = _varint(plaintext,pos)  # first ack range
            if count > 1024: raise ValueError('too many ACK ranges')
            for _ in range(count):
                _, pos = _varint(plaintext,pos)
                _, pos = _varint(plaintext,pos)
            if kind == 3:
                for _ in range(3): _, pos = _varint(plaintext,pos)
        elif kind in (0x1c, 0x1d):
            _, pos = _varint(plaintext,pos)  # error code
            if kind == 0x1c: _, pos = _varint(plaintext,pos)  # frame type
            length, pos = _varint(plaintext,pos)
            if pos+length > len(plaintext): raise ValueError('truncated close frame')
            pos += length
        else:
            raise ValueError(f'unsupported QUIC Initial frame 0x{kind:x}')
    return frames


def extract_quic_client_hello(datagrams: bytes | Iterable[bytes], *,
                              max_hello: int = 131072,
                              max_datagrams: int = 256) -> bytes | None:
    """Extract raw TLS handshake from authenticated QUIC v1/v2 client Initial(s).

    None means incomplete/absent ClientHello; non-initial QUIC packets are
    skipped where possible. Does not handle QUIC Retry, IP fragmentation,
    QUIC 0-RTT/Handshake/1-RTT, or coalescing of unrelated connections.
    """
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.exceptions import InvalidTag
    except ImportError as e:
        raise ImportError('QUIC analysis requires pip install "advanced-ua-forge[quic]"') from e
    if not 1 <= max_hello <= 1_048_576 or not 1 <= max_datagrams <= 4096:
        raise ValueError('invalid resource bounds')
    if isinstance(datagrams, bytes): datagrams = [datagrams]
    fragments: list[tuple[int,bytes]] = []
    largest_pn = -1
    flow = None
    seen: set[int] = set()
    for count, datagram in enumerate(datagrams,1):
        if count > max_datagrams: raise ValueError('too many datagrams')
        if not isinstance(datagram, bytes): raise TypeError('QUIC datagrams must be bytes')
        pos = 0
        while pos < len(datagram):
            if not datagram[pos] & 0x80: break  # short-header, cannot parse length
            if len(datagram)-pos < 7: raise ValueError('truncated QUIC long header')
            start = pos
            first = datagram[pos]
            version = int.from_bytes(datagram[pos+1:pos+5],'big')
            pos += 5
            dcid_len = datagram[pos]; pos += 1
            if dcid_len > 20 or pos+dcid_len+1 > len(datagram): raise ValueError('invalid QUIC destination CID')
            dcid = datagram[pos:pos+dcid_len]; pos += dcid_len
            scid_len = datagram[pos]; pos += 1
            if scid_len > 20 or pos+scid_len > len(datagram): raise ValueError('invalid QUIC source CID')
            pos += scid_len
            if version == 0: break  # version negotiation
            if version not in _VERSION: raise ValueError('unsupported QUIC version')
            _, _, initial_type = _VERSION[version]
            packet_type = (first >> 4) & 3
            if packet_type == (3 if version == 1 else 0):  # Retry has no Length
                break
            if packet_type == initial_type:
                token_length,pos = _varint(datagram,pos)
                if pos+token_length > len(datagram): raise ValueError('truncated QUIC token')
                pos += token_length
            length,pos = _varint(datagram,pos)
            pn_off = pos
            packet_end = pos+length
            if packet_end > len(datagram): raise ValueError('truncated QUIC packet')
            pos = packet_end
            if packet_type != initial_type: continue
            if flow is None: flow = (version,dcid)
            if flow != (version,dcid): raise ValueError('mixed QUIC Initial connections')
            keys = derive_initial_keys(dcid,version=version)
            sample_start = pn_off+4
            if sample_start+16 > packet_end: raise ValueError('QUIC header protection sample truncated')
            enc = Cipher(algorithms.AES(keys.hp),modes.ECB()).encryptor()
            mask = enc.update(datagram[sample_start:sample_start+16])+enc.finalize()
            unprotected = first ^ (mask[0] & 0x0f)
            if unprotected & 0x0c: raise ValueError('QUIC Initial reserved bits invalid')
            pn_len = (unprotected & 3) + 1
            if pn_off+pn_len > packet_end: raise ValueError('truncated QUIC packet number')
            pn_bytes = bytes(datagram[pn_off+i] ^ mask[1+i] for i in range(pn_len))
            pn = _decode_packet_number(int.from_bytes(pn_bytes,'big'),pn_len,largest_pn)
            aad = bytes([unprotected])+datagram[start+1:pn_off]+pn_bytes
            nonce = bytes(a ^ b for a,b in zip(keys.iv,pn.to_bytes(12,'big')))
            try:
                plain = AESGCM(keys.key).decrypt(nonce,datagram[pn_off+pn_len:packet_end],aad)
            except InvalidTag as e:
                raise ValueError('QUIC Initial authentication failed (bad keys, packet or PN context)') from e
            if pn in seen: continue
            seen.add(pn)
            largest_pn = max(largest_pn,pn)
            fragments.extend(_read_crypto_frames(plain,max_hello=max_hello))
    if not fragments: return None
    hello = reassemble_segments(fragments,start_seq=0,max_bytes=max_hello)
    if len(hello) < 4: return None
    if hello[0] != 1: raise ValueError('first QUIC CRYPTO message is not ClientHello')
    n = int.from_bytes(hello[1:4],'big')
    if n > max_hello-4: raise ValueError('QUIC ClientHello too large')
    return hello[:n+4] if len(hello) >= n+4 else None


def calculate_quic_ja4(datagrams: bytes | Iterable[bytes]) -> JA4Result:
    """Analyze client QUIC v1/v2 Initial UDP payload(s) and produce JA4-Q."""
    hello = extract_quic_client_hello(datagrams)
    if hello is None: raise ValueError('QUIC ClientHello incomplete or not present')
    return _calculate_transport_ja4(hello, transport='q')
