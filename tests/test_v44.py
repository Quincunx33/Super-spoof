"""v4.4 offline QUIC/DTLS tests including RFC 9001 key vector and synthetic AEAD packets."""
import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ua_forge.dtls_analysis import calculate_dtls_ja4, extract_dtls_client_hello
from ua_forge.quic_analysis import (derive_initial_keys, extract_quic_client_hello,
                                    calculate_quic_ja4)
from ua_forge.ja4_analysis import calculate_ja4
from test_v43 import make_hello, vec


def _record(fragment, *, seq=0):
    return b'\x16\xfe\xfd' + b'\x00\x00' + seq.to_bytes(6,'big') + len(fragment).to_bytes(2,'big') + fragment


def _dtls_piece(body, off, n, *, seq=0):
    return (b'\x01' + len(body).to_bytes(3,'big') + seq.to_bytes(2,'big') +
            off.to_bytes(3,'big') + n.to_bytes(3,'big') + body[off:off+n])


def _dtls_body(hello):
    body = hello[4:]
    return body[:35]+b'\x00'+body[35:]  # empty DTLS legacy_cookie


def test_dtls_fragmented_reordered_client_hello():
    hello = make_hello(extra_exts=[(0,b''),(16,vec(vec(b'h2',1))),
                                 (43,vec(b'\xfe\xfc\xfe\xfd',1)),
                                 (13,vec(b'\x04\x03\x08\x04\x04\x01'))])
    body = _dtls_body(hello)
    body = b'\xfe\xfd'+body[2:]  # DTLS 1.3 legacy_version
    mid = len(body)//2
    fragments = [_record(_dtls_piece(body,0,mid)),
                 _record(_dtls_piece(body,mid,len(body)-mid),seq=1)]
    assert extract_dtls_client_hello(fragments[::-1]) == b'\x01'+len(body).to_bytes(3,'big')+body
    result = calculate_dtls_ja4(fragments[::-1])
    assert result.ja4.startswith('dd3d0304h2_')
    assert result.ja4.split('_')[1:] == calculate_ja4(hello).ja4.split('_')[1:]


def test_dtls13_wire_version_and_cookie():
    hello = make_hello(extra_exts=[(43,vec(b'\xfe\xfc\xfe\xfd',1))])
    body = _dtls_body(hello)
    body = b'\xfe\xfd'+body[2:]
    result = calculate_dtls_ja4(_record(_dtls_piece(body,0,len(body))))
    assert result.ja4.startswith('dd3i030100_')


def test_dtls_incomplete_conflicting_and_bounds():
    body = _dtls_body(make_hello())
    first = _record(_dtls_piece(body,0,16))
    assert extract_dtls_client_hello(first) is None
    bad = bytearray(body)
    bad[5] ^= 1
    overlap = _record(_dtls_piece(bytes(bad),0,16),seq=1)
    with pytest.raises(ValueError,match='conflicting'):
        extract_dtls_client_hello([first,overlap])
    with pytest.raises(ValueError,match='truncated'):
        extract_dtls_client_hello(first[:-1])
    with pytest.raises(ValueError,match='incomplete'):
        calculate_dtls_ja4(first)


def _vint(n):
    if n < 64: return bytes([n])
    if n < 16384: return (n|0x4000).to_bytes(2,'big')
    raise ValueError('test fixture too large')


def _encrypt_initial(frames, *, pn=0, version=1, dcid=bytes.fromhex('8394c8f03e515708')):
    keys = derive_initial_keys(dcid,version=version)
    pnlen=2
    initial_type = 0xc0 if version == 1 else 0xd0
    first=initial_type|(pnlen-1)
    body = (bytes([first])+version.to_bytes(4,'big')+bytes([len(dcid)])+dcid+
            b'\x00'+b'\x00')
    payload_len = pnlen+len(frames)+16
    prefix=body+_vint(payload_len)
    pnbytes = pn.to_bytes(pnlen,'big')
    nonce=bytes(a^b for a,b in zip(keys.iv,pn.to_bytes(12,'big')))
    ciphertext = AESGCM(keys.key).encrypt(nonce,frames,prefix+pnbytes)
    raw=bytearray(prefix+pnbytes+ciphertext)
    pn_start=len(prefix)
    sample=bytes(raw[pn_start+4:pn_start+20])
    encryptor=Cipher(algorithms.AES(keys.hp),modes.ECB()).encryptor()
    mask=encryptor.update(sample)+encryptor.finalize()
    raw[0] ^= mask[0]&0x0f
    for k in range(pnlen):raw[pn_start+k]^=mask[k+1]
    return bytes(raw)


def _crypto(offset, data):
    return b'\x06'+_vint(offset)+_vint(len(data))+data


def test_rfc9001_v1_initial_key_reference():
    k = derive_initial_keys(bytes.fromhex('8394c8f03e515708'))
    assert k.key.hex() == '1f369613dd76d5467730efcbe3b1a22d'
    assert k.iv.hex() == 'fa044b2f42a3fd3b46fb255c'
    assert k.hp.hex() == '9f50449e04a0e810283a1e9933adedd2'


@pytest.mark.parametrize('version', [1, 0x6b3343cf])
def test_quic_v1_v2_client_initial_roundtrip(version):
    hello = make_hello()
    datagram = _encrypt_initial(_crypto(0,hello)+b'\x00'*50,version=version)
    assert extract_quic_client_hello(datagram) == hello
    fp=calculate_quic_ja4(datagram)
    assert fp.ja4.startswith('q13d0304h2_')
    assert fp.ja4[1:] == calculate_ja4(hello).ja4[1:]


def test_quic_crypto_out_of_order_and_coalesced():
    hello=make_hello()
    n=len(hello)//2
    packet0=_encrypt_initial(_crypto(0,hello[:n]),pn=0)
    packet1=_encrypt_initial(_crypto(n,hello[n:]),pn=1)
    assert extract_quic_client_hello([packet1,packet0])==hello
    assert extract_quic_client_hello(packet0+packet1)==hello
    assert extract_quic_client_hello([packet0,packet0,packet1])==hello
    assert extract_quic_client_hello(packet0) is None


def test_quic_invalid_tag_version_flow_and_limits():
    packet=_encrypt_initial(_crypto(0,make_hello()))
    invalid=packet[:-1]+bytes([packet[-1]^1])
    with pytest.raises(ValueError,match='authentication failed'):
        extract_quic_client_hello(invalid)
    with pytest.raises(ValueError,match='unsupported QUIC version'):
        extract_quic_client_hello(packet[:1]+(5).to_bytes(4,'big')+packet[5:])
    with pytest.raises(ValueError,match='mixed QUIC Initial connections'):
        extract_quic_client_hello([packet,_encrypt_initial(_crypto(0,make_hello()),dcid=b'otherid0')])
    with pytest.raises(ValueError,match='configured maximum'):
        extract_quic_client_hello(_encrypt_initial(_crypto(0,make_hello())),max_hello=10)


def test_udp_auto_inspector():
    from ua_forge import analyze_udp_datagrams
    hello=make_hello()
    packet=_encrypt_initial(_crypto(0,hello))
    result=analyze_udp_datagrams([packet])
    assert result['protocol']=='quic' and result['ja4'].startswith('q13')
    body=_dtls_body(hello)
    datagram=_record(_dtls_piece(body,0,len(body)))
    result=analyze_udp_datagrams([datagram])
    assert result['protocol']=='dtls' and result['ja4'].startswith('d')
    with pytest.raises(ValueError,match='unrecognized'):
        analyze_udp_datagrams([b'hello'])


def test_rfc9369_quic_v2_initial_keys_reference():
    k = derive_initial_keys(bytes.fromhex('8394c8f03e515708'), version=0x6b3343cf)
    assert k.key.hex() == '8b1a0bc121284290a29e0971b5cd045d'
    assert k.iv.hex() == '91f73e2351d8fa91660e909f'
    assert k.hp.hex() == '45b95e15235d6f45a6b19cbcb0294ba9'
