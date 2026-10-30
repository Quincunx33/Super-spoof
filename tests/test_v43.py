"""v4.3 tests operate entirely offline with synthetic, permitted data."""
from __future__ import annotations
import hashlib
import json
import pytest

from ua_forge.ja4_analysis import calculate_ja4, ja4_diagnostic
from ua_forge.tcp_reassembly import reassemble_segments, extract_client_hello, TCPStream
from ua_forge.catalog import update_verified_catalog, load_verified_catalog
from ua_forge import UserAgent
from ua_forge.cloudflare_api import fetch_security_events_paginated


def vec(data, width=2): return len(data).to_bytes(width, 'big') + data

def make_hello(ciphers=(0x1301,0x1302,0x1303,0x0a0a), extra_exts=None):
    sigs = (0x0403,0x0804,0x0401)
    ext_list = [
        (0, b''),
        (16, vec(vec(b'h2',1))),
        (43, vec(b'\x03\x04\x03\x03',1)),
        (13, vec(b''.join(n.to_bytes(2,'big') for n in sigs))),
        (0x1a1a, b''),
    ]
    if extra_exts is not None: ext_list = extra_exts
    exts = b''.join(n.to_bytes(2,'big') + vec(body) for n,body in ext_list)
    body = (b'\x03\x03' + b'\0'*32 + vec(b'',1) +
            vec(b''.join(n.to_bytes(2,'big') for n in ciphers)) + vec(b'\x00',1) + vec(exts))
    return b'\x01' + len(body).to_bytes(3, 'big') + body


def tls_record(payload): return b'\x16\x03\x01' + vec(payload)


def test_ja4_canonical_expected():
    hello = make_hello()
    value = calculate_ja4(tls_record(hello))
    assert value.ja4.startswith('t13d0304h2_')
    assert value.ja4.split('_')[1] == hashlib.sha256('1301,1302,1303'.encode()).hexdigest()[:12]
    assert value.ja4.split('_')[2] == hashlib.sha256('000d,002b_0403,0804,0401'.encode()).hexdigest()[:12]
    assert ja4_diagnostic(hello)['standard_compliant']


def test_ja4_shuffled_grease_consistency():
    hello_a = make_hello()
    ext = [(0x1a1a,b''),(13,vec(b'\x04\x03\x08\x04\x04\x01')),
           (43,vec(b'\x03\x04\x03\x03',1)),(16,vec(vec(b'h2',1))),(0,b'')]
    hello_b = make_hello(ciphers=(0x1303,0x1301,0x0a0a,0x1302), extra_exts=ext)
    assert calculate_ja4(hello_a).ja4 == calculate_ja4(hello_b).ja4


def test_ja4_missing_sni_alpn():
    ext = [(43,vec(b'\x03\x04',1))]
    val = calculate_ja4(make_hello(extra_exts=ext))
    assert val.ja4.startswith('t13i030100_')
    assert val.ja4.split('_')[2] != '000000000000'  # supported_versions remains


def test_ja4_malformed_and_no_quic():
    with pytest.raises(ValueError): calculate_ja4(make_hello()[:-3])
    with pytest.raises(ValueError): calculate_ja4(make_hello(), transport='q')


def test_tcp_out_of_order_duplicate_conflict():
    assert reassemble_segments([(104,b'ef'),(100,b'abcd'),(102,b'cdef')]) == b'abcdef'
    assert reassemble_segments([(100,b'ab'),(104,b'ef')]) == b'ab'
    with pytest.raises(ValueError): reassemble_segments([(100,b'ab'),(101,b'x')])
    with pytest.raises(ValueError): reassemble_segments([(0,b'x'*12)], max_bytes=10)


def test_split_tls_across_tcp_segments_and_tls_records():
    hello = make_hello()
    wire = tls_record(hello[:17]) + tls_record(hello[17:])
    s = TCPStream(start_seq=1000)
    s.feed(1020,wire[20:])
    assert extract_client_hello(s.data()) is None
    s.feed(1000,wire[:20])
    assert extract_client_hello(s.data()) == hello
    assert calculate_ja4(extract_client_hello(s.data())).ja4.startswith('t13')


def test_catalog_update_opt_in_atomic(tmp_path):
    path = tmp_path/'latest.json'
    latest = {'versions': {'chrome':'155.0.0.0', 'firefox':'159.0'},'errors': {}}
    report = update_verified_catalog(path, latest)
    assert len(report['updated']) == 3
    specs = load_verified_catalog(path)
    assert UserAgent(catalog_path=str(path)).profile(browser='chrome',platform='windows').spec.version == '155.0.0.0'
    assert next(s for s in specs if s.browser=='chrome' and s.platform=='android').version == '134.0.0.0'
    assert next(s for s in specs if s.browser=='safari').version == '17.6'
    prev = path.read_bytes()
    with pytest.raises(ValueError): update_verified_catalog(path, {'versions':{'chrome':'155.0.0.0\r\n'}, 'errors': {}})
    assert path.read_bytes() == prev
    with pytest.raises(ValueError): update_verified_catalog(path, {'errors':{'chrome':'timeout'},'versions':{}})


def test_graphql_pages_and_boundary_warning(monkeypatch):
    import ua_forge.cloudflare_api as api
    calls=[]
    def fake(token, variables, timeout):
        calls.append(variables)
        if len(calls)==1:
            data=[{'datetime':'2026-10-29T12:00:02Z','action':'block'},
                  {'datetime':'2026-10-29T12:00:01Z','action':'allow'}]
        else: data=[{'datetime':'2026-10-29T12:00:00Z','action':'challenge'}]
        return {'data':{'viewer':{'zones':[{'firewallEventsAdaptive':data}]}}}
    monkeypatch.setattr(api,'_api_post',fake)
    output=fetch_security_events_paginated('a'*32,'secret',start='2026-10-29T11:00:00Z',
                                          end='2026-10-29T13:00:00Z',page_size=2,max_pages=3)
    assert output['pages_fetched']==2 and output['summary']['total']==3
    assert output['complete'] is False and output['warnings']
    assert calls[1]['filter']['datetime_leq'] < calls[0]['filter']['datetime_leq']


def test_graphql_reject_invalid_and_error(monkeypatch):
    import ua_forge.cloudflare_api as api
    with pytest.raises(ValueError): fetch_security_events_paginated('bad','x',start='x',end='y')
    with pytest.raises(ValueError): fetch_security_events_paginated('a'*32,'x',start='2026-10-01T00:00:00Z',end='2026-11-02T00:00:00Z')
    monkeypatch.setattr(api,'_api_post',lambda *args: {'errors':[{'message':'permission denied'}]})
    with pytest.raises(RuntimeError): fetch_security_events_paginated('a'*32,'x',start='2026-10-29T11:00:00Z',end='2026-10-29T13:00:00Z')


def test_official_ja4_documentation_vector():
    # FoxIO JA4.md official sorted cipher + extension + signature algorithm example.
    ciphers = [0x1301,0x1302,0x1303,0xc02b,0xc02f,0xc02c,0xc030,0xcca9,
               0xcca8,0xc013,0xc014,0x009c,0x009d,0x002f,0x0035]
    extensions = [0x001b,0x0000,0x0033,0x0010,0x4469,0x0017,0x002d,0x000d,
                  0x0005,0x0023,0x0012,0x002b,0xff01,0x000b,0x000a,0x0015]
    signatures = [0x0403,0x0804,0x0401,0x0503,0x0805,0x0501,0x0806,0x0601]
    bodies = {0x0010:vec(vec(b'h2',1)),
              0x002b:vec(b'\x03\x04\x03\x03',1),
              0x000d:vec(b''.join(v.to_bytes(2,'big') for v in signatures))}
    ext = [(n,bodies.get(n,b'')) for n in extensions]
    ja4 = calculate_ja4(make_hello(ciphers, ext))
    assert ja4.ja4 == 't13d1516h2_8daaf6152771_e5627efa2ab1'
