from ua_forge import UserAgent
from ua_forge.catalog import catalog_summary, catalog_snapshot
from ua_forge.diagnostics import compare_headers, export_json, inspect_http
from ua_forge.native import ssl_capabilities
from ua_forge.report import local_report
import pytest

def test_report():
    p = UserAgent(seed=2).profile(browser='chrome')
    r = local_report(p)
    assert r['validation']['valid']
    assert 'OpenSSL' in r['native_tls']['openssl']
    assert 'profile' in export_json(r)

def test_header_diff():
    diff = compare_headers({'User-Agent':'a','Accept':'x'}, {'user-agent':'b','Other':'y'})
    assert diff['missing'] == ['accept']
    assert diff['different']['user-agent']['actual'] == 'b'
    assert diff['extra'] == ['other']

def test_catalog():
    assert catalog_summary()['count'] == len(catalog_snapshot())

def test_invalid_url():
    with pytest.raises(ValueError):
        inspect_http('file:///etc/passwd')
