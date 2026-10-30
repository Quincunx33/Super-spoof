import pytest
from ua_forge.cloudflare_api import fetch_security_events
from ua_forge.live_capture import capture_client_hellos
from ua_forge.release_fetch import fetch_browser_releases
from ua_forge.ja4_analysis import ja4_diagnostic

def test_invalid_cloudflare_zone():
    with pytest.raises(ValueError): fetch_security_events('bad', 'token')

def test_capture_rejects_invalid_count():
    with pytest.raises(ValueError): capture_client_hellos('eth0', count=0)

def test_ja4_rejects_non_tls():
    with pytest.raises(ValueError): ja4_diagnostic(b'not tls')

def test_fetch_mock(monkeypatch):
    import ua_forge.release_fetch as r
    monkeypatch.setattr(r, '_json', lambda url, timeout: {'versions':[{'version':'130.0'}]} if 'googleapis' in url else {'LATEST_FIREFOX_VERSION':'131.0'})
    data=fetch_browser_releases()
    assert data['versions']=={'chrome':'130.0','firefox':'131.0'}
