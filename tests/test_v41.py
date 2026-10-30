from ua_forge.tls_analysis import parse_client_hello
from ua_forge.http2_analysis import parse_settings_frame
from ua_forge.waf_events import summarize_events
from ua_forge.release_audit import audit_versions
import pytest

def test_ja3_minimal():
    body=b"\x03\x03"+bytes(32)+b"\x00"+b"\x00\x02\x13\x01"+b"\x01\x00"
    handshake=b"\x01"+len(body).to_bytes(3,"big")+body
    obs=parse_client_hello(handshake)
    assert obs.ja3=="771,4865,,,"
    assert len(obs.md5)==32

def test_ja3_rejects_truncated():
    with pytest.raises(ValueError):parse_client_hello(b"\x01\x00")

def test_http2_settings():
    frame=b"\x00\x00\x06\x04\x00\x00\x00\x00\x00\x00\x01\x00\x00\x10\x00"
    assert parse_settings_frame(frame)["settings"][0]["value"]==4096

def test_http2_invalid():
    with pytest.raises(ValueError):parse_settings_frame(b"\x00")

def test_events():
    assert summarize_events([{"action":"block","ruleId":"x"},{"Action":"allow"}])["total"]==2

def test_release_audit():
    assert any(x["major_gap"] is not None for x in audit_versions({"chrome":"140"}))
