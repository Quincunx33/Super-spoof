"""Keylog-assisted capture summaries, CLI and capability tests (no live network needed)."""
import os
from pathlib import Path
import struct
from types import SimpleNamespace
import pytest
from ua_forge.encrypted_capture import (
    analyze_encrypted_capture, _parse_tshark_rows, check_tshark
)
from ua_forge.capture_selftest import verify_loopback_capture, capture_capabilities


@pytest.fixture
def capture_files(tmp_path):
    cap = tmp_path / 'capture.pcap'
    cap.write_bytes(b'\xd4\xc3\xb2\xa1'+b'\x00'*20)
    key = tmp_path / 'own-session.keys'
    key.write_text('CLIENT_TRAFFIC_SECRET_0 '+'a'*64+' '+'b'*64+'\n')
    key.chmod(0o600)
    return cap, key


def test_tshark_keylog_analysis(monkeypatch, capture_files):
    cap, key = capture_files
    from ua_forge import encrypted_capture as ec
    commands = []
    monkeypatch.setattr(ec.shutil, 'which', lambda name: '/usr/bin/tshark')
    def fake_run(cmd, **kw):
        commands.append(cmd)
        assert kw['timeout'] == 30 and not kw['check']
        return SimpleNamespace(returncode=0, stdout=(
            '1\teth:ip:udp:quic\n'
            '2\teth:ip:udp:quic:http3\n'
            '3\teth:ip:udp:dtls\n'
            '4\teth:ip:tcp:tls:http2\n'), stderr='')
    monkeypatch.setattr(ec.subprocess, 'run', fake_run)
    report = analyze_encrypted_capture(cap, key, max_samples=3)
    assert report.packets_inspected == 4
    assert report.quic_packets == 2 and report.dtls_packets == 1
    assert report.tls_packets == 1
    assert report.decoded_application_packets == 2
    assert report.decoded_protocols == ('http2', 'http3')
    assert report.decryption_status == 'application_decode_observed'
    assert len(report.samples) == 3
    assert '-r' in commands[0] and str(cap) in commands[0]
    assert f'tls.keylog_file:{key}' in commands[0]
    assert not any('bbbbbb' in str(report.as_dict()) for _ in (0,))


def test_keylog_file_permissions_warning(monkeypatch, capture_files):
    cap, key = capture_files
    key.chmod(0o644)
    from ua_forge import encrypted_capture as ec
    monkeypatch.setattr(ec.shutil, 'which', lambda _: '/mock/tshark')
    monkeypatch.setattr(ec.subprocess, 'run', lambda *a, **kw: SimpleNamespace(returncode=0,stdout='1\teth:ip:udp:quic\n',stderr=''))
    result = analyze_encrypted_capture(cap, key)
    assert any('chmod 600' in x for x in result.warnings)
    assert result.decryption_status == 'not_confirmed'


@pytest.mark.parametrize('bad', ['bad format', 'CLIENT_TRAFFIC_SECRET_0 '+ 'a'*64+' not_hex'])
def test_keylog_reject_invalid(monkeypatch, capture_files, bad):
    cap, key = capture_files
    key.write_text(bad)
    with pytest.raises(ValueError,match='valid NSS-style'):
        analyze_encrypted_capture(cap,key)


def test_non_pcap_rejected(capture_files):
    cap,key=capture_files
    cap.write_bytes(b'wrong file')
    with pytest.raises(ValueError,match='not a PCAP'):
        analyze_encrypted_capture(cap,key)


def test_missing_keylog_rejected(capture_files):
    cap,key=capture_files
    key.unlink()
    with pytest.raises(FileNotFoundError,match='key log'):
        analyze_encrypted_capture(cap,key)


def test_tshark_missing(monkeypatch,capture_files):
    cap,key=capture_files
    from ua_forge import encrypted_capture as ec
    monkeypatch.setattr(ec.shutil,'which',lambda *a:None)
    with pytest.raises(RuntimeError,match='TShark is required'):
        analyze_encrypted_capture(cap,key)
    assert check_tshark('no-such-binary')['available'] is False


def test_tshark_failure_does_not_disclose_keylog(monkeypatch,capture_files):
    cap,key=capture_files
    from ua_forge import encrypted_capture as ec
    monkeypatch.setattr(ec.shutil,'which',lambda *a:'/usr/bin/tshark')
    monkeypatch.setattr(ec.subprocess,'run', lambda *a, **kw:SimpleNamespace(returncode=3,stdout='',stderr=str(key)+' secret-secret'))
    with pytest.raises(RuntimeError) as exc:
        analyze_encrypted_capture(cap,key)
    assert 'secret-secret' not in str(exc.value)
    assert str(key) not in str(exc.value)


def test_tshark_timeout(monkeypatch,capture_files):
    import subprocess
    from ua_forge import encrypted_capture as ec
    cap,key=capture_files
    monkeypatch.setattr(ec.shutil,'which',lambda *a:'/mock/tshark')
    def boom(*a,**kw):
        raise subprocess.TimeoutExpired(cmd=['tshark'],timeout=2)
    monkeypatch.setattr(ec.subprocess,'run',boom)
    with pytest.raises(RuntimeError,match='timed out'):
        analyze_encrypted_capture(cap,key)


def test_row_count_and_sample_bounds():
    report=_parse_tshark_rows('1\teth:ip:quic:http3\n2\teth:ip:dtls\n3\teth:ip:quic\n', max_samples=1,warnings=[])
    assert report.packets_inspected == 3
    assert len(report.samples)==1
    assert report.quic_packets==2


def test_empty_row_warning():
    report=_parse_tshark_rows('',max_samples=50,warnings=[])
    assert report.packets_inspected==0
    assert 'not_confirmed'==report.decryption_status
    assert any('No decodable packets' in s for s in report.warnings)


def test_live_test_interface_validation():
    with pytest.raises(ValueError,match='loopback'):
        verify_loopback_capture(interface='eth0')
    with pytest.raises(ValueError,match='timeout'):
        verify_loopback_capture(timeout=0)


def test_capture_capability_report_keys():
    report=capture_capabilities()
    assert isinstance(report['scapy_installed'],bool)
    assert isinstance(report['raw_packet_socket_available'],bool)
    assert isinstance(report['tshark_available'],bool)


def test_public_api():
    import ua_forge
    for name in ('analyze_encrypted_capture', 'capture_capabilities',
                 'verify_loopback_capture', 'check_tshark'):
        assert callable(getattr(ua_forge, name))
    assert ua_forge.__version__=='4.5.0'


def test_analysis_bounds(capture_files):
    cap,key=capture_files
    with pytest.raises(ValueError,match='bounds'):
        analyze_encrypted_capture(cap,key,max_packets=0)
    with pytest.raises(ValueError,match='bounds'):
        analyze_encrypted_capture(cap,key,max_samples=1001)
