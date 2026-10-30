"""Authorized encrypted capture analysis through a Wireshark/TShark backend.

Own-session NSS TLS key log files let an installed TShark decrypt supported
TLS/QUIC/DTLS traffic. This module intentionally returns protocol-layer
summaries, NOT private payloads, keys or HTTP contents. Keyless decryption is
not possible. QUIC/DTLS support depends on the installed Wireshark version.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path
import os
import re
import shutil
import subprocess

_SAFE_KEYLOG = re.compile(r"^[A-Z][A-Z0-9_]* [0-9a-fA-F]{64} [0-9a-fA-F]{2,256}$")
_DECODED_LAYER_NAMES = frozenset({'http','http2','http3','dns','stun','rtp','rtcp','sip','coap'})
_TRANSPORT_NAMES = frozenset({'quic','dtls','tls'})


@dataclass(frozen=True)
class EncryptedCaptureReport:
    packets_inspected: int
    tls_packets: int
    dtls_packets: int
    quic_packets: int
    decoded_application_packets: int
    decoded_protocols: tuple[str, ...]
    decryption_status: str
    warnings: tuple[str, ...]
    samples: tuple[dict, ...]

    def as_dict(self) -> dict:
        return asdict(self)


def check_tshark(binary: str = 'tshark') -> dict:
    """Check for a local TShark executable without executing a shell."""
    path = shutil.which(binary)
    if not path:
        return {'available': False, 'path': None, 'version': None,
                'message': 'TShark is not installed or is not on PATH'}
    try:
        result = subprocess.run([path, '--version'], capture_output=True, text=True,
                                timeout=8, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {'available': False, 'path': path, 'version': None, 'message': str(exc)}
    version = result.stdout.splitlines()[0][:200] if result.stdout else ''
    return {'available': result.returncode == 0, 'path': path,
            'version': version, 'message': '' if result.returncode == 0 else 'TShark failed'}


def _check_paths(capture_file: str | os.PathLike, keylog_file: str | os.PathLike,
                 max_capture_bytes: int) -> tuple[Path, Path, list[str]]:
    cap, key = Path(capture_file).expanduser().resolve(), Path(keylog_file).expanduser().resolve()
    if cap == key:
        raise ValueError('capture_file and keylog_file must be different files')
    for p, label, limit in ((cap, 'capture', max_capture_bytes), (key, 'key log', 8_388_608)):
        if not p.is_file():
            raise FileNotFoundError(f'{label} is not a regular file: {p}')
        if not 0 < p.stat().st_size <= limit:
            raise ValueError(f'{label} file size is empty or exceeds limit ({limit} bytes)')
    # PCAP magic and PCAPNG section header; does not parse packet records here.
    with cap.open('rb') as f:
        magic = f.read(4)
    if magic not in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4',
                     b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d', b'\x0a\x0d\x0d\x0a'):
        raise ValueError('input is not a PCAP or PCAPNG capture')
    warnings = []
    if os.name == 'posix' and key.stat().st_mode & 0o077:
        warnings.append('Key log file is accessible to group/other users; restrict permissions (chmod 600).')
    # Never include key contents in output, exceptions, logs, or error messages.
    with key.open('r', encoding='ascii', errors='replace') as f:
        valid = any(_SAFE_KEYLOG.fullmatch(line.strip()) for line in f if line.strip() and not line.startswith('#'))
    if not valid:
        raise ValueError('key log has no valid NSS-style TLS secret entries')
    return cap, key, warnings


def _parse_tshark_rows(rows: str, *, max_samples: int, warnings: list[str]) -> EncryptedCaptureReport:
    inspected = tls_count = dtls_count = quic_count = decoded_count = 0
    applications: set[str] = set()
    samples = []
    for line in rows.splitlines():
        columns = line.split('\t')
        if len(columns) < 2:
            continue
        frame = columns[0].strip()
        if not frame.isdecimal():
            continue
        protocols = [p.strip().lower() for p in columns[1].split(':') if p.strip()]
        layers = set(protocols)
        if not layers:
            continue
        inspected += 1
        tls_count += int('tls' in layers)
        dtls_count += int('dtls' in layers)
        quic_count += int('quic' in layers)
        visible = sorted(layers & _DECODED_LAYER_NAMES)
        if visible:
            decoded_count += 1
            applications.update(visible)
        if len(samples) < max_samples and (visible or layers & _TRANSPORT_NAMES):
            samples.append({'frame': int(frame), 'protocols': [p for p in protocols if p in (_TRANSPORT_NAMES | _DECODED_LAYER_NAMES)],
                            'decoded_application': bool(visible)})
    if not inspected:
        warnings.append('No decodable packets were returned; check capture and dissector compatibility.')
    if decoded_count == 0:
        warnings.append('No application-layer decode observed; this is not proof that TLS decryption failed.')
    # Even if application protocols appear, some may have been cleartext. This
    # only confirms protocol decode, NOT decryption of arbitrary sessions.
    warnings.append('Application-layer visibility does not by itself prove that each packet was decrypted.')
    return EncryptedCaptureReport(inspected, tls_count, dtls_count, quic_count, decoded_count,
                                  tuple(sorted(applications)),
                                  'application_decode_observed' if decoded_count else 'not_confirmed',
                                  tuple(warnings), tuple(samples))


def analyze_encrypted_capture(capture_file: str | os.PathLike,
                              keylog_file: str | os.PathLike, *,
                              tshark_binary: str = 'tshark',
                              max_packets: int = 3000,
                              max_samples: int = 50,
                              max_capture_bytes: int = 134_217_728,
                              timeout: int = 30) -> EncryptedCaptureReport:
    """Analyze PCAP/PCAPNG using a user-supplied *own-session* TLS key log.

    TShark handles decrypting supported TLS/QUIC/DTLS records with the secrets;
    the Python module only returns protocol/layer summaries. No key material or
    HTTP bodies are returned. The result is diagnostic, not a decryption proof.
    """
    if not (1 <= max_packets <= 100_000 and 0 <= max_samples <= 1000 and
            1 <= max_capture_bytes <= 1_073_741_824 and 1 <= timeout <= 300):
        raise ValueError('invalid analysis resource bounds')
    cap, key, warnings = _check_paths(capture_file, keylog_file, max_capture_bytes)
    binary = shutil.which(tshark_binary)
    if not binary:
        raise RuntimeError('TShark is required for keylog-based QUIC/DTLS analysis (install Wireshark/TShark)')
    cmd = [binary, '-n', '-r', str(cap), '-c', str(max_packets),
           '-o', f'tls.keylog_file:{key}', '-T', 'fields',
           '-E', 'separator=/t', '-e', 'frame.number', '-e', 'frame.protocols']
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError('TShark analysis timed out') from exc
    except OSError as exc:
        raise RuntimeError('TShark could not be started') from exc
    if res.returncode:
        # TShark stderr may contain sensitive local paths; don't echo it.
        raise RuntimeError(f'TShark returned exit code {res.returncode}; check capture, keylog and installed version')
    warnings.append('Only protocol metadata returned; decrypted application contents are intentionally omitted.')
    return _parse_tshark_rows(res.stdout, max_samples=max_samples, warnings=warnings)
