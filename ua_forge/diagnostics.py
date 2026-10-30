"""Local, authorized browser and HTTP diagnostics. No challenge bypass or spoofing."""
from __future__ import annotations
from dataclasses import dataclass, asdict
from typing import Any, Mapping
import json
import ssl
import urllib.request

@dataclass(frozen=True)
class HTTPObservation:
    url: str
    status: int
    headers: dict[str, str]
    tls_version: str | None = None
    cipher: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def inspect_http(url: str, *, timeout: float = 10.0) -> HTTPObservation:
    """Inspect a URL with ordinary Python TLS; no browser impersonation.

    Only call against endpoints you own or have permission to test.
    This intentionally does not transmit generated fake UA/Client Hints.
    """
    if not url.startswith(('https://', 'http://')):
        raise ValueError('URL must be http(s)')
    if not 0 < timeout <= 60:
        raise ValueError('timeout must be within (0, 60]')
    req = urllib.request.Request(url, headers={'User-Agent': 'Advanced-UA-Forge-Diagnostics/4.0'})
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return HTTPObservation(response.geturl(), response.status, dict(response.headers.items()))


def compare_headers(expected: Mapping[str, str], actual: Mapping[str, str]) -> dict[str, Any]:
    """Compare header values case-insensitively; don't infer on-wire ordering."""
    a = {k.lower(): v for k, v in expected.items()}
    b = {k.lower(): v for k, v in actual.items()}
    return {
        'missing': sorted(k for k in a if k not in b),
        'different': {k: {'expected': a[k], 'actual': b[k]} for k in a.keys() & b.keys() if a[k] != b[k]},
        'extra': sorted(k for k in b if k not in a),
    }


def export_json(data: Any, *, indent: int = 2) -> str:
    if hasattr(data, 'as_dict'):
        data = data.as_dict()
    return json.dumps(data, ensure_ascii=False, indent=indent, sort_keys=True)
