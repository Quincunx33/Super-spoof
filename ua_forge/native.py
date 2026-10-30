"""Native SSL capability inspection. This does not emulate a browser TLS stack."""
from __future__ import annotations
import ssl

def ssl_capabilities() -> dict:
    ctx = ssl.create_default_context()
    return {'openssl': ssl.OPENSSL_VERSION, 'tls13_supported': getattr(ssl, 'HAS_TLSv1_3', False),
            'cipher_names': [c['name'] for c in ctx.get_ciphers()],
            'alpn_supported': getattr(ssl, 'HAS_ALPN', False),
            'note': 'Local OpenSSL capabilities, not JA3/JA4 of a live connection'}
