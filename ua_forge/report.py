"""Structured cross-layer local inspection report."""
from __future__ import annotations
from . import UAProfile
from .catalog import catalog_summary
from .native import ssl_capabilities

def local_report(profile: UAProfile) -> dict:
    return {'profile': profile.metadata, 'user_agent': profile.user_agent,
            'headers': profile.headers, 'validation': profile.validate().as_dict(),
            'native_tls': ssl_capabilities(), 'catalog': catalog_summary(),
            'scope': 'Local compatibility diagnostics; not an anti-bot bypass assessment'}
