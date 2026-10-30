"""Fetch vendor-published release information with bounded requests; no UA fabrication."""
from __future__ import annotations
import json
from urllib.request import Request, urlopen

def _json(url: str, timeout: int):
    if not 1 <= timeout <= 60: raise ValueError('timeout must be 1..60 seconds')
    with urlopen(Request(url, headers={'User-Agent': 'Advanced-UA-Forge/4.3 (release-audit)'}), timeout=timeout) as response:
        return json.load(response)

def fetch_browser_releases(*, timeout: int = 10) -> dict:
    """Fetch Chrome stable and Firefox current versions. Per-source errors are explicit."""
    result = {'versions': {}, 'errors': {}}
    sources = {
        'chrome': 'https://versionhistory.googleapis.com/v1/chrome/platforms/win/channels/stable/versions?pageSize=1',
        'firefox': 'https://product-details.mozilla.org/1.0/firefox_versions.json',
    }
    for browser, url in sources.items():
        try:
            obj = _json(url, timeout)
            version = obj['versions'][0]['version'] if browser == 'chrome' else obj['LATEST_FIREFOX_VERSION']
            result['versions'][browser] = version
        except (OSError, ValueError, KeyError, IndexError, TypeError) as exc:
            result['errors'][browser] = str(exc)
    result['not_supported'] = ['edge', 'safari']
    return result
