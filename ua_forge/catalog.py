"""Verified, atomic browser catalog snapshots; no invented release versions.

Updates are opt-in and stored separately from bundled sample profiles.
Only update browser/platform combinations verified by the release source.
"""
from __future__ import annotations
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
import json
import os
import re
import tempfile
from . import SPECS, _build, BrowserSpec

_VERSION = re.compile(r'^\d+(?:\.\d+){1,3}$')


def catalog_snapshot() -> list[dict]:
    return [asdict(spec) for spec in SPECS]


def save_catalog(path: str | Path) -> None:
    Path(path).write_text(json.dumps(catalog_snapshot(), indent=2), encoding='utf-8')


def catalog_summary() -> dict:
    return {'count': len(SPECS), 'browsers': sorted({s.browser for s in SPECS}),
            'platforms': sorted({s.platform for s in SPECS}),
            'note': 'Bundled baseline samples; optional verified update available'}


def update_verified_catalog(path: str | Path, release_info: dict, *,
                            allow_major_downgrade: bool = False) -> dict:
    """Validate fetched vendor versions and atomically write an opt-in catalog.

    chrome from Google's Windows stable feed: Windows only.
    firefox from Mozilla's release channel: Windows and Linux baselines.
    Edge, Safari, Android Chrome and all unverified combinations stay pinned.
    """
    if not isinstance(release_info, dict): raise TypeError('release_info must be dict')
    versions = release_info.get('versions', {})
    errors = release_info.get('errors', {})
    if not isinstance(versions, dict) or not isinstance(errors, dict):
        raise ValueError('invalid release data')
    valid = {}
    for key in ('chrome', 'firefox'):
        raw = versions.get(key)
        if raw is None or key in errors: continue
        if not isinstance(raw, str) or not _VERSION.fullmatch(raw):
            raise ValueError(f'Invalid vendor-reported {key} version')
        valid[key] = raw
    if not valid: raise ValueError('no verified versions available; catalog unchanged')
    rows = []
    changed = []
    for item in SPECS:
        can_update = ((item.browser == 'chrome' and item.platform == 'windows') or
                      (item.browser == 'firefox' and item.platform in ('windows','linux')))
        version = valid.get(item.browser) if can_update else None
        if version and (allow_major_downgrade or int(version.split('.')[0]) >= int(item.version.split('.')[0])):
            row = (item.browser, item.platform, item.device, version,
                   item.platform_version, item.architecture, item.screen, item.model)
            replacement = _build(row)
            changed.append({'browser': item.browser, 'platform': item.platform,
                            'previous_version': item.version, 'new_version': version})
            rows.append(asdict(replacement))
        else:
            rows.append(asdict(item))
    payload = {'schema_version': 1, 'updated_at': datetime.now(timezone.utc).isoformat(),
               'source_urls': {
                 'chrome': 'https://versionhistory.googleapis.com/v1/chrome/platforms/win/channels/stable/versions?pageSize=1',
                 'firefox': 'https://product-details.mozilla.org/1.0/firefox_versions.json'},
               'updated': changed, 'profiles': rows,
               'note': 'Browser release version is not proof of locally installed binary/device compatibility'}
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix='.ua-catalog-', dir=target.parent)
    try:
        with os.fdopen(descriptor, 'w', encoding='utf-8') as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(temporary, target)
    finally:
        if os.path.exists(temporary): os.unlink(temporary)
    return {'path': str(target), 'updated': changed, 'count': len(rows)}


def load_verified_catalog(path: str | Path) -> tuple[BrowserSpec, ...]:
    obj = json.loads(Path(path).read_text(encoding='utf-8'))
    if not isinstance(obj, dict) or obj.get('schema_version') != 1:
        raise ValueError('unsupported catalog schema')
    rows = obj.get('profiles')
    if not isinstance(rows, list) or not rows or len(rows) > 10000:
        raise ValueError('invalid catalog profiles')
    specs = []
    for row in rows:
        if not isinstance(row, dict): raise ValueError('invalid profile entry')
        version = row.get('version')
        if not isinstance(version, str) or not _VERSION.fullmatch(version):
            raise ValueError('invalid profile version')
        # rebuild only from trusted, structural metadata, not supplied raw UAs
        item = _build((row['browser'], row['platform'], row['device'], version,
                       row['platform_version'], row['architecture'], tuple(row['screen']), row.get('model','')))
        if item.browser not in {'chrome','firefox','edge','safari'}:
            raise ValueError('unsupported browser')
        specs.append(item)
    return tuple(specs)


def refresh_catalog_from_vendors(path: str | Path, *, timeout: int = 10) -> dict:
    """Explicit network refresh: fetch vendor data, validate, write atomically.

    Never changes bundled SPECS or an existing UserAgent instance.
    Reinitialize UserAgent(catalog_path=...) to use a refreshed snapshot.
    """
    from .release_fetch import fetch_browser_releases
    release_data = fetch_browser_releases(timeout=timeout)
    outcome = update_verified_catalog(path, release_data)
    outcome['source_errors'] = release_data['errors']
    return outcome
