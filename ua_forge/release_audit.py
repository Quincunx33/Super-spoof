"""Audit catalog age against an explicitly supplied, verified release manifest."""
from __future__ import annotations
from collections.abc import Mapping
from .catalog import catalog_snapshot

def audit_versions(releases: Mapping[str,str]) -> list[dict]:
    """releases: browser name -> verified major version (not fetched automatically)."""
    results=[]
    for spec in catalog_snapshot():
        browser=spec["browser"]
        latest=releases.get(browser)
        major=int(spec["version"].split(".")[0])
        expected=int(str(latest).split(".")[0]) if latest is not None else None
        results.append({"browser":browser,"platform":spec["platform"],"catalog_version":spec["version"],"reference_version":latest,"major_gap":expected-major if expected is not None else None})
    return results
