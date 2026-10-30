"""Read-only Cloudflare Security Events via documented GraphQL Analytics API.

Only for zones administered by the API token holder. Bounded pagination.
See https://developers.cloudflare.com/analytics/graphql-api/features/pagination/
"""
from __future__ import annotations
from datetime import datetime, timedelta, timezone
import json
import re
from urllib.request import Request, urlopen
from .waf_events import summarize_events

_ZONE = re.compile(r'^[0-9a-fA-F]{32}$')
_ENDPOINT = 'https://api.cloudflare.com/client/v4/graphql'
_QUERY = '''query($zoneTag: string!, $filter: FirewallEventsAdaptiveFilter_InputObject, $pageSize: Int!) {
 viewer { zones(filter: {zoneTag: $zoneTag}) {
  firewallEventsAdaptive(filter: $filter, limit: $pageSize, orderBy: [datetime_DESC]) {
   datetime action source clientAsn clientCountryName clientIP clientRequestPath userAgent
  }
 } }
}'''


def _timestamp(value: str) -> datetime:
    if not isinstance(value, str): raise ValueError('timestamp must be an ISO-8601 string')
    try: parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError as exc: raise ValueError('invalid timestamp') from exc
    if parsed.tzinfo is None: raise ValueError('timezone required in timestamp')
    return parsed.astimezone(timezone.utc)


def _api_post(api_token: str, variables: dict, timeout: int) -> dict:
    body = json.dumps({'query': _QUERY, 'variables': variables}).encode('utf-8')
    request = Request(_ENDPOINT, data=body, method='POST', headers={
        'Authorization': f'Bearer {api_token}', 'Accept': 'application/json',
        'Content-Type': 'application/json', 'User-Agent': 'Advanced-UA-Forge/4.3'})
    with urlopen(request, timeout=timeout) as response:
        return json.load(response)


def fetch_security_events_paginated(zone_id: str, api_token: str, *,
                                     start: str, end: str, page_size: int = 100,
                                     max_pages: int = 5, timeout: int = 15) -> dict:
    """Fetch time-bounded Security Events pages with no undocumented REST endpoint.

    Cloudflare GraphQL does *not* offer cursors. A strict datetime_lt boundary
    may omit rows tied on the same timestamp; a warning is included for
    every full page and `complete` is False if a boundary was traversed.
    This is a bounded diagnostics sample, not an exhaustive audit export.
    """
    if not _ZONE.fullmatch(zone_id): raise ValueError('zone_id must be 32 hex digits')
    if not api_token: raise ValueError('API token required')
    if not 1 <= page_size <= 1000: raise ValueError('page_size must be 1..1000')
    if not 1 <= max_pages <= 100: raise ValueError('max_pages must be 1..100')
    if not 1 <= timeout <= 60: raise ValueError('timeout must be 1..60')
    lower, upper = _timestamp(start), _timestamp(end)
    if upper <= lower or upper-lower > timedelta(days=30):
        raise ValueError('require a positive time window no longer than 30 days')
    def utc(v): return v.isoformat(timespec='microseconds').replace('+00:00','Z')
    lower_txt, upper_txt = utc(lower), utc(upper)
    events, warnings = [], []
    pages = 0
    reached_end = False
    for _ in range(max_pages):
        variables = {'zoneTag': zone_id, 'pageSize': page_size,
                     'filter': {'datetime_geq': lower_txt, 'datetime_leq': upper_txt}}
        payload = _api_post(api_token, variables, timeout)
        if payload.get('errors'):
            # Do not print credentials, full raw API content, or sensitive body.
            raise RuntimeError('Cloudflare GraphQL returned errors; inspect zone permissions/schema')
        try:
            zones = payload['data']['viewer']['zones']
            if len(zones) != 1: raise ValueError('expected exactly one authorized zone')
            page = zones[0]['firewallEventsAdaptive']
        except (KeyError, TypeError, IndexError) as exc:
            raise ValueError('unexpected Cloudflare GraphQL response shape') from exc
        if not isinstance(page, list): raise ValueError('events must be a list')
        pages += 1
        if any(not isinstance(item, dict) or not isinstance(item.get('datetime'), str) for item in page):
            raise ValueError('event datetime missing')
        events.extend(page)
        if len(page) < page_size:
            reached_end = True
            break
        latest = min(_timestamp(item['datetime']) for item in page)
        if latest < lower: raise ValueError('API returned event outside requested window')
        # No stable, unique cursor is exposed. Strict inequality avoids endless
        # repeats, at the cost of possibly omitting events with same timestamp.
        warnings.append('Full page boundary may omit additional events sharing its final timestamp')
        if latest <= lower: reached_end = True; break
        next_upper = latest - timedelta(microseconds=1)
        if next_upper <= lower: reached_end = True; break
        upper_txt = utc(next_upper)
    if not reached_end: warnings.append('Stopped at configured max_pages; additional events may exist')
    return {'events': events, 'summary': summarize_events(events), 'pages_fetched': pages,
            'complete': reached_end and not warnings, 'warnings': sorted(set(warnings)),
            'pagination': 'GraphQL datetime boundary (not a cursor)',
            'note': 'Cloudflare data may be sampled; use narrower windows for investigations'}


def fetch_security_events(zone_id: str, api_token: str, *, per_page: int = 50,
                          timeout: int = 15, start: str | None = None,
                          end: str | None = None, max_pages: int = 1) -> dict:
    """Backward-compatible wrapper. Default observation window is last hour."""
    now = datetime.now(timezone.utc)
    end = end or now.isoformat()
    start = start or (now-timedelta(hours=1)).isoformat()
    return fetch_security_events_paginated(zone_id, api_token, start=start, end=end,
                                           page_size=per_page, timeout=timeout,
                                           max_pages=max_pages)
