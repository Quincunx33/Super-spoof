"""Analyze exported Cloudflare-style security events offline (authorized zones only)."""
from __future__ import annotations
from collections import Counter
from collections.abc import Iterable, Mapping

def summarize_events(events: Iterable[Mapping]) -> dict:
    actions, rules, statuses = Counter(), Counter(), Counter()
    total = 0
    for event in events:
        if not isinstance(event, Mapping): raise TypeError("events must be mappings")
        total += 1
        actions[str(event.get("action", event.get("Action", "unknown")))]+=1
        rule = event.get("ruleId", event.get("RuleID"))
        if rule is not None: rules[str(rule)] += 1
        status = event.get("edgeResponseStatus", event.get("EdgeResponseStatus"))
        if status is not None: statuses[str(status)] += 1
    return {"total": total, "actions": dict(actions), "rule_ids": dict(rules), "edge_statuses": dict(statuses)}
