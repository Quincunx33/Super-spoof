"""Observe a real browser's fingerprint surfaces without spoofing them.

Requires ``pip install advanced-ua-forge[browser]`` and installed Playwright browsers.
Only inspect pages you control or are authorized to test.
"""
from __future__ import annotations
from dataclasses import dataclass, asdict
from typing import Any

@dataclass(frozen=True)
class BrowserObservation:
    engine: str
    browser_version: str
    user_agent: str
    navigator_platform: str
    languages: list[str]
    webdriver: bool
    screen: dict[str, Any]
    timezone: str
    webgl: dict[str, str]
    canvas_supported: bool
    hardware_concurrency: int | None
    device_memory: float | None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)

_JS = r'''() => {
  const canvas = document.createElement('canvas');
  let gl = null, webgl = {};
  try {
    gl = canvas.getContext('webgl');
    if (gl) {
      webgl.vendor = String(gl.getParameter(gl.VENDOR));
      webgl.renderer = String(gl.getParameter(gl.RENDERER));
    }
  } catch (e) { webgl.error = String(e); }
  return {
    user_agent: navigator.userAgent,
    navigator_platform: navigator.platform,
    languages: [...navigator.languages],
    webdriver: navigator.webdriver === true,
    screen: {width: screen.width, height: screen.height,
             availWidth: screen.availWidth, availHeight: screen.availHeight,
             devicePixelRatio: devicePixelRatio},
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
    webgl,
    canvas_supported: !!canvas.getContext('2d'),
    hardware_concurrency: navigator.hardwareConcurrency ?? null,
    device_memory: navigator.deviceMemory ?? null
  };
}'''

def observe_browser(*, engine: str = "chromium", headless: bool = True) -> BrowserObservation:
    """Launch a real browser and collect local JS-observable properties.

    No UA override, JS patches, canvas noise, or TLS impersonation is applied.
    """
    if engine not in ("chromium", "firefox", "webkit"):
        raise ValueError("engine must be chromium, firefox or webkit")
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise RuntimeError("Install optional dependency: pip install '.[browser]'") from exc
    with sync_playwright() as p:
        browser = getattr(p, engine).launch(headless=headless)
        try:
            context = browser.new_context()
            page = context.new_page()
            page.goto('about:blank')
            result = page.evaluate(_JS)
            return BrowserObservation(engine=engine, browser_version=browser.version, **result)
        finally:
            browser.close()

def compare_observation(profile: Any, observation: BrowserObservation):
    """Compare a catalog profile with observed native browser properties."""
    from . import ValidationIssue, ValidationReport
    issues = []
    expected = profile.spec
    if observation.user_agent != expected.ua:
        issues.append(ValidationIssue('observed_ua_mismatch', 'Observed browser UA differs from generated UA'))
    engine_map = {'blink': 'chromium', 'gecko': 'firefox', 'webkit': 'webkit'}
    if engine_map.get(expected.engine) != observation.engine:
        issues.append(ValidationIssue('observed_engine_mismatch', 'Browser engine differs from profile'))
    if observation.screen['width'] != expected.screen[0] or observation.screen['height'] != expected.screen[1]:
        issues.append(ValidationIssue('observed_screen_difference', 'Screen dimensions differ from catalog sample', 'warning'))
    if observation.webdriver:
        issues.append(ValidationIssue('automation_observed', 'Browser reports automation through navigator.webdriver', 'warning'))
    return ValidationReport(issues)

__all__ = ['BrowserObservation', 'observe_browser', 'compare_observation']
