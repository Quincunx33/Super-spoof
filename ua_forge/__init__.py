"""Advanced UA Forge: coherent, offline browser identity metadata.

This library does not modify TLS, IP, JavaScript runtime, or browser behavior.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import random
import re
from typing import Mapping

__version__ = "4.5.0"

@dataclass(frozen=True)
class BrowserSpec:
    browser: str
    platform: str
    device: str
    version: str
    ua: str
    mobile: bool
    engine: str
    architecture: str
    platform_version: str
    screen: tuple[int, int]
    model: str = ""

@dataclass(frozen=True)
class ValidationIssue:
    code: str
    message: str
    severity: str = "error"

@dataclass
class ValidationReport:
    issues: list[ValidationIssue] = field(default_factory=list)

    @property
    def valid(self) -> bool:
        return not any(i.severity == "error" for i in self.issues)

    def as_dict(self) -> dict:
        return {"valid": self.valid, "issues": [vars(i) for i in self.issues]}

@dataclass(frozen=True)
class UAProfile:
    spec: BrowserSpec
    headers: dict[str, str]

    @property
    def user_agent(self) -> str:
        return self.spec.ua

    @property
    def metadata(self) -> dict:
        s = self.spec
        return {"browser": s.browser, "version": s.version, "platform": s.platform,
                "platform_version": s.platform_version, "device": s.device,
                "mobile": s.mobile, "engine": s.engine, "architecture": s.architecture,
                "screen": {"width": s.screen[0], "height": s.screen[1]}, "model": s.model}

    def validate(self, headers: Mapping[str, str] | None = None, *,
                 screen: tuple[int, int] | None = None,
                 runtime: Mapping[str, str] | None = None) -> ValidationReport:
        return validate(self, headers=headers, screen=screen, runtime=runtime)

# Version numbers are explicit catalog samples, not claims of latest installed versions.
# Keep catalog updated independently as browser releases change.
_CATALOG = (
    ("chrome", "windows", "desktop", "134.0.0.0", "10.0", "x86", (1920, 1080), ""),
    ("chrome", "macos", "desktop", "134.0.0.0", "14.0", "arm", (1512, 982), ""),
    ("chrome", "linux", "desktop", "134.0.0.0", "6.0", "x86", (1920, 1080), ""),
    ("chrome", "android", "mobile", "134.0.0.0", "14", "arm", (412, 915), "Pixel 8"),
    ("chrome", "android", "tablet", "134.0.0.0", "14", "arm", (800, 1280), "SM-X700"),
    ("edge", "windows", "desktop", "134.0.0.0", "10.0", "x86", (1920, 1080), ""),
    ("firefox", "windows", "desktop", "136.0", "10.0", "x86", (1920, 1080), ""),
    ("firefox", "linux", "desktop", "136.0", "6.0", "x86", (1920, 1080), ""),
    ("safari", "macos", "desktop", "17.6", "14.0", "arm", (1512, 982), ""),
    ("safari", "ios", "mobile", "17.6", "17.6", "arm", (390, 844), "iPhone"),
    ("safari", "ios", "tablet", "17.6", "17.6", "arm", (820, 1180), "iPad"),
)

def _build(row: tuple) -> BrowserSpec:
    browser, platform, device, version, osver, arch, screen, model = row
    major = version.split(".")[0]
    if platform == "windows":
        os_token = "Windows NT 10.0; Win64; x64"
    elif platform == "macos":
        os_token = "Macintosh; Intel Mac OS X 10_15_7"
    elif platform == "linux":
        os_token = "X11; Linux x86_64"
    elif platform == "android":
        os_token = f"Linux; Android {osver}; {model}"
    else:
        os_token = (f"iPhone; CPU iPhone OS {osver.replace('.', '_')} like Mac OS X" if device == "mobile"
                    else f"iPad; CPU OS {osver.replace('.', '_')} like Mac OS X")
    if browser in ("chrome", "edge"):
        mobile_token = " Mobile" if device == "mobile" else ""
        ua = (f"Mozilla/5.0 ({os_token}) AppleWebKit/537.36 (KHTML, like Gecko) "
              f"Chrome/{version}{mobile_token} Safari/537.36")
        if browser == "edge":
            ua += f" Edg/{version}"
        engine = "blink"
    elif browser == "firefox":
        ua = f"Mozilla/5.0 ({os_token}; rv:{major}.0) Gecko/20100101 Firefox/{version}"
        engine = "gecko"
    else:
        if platform == "ios":
            ua = (f"Mozilla/5.0 ({os_token}) AppleWebKit/605.1.15 (KHTML, like Gecko) "
                  f"Version/{version} Mobile/15E148 Safari/604.1")
        else:
            ua = (f"Mozilla/5.0 ({os_token}) AppleWebKit/605.1.15 (KHTML, like Gecko) "
                  f"Version/{version} Safari/605.1.15")
        engine = "webkit"
    return BrowserSpec(browser, platform, device, version, ua, device == "mobile", engine, arch, osver, screen, model)

SPECS = tuple(_build(row) for row in _CATALOG)

def _language(locale: str) -> str:
    known = {"bd": "bn-BD,bn;q=0.9,en-US;q=0.8,en;q=0.7",
             "global": "en-US,en;q=0.9", "en": "en-US,en;q=0.9"}
    if not isinstance(locale, str) or not locale.strip() or "\r" in locale or "\n" in locale:
        raise ValueError("invalid locale")
    return known.get(locale.lower(), locale)

def make_headers(spec: BrowserSpec, *, locale: str = "global", navigation: bool = True) -> dict[str, str]:
    if not isinstance(navigation, bool):
        raise TypeError("navigation must be bool")
    headers = {"User-Agent": spec.ua,
               "Accept": ("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,"
                          "image/webp,*/*;q=0.8" if spec.engine == "blink" else
                          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
               "Accept-Language": _language(locale),
               "Accept-Encoding": "gzip, deflate, br"}
    if spec.engine == "blink":
        brand = "Microsoft Edge" if spec.browser == "edge" else "Google Chrome"
        major = spec.version.split(".")[0]
        platform = {"windows": "Windows", "macos": "macOS", "linux": "Linux", "android": "Android"}[spec.platform]
        headers.update({"Sec-CH-UA": f'"Chromium";v="{major}", "{brand}";v="{major}", "Not A(Brand";v="99"',
                        "Sec-CH-UA-Mobile": "?1" if spec.mobile else "?0",
                        "Sec-CH-UA-Platform": f'"{platform}"'})
    # High entropy Client Hints are not sent by default; require server opt-in.
    if navigation:
        headers.update({"Sec-Fetch-Dest": "document", "Sec-Fetch-Mode": "navigate",
                        "Sec-Fetch-Site": "none", "Sec-Fetch-User": "?1",
                        "Upgrade-Insecure-Requests": "1"})
    return headers

class UserAgent:
    def __init__(self, *, seed: int | None = None, locale: str = "global", catalog_path: str | None = None):
        self._rng = random.Random(seed)
        self.locale = locale
        _language(locale)
        if catalog_path is None:
            self._specs = SPECS
        else:
            from .catalog import load_verified_catalog
            self._specs = load_verified_catalog(catalog_path)

    def profile(self, *, browser: str | None = None, platform: str | None = None,
                device: str | None = None, navigation: bool = True) -> UAProfile:
        choices = [s for s in self._specs if (browser is None or s.browser == browser.lower())
                   and (platform is None or s.platform == platform.lower())
                   and (device is None or s.device == device.lower())]
        if not choices:
            raise ValueError("no catalog profile matches requested filters")
        spec = self._rng.choice(choices)
        return UAProfile(spec, make_headers(spec, locale=self.locale, navigation=navigation))

    @property
    def random(self) -> str:
        return self.profile().user_agent

    @property
    def chrome(self) -> str:
        return self.profile(browser="chrome").user_agent

    @property
    def firefox(self) -> str:
        return self.profile(browser="firefox").user_agent

    @property
    def safari(self) -> str:
        return self.profile(browser="safari").user_agent

    @property
    def edge(self) -> str:
        return self.profile(browser="edge").user_agent

def validate(profile: UAProfile, *, headers: Mapping[str, str] | None = None,
             screen: tuple[int, int] | None = None,
             runtime: Mapping[str, str] | None = None) -> ValidationReport:
    s = profile.spec
    h = {k.lower(): v for k, v in (headers if headers is not None else profile.headers).items()}
    issues: list[ValidationIssue] = []
    def add(code: str, msg: str, severity: str = "error") -> None:
        issues.append(ValidationIssue(code, msg, severity))
    if h.get("user-agent") != s.ua:
        add("ua_mismatch", "User-Agent differs from selected profile")
    ch = h.get("sec-ch-ua")
    mobile = h.get("sec-ch-ua-mobile")
    platform = h.get("sec-ch-ua-platform")
    if s.engine == "blink":
        if ch is None or mobile is None or platform is None:
            add("missing_client_hints", "Expected low-entropy Chromium Client Hints")
        if ch is not None and (f'v="{s.version.split(".")[0]}"' not in ch or
                               ("Microsoft Edge" if s.browser == "edge" else "Google Chrome") not in ch):
            add("brand_version_mismatch", "Client Hint browser brand/version differs")
        if mobile is not None and mobile != ("?1" if s.mobile else "?0"):
            add("mobile_mismatch", "Sec-CH-UA-Mobile disagrees with profile")
        expected_platform = {"windows": "Windows", "macos": "macOS", "linux": "Linux", "android": "Android"}[s.platform]
        if platform is not None and platform.strip('"') != expected_platform:
            add("platform_mismatch", "Sec-CH-UA-Platform disagrees with profile")
    elif any(x in h for x in ("sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform")):
        add("unexpected_client_hints", "Chromium Client Hints on non-Chromium profile")
    if "\r" in h.get("accept-language", "") or "\n" in h.get("accept-language", ""):
        add("invalid_language", "Header contains newline")
    if screen is not None:
        if len(screen) != 2 or any(type(x) is not int or x <= 0 for x in screen):
            add("invalid_screen", "Screen must be a pair of positive integers")
        elif screen != s.screen:
            add("screen_difference", "Screen differs from catalog sample (not proof of OS mismatch)", "warning")
    if runtime:
        if runtime.get("platform") and runtime["platform"].lower() != s.platform:
            add("runtime_platform_mismatch", "Runtime platform differs from profile")
        if runtime.get("browser") and runtime["browser"].lower() != s.browser:
            add("runtime_browser_mismatch", "Runtime browser differs from profile")
    return ValidationReport(issues)

__all__ = ["BrowserSpec", "UAProfile", "UserAgent", "ValidationIssue", "ValidationReport", "SPECS", "make_headers", "validate"]

# Read-only transport diagnostic helpers; QUIC's optional cryptography dependency
# is loaded only when extracting an Initial packet.
from .quic_analysis import calculate_quic_ja4, extract_quic_client_hello, derive_initial_keys
from .dtls_analysis import calculate_dtls_ja4, extract_dtls_client_hello
from .udp_capture import analyze_udp_datagrams, capture_udp_hellos
__all__ += ["calculate_quic_ja4", "extract_quic_client_hello", "derive_initial_keys",
            "calculate_dtls_ja4", "extract_dtls_client_hello",
            "analyze_udp_datagrams", "capture_udp_hellos"]

from .encrypted_capture import analyze_encrypted_capture, check_tshark, EncryptedCaptureReport
from .capture_selftest import capture_capabilities, verify_loopback_capture
__all__ += ["analyze_encrypted_capture", "check_tshark", "EncryptedCaptureReport",
            "capture_capabilities", "verify_loopback_capture"]
