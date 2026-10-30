"""ua_forge.py — create a browser-like User-Agent/header bundle.

Screen dimensions cannot reliably identify an operating system. Pass an
explicit ``device_class`` when known. The built-in Chrome catalog is a set of
pinned examples; for newer versions, pass both a ChromeVersion and a matching
curl_cffi impersonation ID after checking that your installed curl_cffi
supports it.

Install: pip install curl_cffi
"""
from __future__ import annotations

import random
import re
from dataclasses import dataclass
from typing import Any, Optional

try:
    from curl_cffi.requests import AsyncSession as CurlAsyncSession
    from curl_cffi.requests import Session as CurlSession
except ImportError:
    CurlSession = None  # type: ignore[assignment,misc]
    CurlAsyncSession = None  # type: ignore[assignment,misc]


@dataclass(frozen=True)
class ChromeVersion:
    """Chrome UA/client-hint version data; use a matching TLS impersonation too."""
    major: str
    full: str
    not_brand_ver: str
    has_zstd: bool


# Pinned example versions. Keep synchronized with curl_cffi fingerprint support.
_CHROME_VERSIONS: dict[str, ChromeVersion] = {
    "122": ChromeVersion("122", "122.0.6261.128", "8", False),
    "123": ChromeVersion("123", "123.0.6312.122", "8", True),
    "124": ChromeVersion("124", "124.0.6367.82", "8", True),
}


@dataclass(frozen=True)
class DeviceProfile:
    name: str
    platform: str
    mobile: bool
    arch: str
    bitness: str
    impersonate_by_major: dict[str, str]
    ua_templates: tuple[str, ...]
    platform_version: str


_PROFILES: dict[str, DeviceProfile] = {
    "windows_desktop": DeviceProfile(
        "Windows Desktop", "Windows", False, "x86", "64",
        {"122": "chrome122", "123": "chrome123", "124": "chrome124"},
        ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
         "(KHTML, like Gecko) Chrome/{major}.0.0.0 Safari/537.36",),
        "10.0.0",
    ),
    "macos_desktop": DeviceProfile(
        "macOS Desktop", "macOS", False, "arm", "64",
        {"122": "chrome122", "123": "chrome123", "124": "chrome124"},
        ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
         "(KHTML, like Gecko) Chrome/{major}.0.0.0 Safari/537.36",),
        "14.4.0",
    ),
    "linux_desktop": DeviceProfile(
        "Linux Desktop", "Linux", False, "x86", "64",
        {"122": "chrome122", "123": "chrome123", "124": "chrome124"},
        ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
         "(KHTML, like Gecko) Chrome/{major}.0.0.0 Safari/537.36",),
        "6.5.0",
    ),
    "android_mobile": DeviceProfile(
        "Android Mobile", "Android", True, "arm", "64",
        {"123": "chrome123_android", "124": "chrome124_android"},
        ("Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 "
         "(KHTML, like Gecko) Chrome/{major}.0.0.0 Mobile Safari/537.36",),
        "14.0.0",
    ),
    "android_tablet": DeviceProfile(
        "Android Tablet", "Android", False, "arm", "64",
        {"123": "chrome123_android", "124": "chrome124_android"},
        ("Mozilla/5.0 (Linux; Android 13; SM-X700) AppleWebKit/537.36 "
         "(KHTML, like Gecko) Chrome/{major}.0.0.0 Safari/537.36",),
        "13.0.0",
    ),
}


@dataclass(frozen=True)
class SafariChoice:
    ios_ua_version: str
    ios_platform_version: str
    impersonate: str


_SAFARI_CHOICES = (
    SafariChoice("17_0", "17.0.0", "safari17_0"),
    SafariChoice("15_5", "15.5.0", "safari15_5"),
    SafariChoice("15_3", "15.3.0", "safari15_3"),
)

_IPHONE_WIDTHS = {320, 360, 375, 390, 393, 402, 414, 428, 430}
_IPAD_SIZES = {
    (768, 1024), (810, 1080), (820, 1180), (834, 1112), (834, 1194),
    (1024, 1366), (1032, 1376),
}
_MAC_SIZES = {
    (900, 1440), (982, 1512), (1117, 1728), (1329, 2056),
    (1600, 2560), (1664, 2560), (1280, 2048),
}
_VALID_DEVICE_CLASSES = frozenset(_PROFILES) | {"iphone", "ipad"}


def _validate_dimensions(width: int, height: int) -> None:
    if isinstance(width, bool) or isinstance(height, bool):
        raise TypeError("width and height must be positive integers")
    if not isinstance(width, int) or not isinstance(height, int):
        raise TypeError("width and height must be positive integers")
    if width <= 0 or height <= 0:
        raise ValueError("width and height must be greater than zero")


def _classify(width: int, height: int) -> str:
    """Heuristic only: screen dimensions cannot identify OS with certainty."""
    _validate_dimensions(width, height)
    long_side, short_side = max(width, height), min(width, height)
    normalized = (short_side, long_side)
    if normalized in _IPAD_SIZES:
        return "ipad"
    if short_side <= 480:
        return "iphone" if short_side in _IPHONE_WIDTHS else "android_mobile"
    if long_side >= 1280:
        return "macos_desktop" if normalized in _MAC_SIZES else "windows_desktop"
    if short_side <= 1100:
        return "ipad" if short_side in {768, 810, 820, 834, 1024} else "android_tablet"
    return "windows_desktop"


def _accept_lang(locale: str, rng: Any) -> str:
    if locale == "bd":
        return rng.choice((
            "bn-BD,bn;q=0.9,en;q=0.8",
            "en-US,en;q=0.9,bn;q=0.8",
            "bn-BD,bn;q=0.9,en-US;q=0.8,en;q=0.7",
        ))
    if locale == "global":
        return rng.choice((
            "en-US,en;q=0.9", "en-GB,en;q=0.9",
            "en-US,en;q=0.9,fr;q=0.8", "en-US,en;q=0.9,de;q=0.8",
        ))
    if not isinstance(locale, str) or not locale.strip():
        raise ValueError("locale must be 'bd', 'global', or an Accept-Language value")
    if "\r" in locale or "\n" in locale:
        raise ValueError("locale cannot contain newline characters")
    return locale


def _validate_chrome_version(version: ChromeVersion) -> None:
    if not isinstance(version, ChromeVersion):
        raise TypeError("chrome_version must be a ChromeVersion instance")
    if not re.fullmatch(r"\d+", version.major):
        raise ValueError("Chrome major version must contain digits only")
    if not re.fullmatch(r"\d+(?:\.\d+){3}", version.full):
        raise ValueError("Chrome full version must have four numeric components")
    if not version.full.startswith(version.major + "."):
        raise ValueError("Chrome full version must begin with the specified major version")
    if not re.fullmatch(r"\d+", version.not_brand_ver):
        raise ValueError("Not=A?Brand version must contain digits only")
    if not isinstance(version.has_zstd, bool):
        raise TypeError("has_zstd must be a bool")


def _validate_impersonation(major: str, value: str, mobile: bool) -> None:
    suffix = "_android" if mobile else ""
    allowed = {f"chrome{major}{suffix}"}
    if value not in allowed:
        raise ValueError(
            f"Chrome {major} impersonation for this device must be one of {sorted(allowed)}"
        )


def _sec_ch_ua(version: ChromeVersion) -> str:
    return (
        f'"Chromium";v="{version.major}", '
        f'"Google Chrome";v="{version.major}", '
        f'"Not=A?Brand";v="{version.not_brand_ver}"'
    )


def _sec_ch_ua_full(version: ChromeVersion) -> str:
    return (
        f'"Chromium";v="{version.full}", '
        f'"Google Chrome";v="{version.full}", '
        f'"Not=A?Brand";v="{version.not_brand_ver}.0.0.0"'
    )


@dataclass
class ForgeBundle:
    device_class: str
    device_name: str
    platform: str
    mobile: bool
    engine: str
    impersonate: str
    headers: dict[str, str]
    browser_version: str

    def __repr__(self) -> str:
        ua = self.headers.get("User-Agent", "")[:72]
        return (f"<ForgeBundle device={self.device_class!r} "
                f"engine={self.engine!r} version={self.browser_version!r} "
                f"impersonate={self.impersonate!r}\n  ua={ua!r}>")


def forge(
    width: int,
    height: int,
    *,
    device_class: Optional[str] = None,
    chrome_version: Optional[ChromeVersion] = None,
    chrome_impersonate: Optional[str] = None,
    locale: str = "global",
    navigation: bool = True,
    rng: Optional[random.Random] = None,
) -> ForgeBundle:
    """Build a coherent browser-like bundle.

    ``rng=random.Random(seed)`` makes output reproducible. For an unlisted
    Chrome version, provide both ``chrome_version`` and the exact matching
    ``chrome_impersonate`` (for example ``chrome130``), after verifying support
    in your installed curl_cffi. ``navigation=False`` omits navigation-only
    Fetch Metadata and Upgrade-Insecure-Requests headers.
    """
    _validate_dimensions(width, height)
    if not isinstance(navigation, bool):
        raise TypeError("navigation must be a bool")
    chooser = rng if rng is not None else random
    klass = device_class or _classify(width, height)
    if klass not in _VALID_DEVICE_CLASSES:
        raise ValueError(f"unknown device_class {klass!r}; choose from {sorted(_VALID_DEVICE_CLASSES)}")
    accept_lang = _accept_lang(locale, chooser)

    if klass in {"iphone", "ipad"}:
        if chrome_version is not None or chrome_impersonate is not None:
            raise ValueError("Chrome version/fingerprint options cannot be used with iOS Safari")
        safari = chooser.choice(_SAFARI_CHOICES)
        device = "iPhone" if klass == "iphone" else "iPad"
        cpu = "CPU iPhone OS" if klass == "iphone" else "CPU OS"
        ua = (
            f"Mozilla/5.0 ({device}; {cpu} {safari.ios_ua_version} like Mac OS X) "
            "AppleWebKit/605.1.15 (KHTML, like Gecko) "
            f"Version/{safari.ios_ua_version.replace('_', '.')}"
            " Mobile/15E148 Safari/604.1"
        )
        headers = {
            "User-Agent": ua,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": accept_lang,
            "Accept-Encoding": "gzip, deflate, br",
        }
        if navigation:
            headers.update({
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "none",
                "Sec-Fetch-User": "?1",
                "Upgrade-Insecure-Requests": "1",
            })
        return ForgeBundle(
            klass, "iPhone (Safari)" if klass == "iphone" else "iPad (Safari)",
            "iOS", klass == "iphone", "webkit", safari.impersonate, headers,
            safari.ios_ua_version.replace("_", "."),
        )

    profile = _PROFILES[klass]
    if chrome_version is None:
        if chrome_impersonate is not None:
            raise ValueError("chrome_impersonate requires an explicit chrome_version")
        candidates = [
            _CHROME_VERSIONS[major]
            for major in profile.impersonate_by_major
            if major in _CHROME_VERSIONS
        ]
        if not candidates:
            raise RuntimeError(f"no pinned Chrome versions configured for {klass}")
        version = chooser.choice(candidates)
        impersonate = profile.impersonate_by_major[version.major]
    else:
        _validate_chrome_version(chrome_version)
        version = chrome_version
        major = version.major
        pinned = _CHROME_VERSIONS.get(major)
        configured_impersonation = profile.impersonate_by_major.get(major)
        if chrome_impersonate is None:
            if pinned != version or configured_impersonation is None:
                raise ValueError(
                    "For a custom/unlisted Chrome version, pass chrome_impersonate too; "
                    "verify the fingerprint exists in your curl_cffi version."
                )
            impersonate = configured_impersonation
        else:
            _validate_impersonation(major, chrome_impersonate, profile.mobile)
            if configured_impersonation and chrome_impersonate != configured_impersonation:
                raise ValueError("chrome_impersonate conflicts with this profile's configured fingerprint")
            impersonate = chrome_impersonate

    ua = chooser.choice(profile.ua_templates).replace("{major}", version.major)
    platform_version = profile.platform_version
    if klass == "windows_desktop":
        platform_version = chooser.choice(("10.0.0", "15.0.0"))

    headers = {
        "User-Agent": ua,
        "Accept": (
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,"
            "image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
        ),
        "Accept-Language": accept_lang,
        "Accept-Encoding": "gzip, deflate, br, zstd" if version.has_zstd else "gzip, deflate, br",
        "Sec-CH-UA": _sec_ch_ua(version),
        "Sec-CH-UA-Mobile": "?1" if profile.mobile else "?0",
        "Sec-CH-UA-Platform": f'"{profile.platform}"',
        "Sec-CH-UA-Platform-Version": f'"{platform_version}"',
        "Sec-CH-UA-Arch": f'"{profile.arch}"',
        "Sec-CH-UA-Bitness": f'"{profile.bitness}"',
        "Sec-CH-UA-Full-Version-List": _sec_ch_ua_full(version),
    }
    if navigation:
        headers.update({
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Upgrade-Insecure-Requests": "1",
        })
    return ForgeBundle(klass, profile.name, profile.platform, profile.mobile,
                       "chromium", impersonate, headers, version.full)


def _merge_headers(defaults: dict[str, str], overrides: Optional[dict[str, str]]) -> dict[str, str]:
    """Merge HTTP headers case-insensitively; caller values replace defaults."""
    merged = dict(defaults)
    if overrides is None:
        return merged
    if not isinstance(overrides, dict):
        raise TypeError("headers must be a dict[str, str]")
    for key, value in overrides.items():
        if not isinstance(key, str) or not key or any(c in key for c in "\r\n:"):
            raise ValueError(f"invalid HTTP header name: {key!r}")
        if not isinstance(value, str) or "\r" in value or "\n" in value:
            raise ValueError(f"invalid HTTP header value for {key!r}")
        existing = next((k for k in merged if k.lower() == key.lower()), None)
        merged[existing if existing is not None else key] = value
    return merged


def request(
    url: str,
    *,
    width: int = 1920,
    height: int = 1080,
    method: str = "GET",
    locale: str = "global",
    device_class: Optional[str] = None,
    chrome_version: Optional[ChromeVersion] = None,
    chrome_impersonate: Optional[str] = None,
    navigation: Optional[bool] = None,
    rng: Optional[random.Random] = None,
    headers: Optional[dict[str, str]] = None,
    timeout: float = 30,
    **kwargs: Any,
):
    """Synchronous curl_cffi request; custom headers replace defaults by name."""
    if CurlSession is None:
        raise ImportError("curl_cffi required: pip install curl_cffi")
    bundle = forge(
        width, height, device_class=device_class, chrome_version=chrome_version,
        chrome_impersonate=chrome_impersonate, locale=locale,
        navigation=(method.upper() in {"GET", "HEAD"}) if navigation is None else navigation,
        rng=rng,
    )
    merged_headers = _merge_headers(bundle.headers, headers)
    with CurlSession(impersonate=bundle.impersonate) as session:
        return session.request(method, url, headers=merged_headers, timeout=timeout, **kwargs)


async def async_request(
    url: str,
    *,
    width: int = 1920,
    height: int = 1080,
    method: str = "GET",
    locale: str = "global",
    device_class: Optional[str] = None,
    chrome_version: Optional[ChromeVersion] = None,
    chrome_impersonate: Optional[str] = None,
    navigation: Optional[bool] = None,
    rng: Optional[random.Random] = None,
    headers: Optional[dict[str, str]] = None,
    timeout: float = 30,
    **kwargs: Any,
):
    """Asynchronous curl_cffi request; custom headers replace defaults by name."""
    if CurlAsyncSession is None:
        raise ImportError("curl_cffi required: pip install curl_cffi")
    bundle = forge(
        width, height, device_class=device_class, chrome_version=chrome_version,
        chrome_impersonate=chrome_impersonate, locale=locale,
        navigation=(method.upper() in {"GET", "HEAD"}) if navigation is None else navigation,
        rng=rng,
    )
    merged_headers = _merge_headers(bundle.headers, headers)
    async with CurlAsyncSession(impersonate=bundle.impersonate) as session:
        return await session.request(method, url, headers=merged_headers, timeout=timeout, **kwargs)


if __name__ == "__main__":
    examples = [
        (390, 844, "iPhone", "bd", None),
        (768, 1024, "iPad", "bd", None),
        (412, 915, "Android phone", "bd", None),
        (1920, 1080, "Windows desktop", "global", None),
        (2560, 1600, "Mac-like display", "global", None),
        (1280, 800, "Linux (explicit class)", "global", "linux_desktop"),
        (1024, 1366, "iPad Pro", "global", None),
    ]
    for width, height, label, locale, klass in examples:
        bundle = forge(width, height, locale=locale, device_class=klass, rng=random.Random(7))
        print(f"\n{label} {width}x{height}: {bundle}")
        for name, value in bundle.headers.items():
            print(f"{name}: {value}")
