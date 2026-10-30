# Advanced UA Forge v4.5

**Install after PyPI publication:** `python -m pip install advanced-ua-forge`

**Import:** `from ua_forge import UserAgent` · **CLI:** `ua-forge --browser chrome --platform windows`

```python
from ua_forge import UserAgent
ua = UserAgent(locale="bd")
print(ua.random)
profile = ua.profile(browser="chrome", platform="windows")
print(profile.user_agent)
print(profile.headers)
print(profile.validate().as_dict())
```

Publishing instructions: [PUBLISHING.md](PUBLISHING.md). Optional native/networking dependencies are **not installed** with the base package. UA strings are samples, not guaranteed to mirror any particular real browser or bypass access controls.

---


Python 3.10+ library for realistic **sample** UA/header/device metadata, browser diagnostics, TLS ClientHello/JA3/JA4 analysis (TCP / QUIC Initial / DTLS), HTTP/2 diagnostics, authorized TCP/UDP packet capture and **read-only** Cloudflare zone Security Events analytics. The baseline UA catalog is historical; use explicit vendor refresh for supported, verified new releases.

**Not** a Cloudflare bypass, WAF evasion library, full browser emulator, or a promise of indistinguishable fingerprints. Only capture traffic you control or have explicit permission to inspect. JA4 TLS is based on [FoxIO's public JA4 spec](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md); JA4+ is not implemented.

## Installation

```bash
unzip advanced_ua_forge_v45.zip
cd advanced_ua_forge_v45
python -m pip install .
# For network capture, optional Scapy dependency and privileged interface access:
python -m pip install '.[capture,quic]' # optional: capture and QUIC Initial inspection
# For real-browser observation:
python -m pip install '.[browser]'
python -m playwright install chromium
python -m pip install pytest
python -m pytest -q
```

## UA profiles

```python
from ua_forge import UserAgent
ua = UserAgent(seed=42, locale='bd')
print(ua.chrome)
profile = ua.profile(browser='chrome', platform='windows')
print(profile.user_agent)
print(profile.headers)
print(profile.validate().as_dict())
```

## JA4 TLS-over-TCP (v4.3)

Calculate JA4 from a **complete** TLS ClientHello handshake (raw handshake or single TLS record). For TCP, extract ClientHello from TLS records/streams separately. QUIC Initial and DTLS are now supported through **separate transport parsers** documented below.

```python
from ua_forge.ja4_analysis import calculate_ja4
# hello = bytes from a capture you are authorized to inspect
result = calculate_ja4(hello)
print(result.ja4)
print(result.ja4_r)
```

JA4 uses highest valid `supported_versions`, GREASE removal, an SNI indicator, ALPN and sorted cipher/extension hashes, while keeping signature-algorithm ordering. An official published JA4 test vector is included in automated tests. **This is not JA4S/JA4H/JA4+**. Compatible fingerprint output does not imply compatibility with any anti-bot solution.

## QUIC v1/v2 ClientHello + JA4-Q (v4.4)

Install the optional C-backed cryptography primitives:

```bash
python -m pip install '.[quic]'
```

```python
from ua_forge import extract_quic_client_hello, calculate_quic_ja4

# Raw UDP payloads captured from an authorized client's QUIC Initial packets.
datagrams = [initial_udp_payload_1, initial_udp_payload_2]
hello = extract_quic_client_hello(datagrams)  # raw TLS handshake bytes or None
result = calculate_quic_ja4(datagrams)
print(result.ja4)     # starts with q
print(result.ja4_r)
```

Supports QUIC v1 (`0x00000001`, RFC 9001) and v2 (`0x6b3343cf`, RFC 9369) **client** Initial packets, public Initial key derivation, AES-ECB header unprotection, AES-128-GCM authentication/decryption, coalesced long-header packet processing, packet-number reconstruction, CRYPTO frame offset reassembly and overlap checks. These operations inspect *only the initial handshake*, whose packet protection keys are intentionally publicly derivable. **This does not decrypt subsequent QUIC 0-RTT, Handshake or 1-RTT application traffic.** No packets are transmitted.

Unsupported: QUIC Retry transitions/changed Initial DCIDs, connection migration, IP fragmentation, unknown QUIC versions, cross-connection mixing and full QUIC session tracking. Missing datagrams and a missing original Initial DCID can prevent extraction. Input is raw UDP payloads, not an Ethernet frame or whole PCAP file.

## DTLS ClientHello + JA4-D (v4.4)

```python
from ua_forge import extract_dtls_client_hello, calculate_dtls_ja4

datagrams = [udp_payload_1, udp_payload_2]  # one directed DTLS flow
hello = extract_dtls_client_hello(datagrams)  # None if incomplete
result = calculate_dtls_ja4(datagrams)
print(result.ja4)  # starts with d
```

Parses plaintext epoch-0 DTLS 1.0/1.2/1.3 handshake records, supports multiple handshake fragments per record, retransmissions, out-of-order records and cookie-bearing ClientHello layout. Implements DTLS supported_versions mapping including reverse DTLS wire version order. It does **not** decrypt encrypted records, reassemble IP fragments or implement general DTLS connection state.

## Authorized live UDP capture (v4.4)

```python
from ua_forge import capture_udp_hellos

# Network interface requires permissions; pass an explicit suitable BPF filter.
observations = capture_udp_hellos(
    interface='eth0', count=2, timeout=10,
    bpf_filter='udp port 443 or udp port 4433'
)
for result in observations:
    print(result['protocol'], result['ja4'])
```

Requires `pip install '.[capture,quic]'`, Scapy's native capture support and interface permissions. Captures passive UDP payloads **only** on an interface you administer or have permission to inspect. No UDP active probing. Capturing traffic that did not include the beginning of the ClientHello may produce no result. The method is bounded by flow, datagram and time limits; it is not a general-purpose QUIC/DTLS analyzer. If you already have UDP payload bytes, use `analyze_udp_datagrams([...])` without Scapy.

## Bounded out-of-order TCP payload reassembly (v4.3)

```python
from ua_forge.tcp_reassembly import TCPStream, extract_client_hello
stream = TCPStream(start_seq=1000)
stream.feed(1010, b'...next segment...')
stream.feed(1000, b'...first segment...')
hello = extract_client_hello(stream.data())  # bytes or None
```

Segments are buffered with size and segment limits. TCP retransmissions and overlapping bytes are checked, and conflicting payloads are rejected. This handles a ClientHello spanning multiple TLS records. **Does not** reassemble IP-fragmented datagrams, handle TCP sequence wraparound, reliably recover an initial segment missing from the capture, or decrypt TLS.

For local capture (requires `scapy` and OS permissions):

```python
from ua_forge.live_capture import capture_client_hellos
print(capture_client_hellos('eth0', count=2, timeout=10))
```

## Cloudflare read-only GraphQL event pagination (v4.3)

Uses Cloudflare's **documented GraphQL Analytics API** `firewallEventsAdaptive`, not an assumed `/security/events` REST endpoint. A Cloudflare API token scoped to the zone and appropriate analytics permission is required.

```python
import os
from ua_forge.cloudflare_api import fetch_security_events_paginated

result = fetch_security_events_paginated(
    os.environ['CF_ZONE_ID'], os.environ['CF_API_TOKEN'],
    start='2026-10-29T00:00:00Z', end='2026-10-30T00:00:00Z',
    page_size=100, max_pages=4,
)
print(result['summary'])
print(result['complete'], result['warnings'])
```

Cloudflare GraphQL does **not** offer page cursors. This collector moves the upper time boundary backward after each full page, and reports the chance that same-timestamp events were skipped. It deliberately does **not** claim completeness after any full page. Cloudflare may sample Security Events. Narrow time windows and data sources with event IDs are preferable for exact exports. The `fetch_security_events()` one-hour convenience wrapper remains.

## Verified browser catalog refresh (v4.3)

A separate **opt-in JSON snapshot** is written using stable Chrome Windows data from the official Google VersionHistory API and current Firefox release data from Mozilla. Chrome on Android/macOS/Linux, Edge, and Safari are not silently updated from mismatched release feeds. Original built-in profiles remain unchanged.

```python
from ua_forge.catalog import refresh_catalog_from_vendors
from ua_forge import UserAgent

print(refresh_catalog_from_vendors('verified_catalog.json'))
ua = UserAgent(catalog_path='verified_catalog.json')
print(ua.profile(browser='chrome', platform='windows').metadata)
```

Or via terminal:

```bash
python -m ua_forge --refresh-catalog verified_catalog.json
python -m ua_forge --catalog verified_catalog.json --browser chrome --platform windows
```

Refresh requires internet. The update validates vendor version formats, rejects empty/invalid results, skips failed sources, prevents major downgrades by default, and atomically replaces the JSON snapshot. It does **not** install/update any actual browser binaries. Safari/iOS release and OS-version compatibility still require curated updates.

## Tests and limits

```bash
python -m pip install pytest
python -m pytest -q
```

Unit tests include the published JA4 fingerprint vector, GREASE & cipher reordering stability, malformed ClientHellos, TCP out-of-order/retransmission handling and TLS-record splits, opt-in catalog atomic update, and mock GraphQL pagination/error cases.

Live privileged packet capture, Cloudflare API permissions/response schema, real vendor HTTP endpoints, and Playwright browser launches have **not** been end-to-end tested in this sandbox. This project does not modify TLS ClientHello or defeat access controls.

## External specifications

- JA4 algorithm: https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md
- Cloudflare Security Events GraphQL: https://developers.cloudflare.com/analytics/graphql-api/tutorials/querying-firewall-events/
- Cloudflare pagination limitations: https://developers.cloudflare.com/analytics/graphql-api/features/pagination/
- Chrome official VersionHistory: https://developer.chrome.com/docs/web-platform/versionhistory/reference
- Mozilla Product Details feed: https://wiki.mozilla.org/Release_Management/Product_details

## v4.4 validation and scope

Offline test suite: **39 passed** (includes all prior v4.3 tests). QUIC v1 and QUIC v2 Initial key derivation checked against RFC 9001 Appendix A.1 and RFC 9369 Appendix A.1; synthetic QUIC v1/v2 packets, tampered authenticated packets, out-of-order QUIC CRYPTO offsets and fragmented DTLS handshakes were tested. **No actual interface capture, live browser, or production Cloudflare endpoint was available for end-to-end validation.**

This is an analysis SDK. A JA4 match does not establish full browser identity or imply any bypass of Cloudflare/WAF filtering. No behavior simulation, browser fingerprint modification or challenge bypass code is included.

Key references: [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000), [RFC 9001](https://www.rfc-editor.org/rfc/rfc9001), [RFC 9369](https://www.rfc-editor.org/rfc/rfc9369), [RFC 6347](https://www.rfc-editor.org/rfc/rfc6347), [RFC 9147](https://www.rfc-editor.org/rfc/rfc9147), [FoxIO JA4 public spec](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md).


## v4.5: Keylog-assisted encrypted capture diagnostics (QUIC/DTLS/TLS)

For captures of **your own sessions only**, v4.5 adds a read-only TShark
integration. A genuine NSS-format TLS key log produced by the participating
client/server is needed to make protected traffic available to Wireshark's
protocol dissectors. Merely having the PCAP or the server's certificate is
not sufficient to decrypt modern sessions. QUIC 1-RTT and encrypted DTLS
are **not** decrypted by our pure-Python code: decryption is delegated to
an installed Wireshark/TShark build and depends on that build's support,
matching session secrets, complete capture data and enabled dissectors.

```bash
# Install the TShark package from your OS/Wireshark distribution separately.
python -m ua_forge --capture-capabilities

# Collect an authorized session with a keylog enabled in your own browser/client:
# Linux/macOS example: SSLKEYLOGFILE=$PWD/session.keys your-browser
# Keep session.keys private: chmod 600 session.keys
# capture.pcapng must come from the same session.
python -m ua_forge --inspect-pcap capture.pcapng --keylog session.keys
```

```python
from ua_forge import analyze_encrypted_capture, check_tshark
print(check_tshark())
report = analyze_encrypted_capture('capture.pcapng', 'session.keys',
                                   max_packets=3000, timeout=30)
print(report.as_dict())
```

This exposes only protocol names, packet counts, a bounded frame summary and
**whether an application dissector was visible**, not raw decrypted payloads,
HTTP headers, cookies or secret material. Application-layer visibility alone
**does not prove** decryption of all encrypted packets. For modern QUIC,
observing HTTP/3 on an encrypted capture alongside the matching key log is
consistent with successful decryption, but should be confirmed in Wireshark.
If no application dissector is seen, the result is `not_confirmed`, not a
false claim of decryption failure. Key log is never printed or copied.

### v4.5: loopback-only live capture self-test

```bash
python -m pip install '.[capture]'
python -m ua_forge --capture-capabilities
# Only runs on local loopback interfaces, requires capture privileges:
python -m ua_forge --selftest-loopback --loopback-interface lo
```

```python
from ua_forge import capture_capabilities, verify_loopback_capture
print(capture_capabilities())
print(verify_loopback_capture(interface='lo'))
```

The self-test emits a **single** random-marker UDP packet to `127.0.0.1`
and checks whether Scapy observes that packet on the named loopback device.
It does not make any external connection and does **not** establish a live
QUIC/DTLS decryption result. It requires permission to capture packets,
a working BPF/capture backend and a recognized local loopback interface.
If it reports `verified=False`, check the reason before investigating the
network. Other capture interfaces are intentionally rejected for self-test.

### v4.5 validation limitations

Unit tests cover the TShark adapter using a mocked executable, keylog/PCAP
input validation, error handling, capability reporting and loopback interface
restrictions, in addition to previous tests. TShark is not installed and the
runtime lacks raw-socket permission, so **there is no successful live packet
capture or end-to-end encrypted traffic decryption demonstrated here**.
A real end-to-end check requires your locally installed TShark and an
authorized capture with a matching key log. Do not upload or share your
session key logs; they can disclose traffic contents.

Wireshark references:
- https://wiki.wireshark.org/TLS
- https://www.wireshark.org/docs/man-pages/tshark
- https://github.com/quicwg/base-drafts/wiki/Tools
