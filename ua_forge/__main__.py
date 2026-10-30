"""CLI: python -m ua_forge --browser chrome --platform windows"""
import argparse
from . import UserAgent
from .report import local_report
from .diagnostics import export_json

def main():
    parser = argparse.ArgumentParser(description='UA Forge local consistency diagnostics')
    parser.add_argument('--browser', choices=['chrome','firefox','edge','safari'])
    parser.add_argument('--platform', choices=['windows','macos','linux','android','ios'])
    parser.add_argument('--device', choices=['desktop','mobile','tablet'])
    parser.add_argument('--locale', default='global')
    parser.add_argument('--catalog', help='Load an opt-in verified catalog JSON')
    parser.add_argument('--refresh-catalog', metavar='PATH', help='Fetch official vendor versions and write catalog')
    parser.add_argument('--capture-capabilities', action='store_true', help='Check local packet-capture prerequisites')
    parser.add_argument('--selftest-loopback', action='store_true', help='Actively test capture of one localhost UDP datagram')
    parser.add_argument('--loopback-interface', default='lo', help='Loopback device for own-packet self-test')
    parser.add_argument('--inspect-pcap', metavar='PATH', help='Read PCAP/PCAPNG with TShark')
    parser.add_argument('--keylog', metavar='PATH', help='Own-session TLS NSS keylog for PCAP analysis')
    args = parser.parse_args()
    if args.capture_capabilities:
        from .capture_selftest import capture_capabilities
        print(export_json(capture_capabilities()))
        return
    if args.selftest_loopback:
        from .capture_selftest import verify_loopback_capture
        print(export_json(verify_loopback_capture(interface=args.loopback_interface)))
        return
    if args.inspect_pcap:
        if not args.keylog:
            parser.error('--inspect-pcap requires --keylog from a session you own')
        from .encrypted_capture import analyze_encrypted_capture
        print(export_json(analyze_encrypted_capture(args.inspect_pcap, args.keylog).as_dict()))
        return
    if args.keylog:
        parser.error('--keylog requires --inspect-pcap')
    if args.refresh_catalog:
        from .catalog import refresh_catalog_from_vendors
        print(export_json(refresh_catalog_from_vendors(args.refresh_catalog)))
        return
    profile = UserAgent(locale=args.locale, catalog_path=args.catalog).profile(browser=args.browser, platform=args.platform, device=args.device)
    print(export_json(local_report(profile)))
if __name__ == '__main__':
    main()
