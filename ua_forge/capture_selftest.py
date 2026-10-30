"""Optional localhost-only live capture verification for owned network interfaces.

Requires Scapy, capture permission, and a known local loopback device.
No packets are sent to third-party hosts. The only active probe is a random
nonce in a single UDP datagram delivered to 127.0.0.1 locally.
"""
from __future__ import annotations
import os
import socket
import threading
import time
import uuid


def capture_capabilities() -> dict:
    """Report whether optional capture tools and OS raw-socket access exist."""
    try:
        import scapy.all  # noqa: F401
        scapy_ok = True
    except ImportError:
        scapy_ok = False
    from .encrypted_capture import check_tshark
    tshark = check_tshark()
    permission = False
    message = ''
    if hasattr(socket, 'AF_PACKET'):
        try:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
            s.close()
            permission = True
        except (PermissionError, OSError) as exc:
            message = f'raw packet capture unavailable: {type(exc).__name__}'
    else:
        message = 'raw packet capability cannot be determined on this operating system'
    return {'scapy_installed': scapy_ok, 'tshark_available': tshark['available'],
            'raw_packet_socket_available': permission,
            'raw_packet_socket_message': message}


def verify_loopback_capture(*, interface: str = 'lo', timeout: float = 4.0) -> dict:
    """Verify ability to sniff *our own* UDP packet on a loopback interface.

    Requires Scapy and elevated capture permissions. Does not test QUIC/DTLS
    decryption. Returns an explicit success/failure report, never silently
    claims verification from socket availability alone.
    """
    if interface not in ('lo', 'lo0', 'Loopback Pseudo-Interface 1'):
        raise ValueError('self-test only permits recognized loopback interfaces')
    if not 1 <= timeout <= 30:
        raise ValueError('timeout must be between 1 and 30 seconds')
    try:
        from scapy.all import AsyncSniffer, UDP, Raw
    except ImportError as exc:
        return {'verified': False, 'reason': 'scapy_not_installed', 'packet_seen': False}
    nonce = b'ua-forge-local-selftest-' + uuid.uuid4().hex.encode('ascii')
    receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sniffer = None
    seen = threading.Event()
    try:
        receiver.bind(('127.0.0.1', 0))
        port = receiver.getsockname()[1]
        receiver.settimeout(timeout)
        def observe(packet):
            if packet.haslayer(UDP) and packet.haslayer(Raw) and bytes(packet[Raw].load) == nonce:
                seen.set()
        try:
            sniffer = AsyncSniffer(iface=interface, filter=f'udp dst port {port}',
                                   prn=observe, store=False)
            sniffer.start()
            # AsyncSniffer may need a moment to attach the capture socket/filter.
            time.sleep(0.25)
            sender.sendto(nonce, ('127.0.0.1', port))
            receiver.recvfrom(256)
            verified = seen.wait(timeout)
            return {'verified': verified, 'reason': 'ok' if verified else 'packet_not_observed',
                    'packet_seen': verified, 'interface': interface}
        except (OSError, PermissionError, RuntimeError) as exc:
            return {'verified': False, 'reason': type(exc).__name__, 'packet_seen': False,
                    'interface': interface}
    finally:
        if sniffer is not None and getattr(sniffer, 'running', False):
            try:
                sniffer.stop()
            except Exception:
                pass
        receiver.close()
        sender.close()
