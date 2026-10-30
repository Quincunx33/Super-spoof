"""Optional passive QUIC / DTLS ClientHello capture on authorized interfaces.

Analyzes UDP payloads only; no active scanning, probing or modification.
Requires Scapy, elevated interface capture permissions and an authorized
network interface. Supports cleartext DTLS ClientHello and QUIC v1/v2 Initial.
"""
from __future__ import annotations
from .quic_analysis import calculate_quic_ja4
from .dtls_analysis import calculate_dtls_ja4


def analyze_udp_datagrams(datagrams: list[bytes], *, protocol: str = 'auto') -> dict:
    """Fingerprint a single directed UDP flow from captured payloads.

    Raises ValueError if no complete ClientHello, unsupported framing, or
    invalid AEAD authentication. `protocol` must be 'auto', 'quic', or 'dtls'.
    """
    if protocol not in ('auto','quic','dtls'): raise ValueError('invalid protocol')
    if not datagrams: raise ValueError('no UDP datagrams provided')
    if protocol == 'auto':
        first = datagrams[0]
        if len(first) >= 5 and first[0] & 0x80 and int.from_bytes(first[1:5],'big') in (1,0x6b3343cf):
            protocol = 'quic'
        elif len(first) >= 3 and first[0] == 22 and first[1] == 0xfe:
            protocol = 'dtls'
        else: raise ValueError('unrecognized UDP handshake protocol')
    obj = calculate_quic_ja4(datagrams) if protocol == 'quic' else calculate_dtls_ja4(datagrams)
    return {'protocol': protocol, **obj.as_dict()}


def capture_udp_hellos(interface: str, *, count: int = 1, timeout: int = 15,
                       bpf_filter: str = 'udp', max_flows: int = 128,
                       max_packets_per_flow: int = 64) -> list[dict]:
    """Passively capture and fingerprint ClientHellos on a permitted interface.

    Returns only completed fingerprints; does not save payloads. Capture may
    miss packets and does not reassemble IP fragments or QUIC Retry flows.
    """
    if not interface or not 1 <= count <= 100 or not 1 <= timeout <= 300:
        raise ValueError('invalid interface, count or timeout')
    if not 1 <= max_flows <= 2048 or not 1 <= max_packets_per_flow <= 1024:
        raise ValueError('invalid capture resource limits')
    try:
        from scapy.all import sniff, UDP, IP, IPv6, Raw
    except ImportError as exc:
        raise RuntimeError('Install optional dependency: pip install "advanced-ua-forge[capture,quic]"') from exc
    flows: dict[tuple,list[bytes]] = {}
    observations: list[dict] = []
    completed: set[tuple] = set()
    def handle(pkt):
        if not pkt.haslayer(UDP): return
        ip = pkt.getlayer(IP) or pkt.getlayer(IPv6)
        if ip is None: return
        udp = pkt[UDP]
        key = (str(ip.src),int(udp.sport),str(ip.dst),int(udp.dport))
        if key in completed: return
        payload = bytes(pkt[Raw].load) if pkt.haslayer(Raw) else b''
        if not payload: return
        if key not in flows:
            if len(flows) >= max_flows: return
            flows[key] = []
        if len(flows[key]) >= max_packets_per_flow: return
        flows[key].append(payload)
        try:
            result = analyze_udp_datagrams(flows[key])
        except ValueError:
            return  # waiting for fragments or unsupported datagram
        except ImportError as exc:
            raise RuntimeError('QUIC capture requires pip install "advanced-ua-forge[quic]"') from exc
        observations.append({'source':key[0], 'source_port':key[1],
                             'destination':key[2], 'destination_port':key[3], **result})
        completed.add(key)
        del flows[key]
    sniff(iface=interface,filter=bpf_filter,timeout=timeout,
          stop_filter=lambda _: len(observations)>=count,prn=handle,store=False)
    return observations
