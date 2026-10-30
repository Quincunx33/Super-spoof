"""Bounded TLS-over-TCP capture for interfaces you administer.

Optional scapy and packet capture privileges. IP fragmentation is not
reassembled here; PCAPs can be handled separately with dedicated tools.
"""
from __future__ import annotations
from .tls_analysis import parse_client_hello
from .ja4_analysis import calculate_ja4
from .tcp_reassembly import TCPStream, extract_client_hello


def capture_client_hellos(interface: str, *, count: int = 1, timeout: int = 15,
                          bpf_filter: str = 'tcp port 443', max_flows: int = 256,
                          max_stream_bytes: int = 262144) -> list[dict]:
    """Capture TLS ClientHellos on an authorized local interface.

    Collects out-of-order/retransmitted TCP payloads (bounded per-flow).
    If capture began after the ClientHello start, a complete hello is not
    guaranteed. `count` is a target; timeout may return fewer observations.
    """
    if not interface or not 1 <= count <= 100 or not 1 <= timeout <= 300:
        raise ValueError('interface, count (1..100), timeout (1..300) required')
    if not 1 <= max_flows <= 2048 or not 1024 <= max_stream_bytes <= 8_388_608:
        raise ValueError('capture memory limits invalid')
    try:
        from scapy.all import sniff, TCP, IP, IPv6, Raw
    except ImportError as exc:
        raise RuntimeError('Install optional dependency: pip install scapy') from exc
    flows: dict[tuple, TCPStream] = {}
    done: set[tuple] = set()
    observations = []

    def handle(pkt):
        if not pkt.haslayer(TCP): return
        ip = pkt.getlayer(IP) or pkt.getlayer(IPv6)
        if ip is None: return
        tcp = pkt[TCP]
        key = (str(ip.src), int(tcp.sport), str(ip.dst), int(tcp.dport))
        if key in done: return
        payload = bytes(pkt[Raw].load) if pkt.haslayer(Raw) else b''
        if not payload and not (int(tcp.flags) & 0x02): return
        if key not in flows:
            if len(flows) >= max_flows: return
            flows[key] = TCPStream(max_bytes=max_stream_bytes)
        try:
            data = flows[key].feed(int(tcp.seq), payload, syn=bool(int(tcp.flags) & 0x02))
            if len(data) < 5 or data[0] != 22: return
            hello = extract_client_hello(data)
            if hello is None: return
            ja3 = parse_client_hello(hello)
            ja4 = calculate_ja4(hello)
        except ValueError:
            # Invalid/corrupt/reused flow or TCP overlap is not a fingerprint.
            return
        observations.append({'source': key[0], 'source_port': key[1],
                             'destination': key[2], 'destination_port': key[3],
                             **ja3.as_dict(), 'ja4': ja4.ja4,
                             'ja4_r': ja4.ja4_r})
        done.add(key)
        del flows[key]

    sniff(iface=interface, filter=bpf_filter, timeout=timeout,
          stop_filter=lambda _: len(observations) >= count, prn=handle, store=False)
    return observations
