"""Bounded TCP stream reassembly for authorized TLS inspection.

Reassembles TCP payload segments by sequence number (not IP fragmentation).
Rejects conflicting overlaps; does not decrypt TLS or follow long-lived sessions.
"""
from __future__ import annotations
from dataclasses import dataclass, field


def reassemble_segments(segments: list[tuple[int, bytes]], *, start_seq: int | None = None,
                        max_bytes: int = 262144) -> bytes:
    """Return contiguous payload from start_seq or minimum observed sequence.

    Handles out-of-order and duplicate segments. Stops at first missing byte.
    Sequence-wrap handling is outside this bounded capture-window API.
    """
    if not 1 <= max_bytes <= 8_388_608: raise ValueError('max_bytes out of range')
    if not segments: return b''
    start = min(seq for seq, _ in segments) if start_seq is None else start_seq
    if start < 0: raise ValueError('invalid starting sequence')
    blocks: dict[int,int] = {}
    for seq, data in segments:
        if seq < 0 or not isinstance(data, bytes): raise ValueError('segments must be (nonnegative seq, bytes)')
        for i, byte in enumerate(data):
            pos = seq+i-start
            if pos < 0: continue
            if pos >= max_bytes: raise ValueError('TCP stream exceeds configured limit')
            old = blocks.get(pos)
            if old is not None and old != byte: raise ValueError('conflicting retransmission/overlap')
            blocks[pos] = byte
    end = 0
    while end in blocks: end += 1
    return bytes(blocks[i] for i in range(end))


def extract_client_hello(stream: bytes, *, max_hello: int = 131072) -> bytes | None:
    """Extract raw TLS ClientHello handshake, even if split across TLS records.

    None indicates more bytes needed. Non-TLS/invalid frames raise ValueError.
    """
    if len(stream) < 5: return None
    offset = 0
    handshake = bytearray()
    while offset < len(stream):
        if len(stream)-offset < 5: return None
        if stream[offset] != 22: raise ValueError('expected TLS handshake record')
        length = int.from_bytes(stream[offset+3:offset+5], 'big')
        if not 1 <= length <= 18432: raise ValueError('invalid TLS record length')
        if len(stream) < offset+5+length: return None
        handshake.extend(stream[offset+5:offset+5+length])
        if len(handshake) > max_hello: raise ValueError('ClientHello too large')
        if len(handshake) >= 4:
            if handshake[0] != 1: raise ValueError('not a ClientHello')
            size = int.from_bytes(handshake[1:4], 'big')
            if size > max_hello: raise ValueError('ClientHello too large')
            if len(handshake) >= size+4: return bytes(handshake[:size+4])
        offset += 5+length
    return None


@dataclass
class TCPStream:
    """Per-direction bounded accumulator; preserve SYN sequence if available."""
    start_seq: int | None = None
    max_bytes: int = 262144
    max_segments: int = 512
    segments: list[tuple[int,bytes]] = field(default_factory=list)

    def feed(self, sequence: int, payload: bytes, *, syn: bool = False) -> bytes:
        if syn and self.start_seq is None: self.start_seq = sequence+1
        if not payload: return self.data()
        if len(self.segments) >= self.max_segments: raise ValueError('too many segments')
        if not isinstance(payload, bytes): raise TypeError('payload must be bytes')
        self.segments.append((sequence+(1 if syn else 0),payload))
        return self.data()

    def data(self) -> bytes:
        return reassemble_segments(self.segments, start_seq=self.start_seq, max_bytes=self.max_bytes)
