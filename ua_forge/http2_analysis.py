"""Offline HTTP/2 SETTINGS frame parser for provided frame bytes."""
from __future__ import annotations
SETTINGS = {1:"HEADER_TABLE_SIZE",2:"ENABLE_PUSH",3:"MAX_CONCURRENT_STREAMS",4:"INITIAL_WINDOW_SIZE",5:"MAX_FRAME_SIZE",6:"MAX_HEADER_LIST_SIZE"}

def parse_settings_frame(frame: bytes) -> dict:
    if len(frame) < 9: raise ValueError("truncated HTTP/2 frame")
    length = int.from_bytes(frame[:3], "big")
    if len(frame) != 9 + length: raise ValueError("frame length mismatch")
    if frame[3] != 4: raise ValueError("not a SETTINGS frame")
    if frame[5:9] != b"\x00" * 4: raise ValueError("SETTINGS stream ID must be zero")
    if frame[4] & 1:
        if length: raise ValueError("ACK SETTINGS must be empty")
        return {"ack": True, "settings": []}
    if length % 6: raise ValueError("invalid SETTINGS payload length")
    result=[]
    for i in range(9,len(frame),6):
        ident=int.from_bytes(frame[i:i+2],"big")
        value=int.from_bytes(frame[i+2:i+6],"big")
        result.append({"id":ident,"name":SETTINGS.get(ident,"UNKNOWN"),"value":value})
    return {"ack":False,"settings":result}
