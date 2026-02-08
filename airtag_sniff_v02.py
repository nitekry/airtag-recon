#!/usr/bin/env python3
"""
airtag_sniff.py (v0.3)

Updates vs v0.2:
- Detects Apple Find My / AirTag-like frames for BOTH:
    - apple_type == 0x12 (previous)
    - apple_type == 0x07 (confirmed sample: 1E FF 4C 00 07 19 ...)
- Keeps apple_len >= 0x19 (classic 0x19 or larger)
- Works with Bleak manufacturer_data where payload is bytes AFTER company_id (Apple payload begins at apple_type)

Still provides conservative chunking for 0x12 frames:
  hdr2 (2 bytes) + blk16 (16 bytes) + tail (remainder)
For 0x07 frames we don't assume the same structure; we print the full payload plus a generic split.
"""

import argparse
import asyncio
import binascii
import hashlib
import time
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

from bleak import BleakScanner

APPLE_COMPANY_ID = 0x004C
APPLE_TYPES = (0x12, 0x07)  # UPDATED: include 0x07


def hx(b: bytes) -> str:
    return binascii.hexlify(b).decode("ascii").upper()


def fp12(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()[:12] if b else ""


@dataclass
class AirtagMatch:
    address: str
    rssi: int
    apple_type: int
    apple_len: int
    mfg_payload: bytes
    ad_struct_len_byte: int
    ad_struct_hex: str
    timestamp: float


def parse_apple_mfg_for_findmy(payload: bytes) -> Optional[Tuple[int, int]]:
    """
    Heuristic detector:
      payload[0] in {0x12, 0x07}
      payload[1] >= 0x19
    """
    if not payload or len(payload) < 2:
        return None

    apple_type = payload[0]
    apple_len = payload[1]

    if apple_type not in APPLE_TYPES:
        return None
    if apple_len < 0x19:
        return None

    return apple_type, apple_len


def reconstruct_mfg_ad_structure(company_id: int, payload: bytes) -> bytes:
    """
    Construct a single AD structure:
      [len][type=0xFF][company_id LE 2 bytes][payload...]
    len = number of bytes after the len byte:
      1 (type) + 2 (company) + len(payload)
    """
    ad_type = 0xFF
    company_le = company_id.to_bytes(2, byteorder="little")
    length = 1 + 2 + len(payload)
    if length > 0xFF:
        raise ValueError("AD structure too large")
    return bytes([length, ad_type]) + company_le + payload


def decode_12_19(payload: bytes) -> Dict[str, bytes]:
    """
    For 0x12 0x19 frames: conservative chunking
      payload = [12][19][body...]
      body -> hdr2 (2 bytes) + blk16 (16 bytes) + tail (remainder)
    """
    body = payload[2:] if len(payload) >= 2 else b""
    hdr2 = body[:2] if len(body) >= 2 else body
    if len(body) >= 2 + 16:
        blk16 = body[2:18]
        tail = body[18:]
    else:
        blk16 = b""
        tail = body[2:] if len(body) > 2 else b""
    return {"hdr2": hdr2, "blk16": blk16, "tail": tail}


def decode_generic(payload: bytes) -> Dict[str, bytes]:
    """
    Generic chunking when we don't want to assume a specific structure.
    """
    body = payload[2:] if len(payload) >= 2 else b""
    head4 = body[:4] if len(body) >= 4 else body
    rest = body[4:] if len(body) > 4 else b""
    return {"head4": head4, "rest": rest}


def match_packet(
    address: str,
    rssi: int,
    manufacturer_data: Dict[int, bytes],
    require_1e_len: bool,
) -> Optional[AirtagMatch]:
    if APPLE_COMPANY_ID not in manufacturer_data:
        return None

    # Bleak manufacturer_data gives bytes after company_id; for Apple this is [apple_type][apple_len]...
    payload = manufacturer_data[APPLE_COMPANY_ID]
    parsed = parse_apple_mfg_for_findmy(payload)
    if not parsed:
        return None

    apple_type, apple_len = parsed

    ad_struct = reconstruct_mfg_ad_structure(APPLE_COMPANY_ID, payload)
    adlen = ad_struct[0]

    if require_1e_len and adlen != 0x1E:
        return None

    return AirtagMatch(
        address=address,
        rssi=rssi,
        apple_type=apple_type,
        apple_len=apple_len,
        mfg_payload=payload,
        ad_struct_len_byte=adlen,
        ad_struct_hex=hx(ad_struct),
        timestamp=time.time(),
    )


def diff_any(prev: Dict[str, bytes], cur: Dict[str, bytes], keys) -> str:
    if not prev:
        return "FIRST"
    for k in keys:
        if prev.get(k, b"") != cur.get(k, b""):
            return f"{k.upper()}:{hx(prev.get(k,b''))}->{hx(cur.get(k,b''))}"
    return ""


async def run(args):
    last_parts: Dict[str, Dict[str, bytes]] = {}
    last_print_time: Dict[str, float] = {}

    def should_print(addr: str) -> bool:
        if args.dedup <= 0:
            return True
        now = time.time()
        prev = last_print_time.get(addr, 0.0)
        if now - prev >= args.dedup:
            last_print_time[addr] = now
            return True
        return False

    def cb(device, adv):
        mfg = getattr(adv, "manufacturer_data", None) or {}
        rssi = getattr(device, "rssi", None)
        if rssi is None:
            rssi = getattr(adv, "rssi", -999)

        addr = getattr(device, "address", "UNKNOWN")

        if args.show_all_apple and APPLE_COMPANY_ID in mfg and should_print(addr):
            payload = mfg[APPLE_COMPANY_ID]
            ad_struct = reconstruct_mfg_ad_structure(APPLE_COMPANY_ID, payload)
            print(
                f"[APPLE]  {addr} RSSI:{int(rssi):4d} "
                f"adlen:0x{ad_struct[0]:02X} mfg_bytes:{len(payload):2d} "
                f"mfg:{hx(payload)}"
            )

        match = match_packet(addr, int(rssi), mfg, require_1e_len=args.require_1e)
        if not match:
            return

        # Decode based on apple_type
        if match.apple_type == 0x12:
            parts = decode_12_19(match.mfg_payload)
            change_keys = ("hdr2", "blk16", "tail")
        else:
            parts = decode_generic(match.mfg_payload)
            change_keys = ("head4", "rest")

        prev = last_parts.get(addr, {})
        changed_label = diff_any(prev, parts, change_keys)

        if args.print_on_change:
            if changed_label == "":
                return
        else:
            if not should_print(addr):
                return

        last_parts[addr] = parts

        base = (
            f"[AIRTAG?] CHANGED({changed_label}) {addr} RSSI:{match.rssi:4d} "
            f"type:0x{match.apple_type:02X} len:0x{match.apple_len:02X} "
            f"adlen:0x{match.ad_struct_len_byte:02X} "
            f"fp_full:{fp12(match.mfg_payload)} mfg:{hx(match.mfg_payload)}"
        )

        # Print type-specific fields
        if match.apple_type == 0x12:
            print(
                base
                + f" hdr2:{hx(parts['hdr2'])} blk16:{hx(parts['blk16'])} tail:{hx(parts['tail'])} "
                + f"fp_blk16:{fp12(parts['blk16'])} fp_tail:{fp12(parts['tail'])}"
            )
        else:
            print(
                base
                + f" head4:{hx(parts['head4'])} rest:{hx(parts['rest'])} "
                + f"fp_head4:{fp12(parts['head4'])} fp_rest:{fp12(parts['rest'])}"
            )

        if args.print_ad_struct:
            print(f"          ad_struct:{match.ad_struct_hex}")

    scanner = BleakScanner(detection_callback=cb)
    await scanner.start()
    try:
        await asyncio.sleep(args.duration)
    finally:
        await scanner.stop()


def main():
    ap = argparse.ArgumentParser(description="Detect Apple (0x004C) Find My / AirTag-like BLE manufacturer frames.")
    ap.add_argument("--duration", type=float, default=300, help="Scan duration in seconds (default: 300)")
    ap.add_argument("--require-1e", action="store_true", help="Require reconstructed mfg AD len byte == 0x1E")
    ap.add_argument("--show-all-apple", action="store_true", help="Print all Apple (0x004C) mfg frames (tuning)")
    ap.add_argument("--dedup", type=float, default=2.0, help="Time dedup per device seconds (0 disables)")
    ap.add_argument("--print-on-change", action="store_true", help="Only print when decoded fields change per device")
    ap.add_argument("--print-ad-struct", action="store_true", help="Also print reconstructed AD structure hex")
    args = ap.parse_args()

    asyncio.run(run(args))


if __name__ == "__main__":
    main()
