#!/usr/bin/env python3
"""
- AD type == 0xFF (manufacturer specific) -> exposed by Bleak as manufacturer_data
- Company == 0x004C (Apple)
- apple_type == 0x12
- apple_len  >= 0x19 (classic full frame 0x19 or larger)
- Optionally require reconstructed AD-structure length byte == 0x1E

Also includes a conservative decoder for 0x12 0x19 frames:
  payload = [12][19][body...]
  body -> hdr2 (2 bytes) + blk16 (16 bytes) + tail (remainder)

Change printing modes:
  --print-on-change with --change-field:
    blk16 : print when blk16 changes per device (Option 1)
    tail  : print when tail changes per device (Option 2)
    any   : print when hdr2 OR blk16 OR tail changes per device (Option 3)
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


def parse_apple_mfg_for_airtag(payload: bytes) -> Optional[Tuple[int, int]]:
    """
    heuristic:
      payload[0] == 0x12
      payload[1] >= 0x19
    """
    if not payload or len(payload) < 2:
        return None
    apple_type = payload[0]
    apple_len = payload[1]
    if apple_type != 0x12:
        return None
    if apple_len < 0x19:
        return None
    return apple_type, apple_len


def reconstruct_mfg_ad_structure(company_id: int, payload: bytes) -> bytes:
    """
    AD structure:
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


def decode_1219(payload: bytes) -> Dict[str, bytes]:
    """
    payloads that begin with 12 19.

    payload = [12][19][body...]
    body -> hdr2 (2 bytes) + blk16 (16 bytes) + tail
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


def match_packet(
    address: str,
    rssi: int,
    manufacturer_data: Dict[int, bytes],
    require_1e_len: bool,
) -> Optional[AirtagMatch]:
    if APPLE_COMPANY_ID not in manufacturer_data:
        return None

    payload = manufacturer_data[APPLE_COMPANY_ID]
    parsed = parse_apple_mfg_for_airtag(payload)
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


def changed_reason(prev: Dict[str, bytes], cur: Dict[str, bytes], mode: str) -> Tuple[bool, str]:
    """
    Returns (changed?, reason_string)
    mode: 'blk16' | 'tail' | 'any'
    """
    if not prev:
        return True, "FIRST"

    if mode == "blk16":
        return (prev.get("blk16", b"") != cur.get("blk16", b"")), "BLK16"
    if mode == "tail":
        return (prev.get("tail", b"") != cur.get("tail", b"")), "TAIL"

    # any
    if prev.get("hdr2", b"") != cur.get("hdr2", b""):
        return True, "HDR2"
    if prev.get("blk16", b"") != cur.get("blk16", b""):
        return True, "BLK16"
    if prev.get("tail", b"") != cur.get("tail", b""):
        return True, "TAIL"
    return False, ""


def diff_any(prev: Dict[str, bytes], cur: Dict[str, bytes]) -> str:
    """
    return FIRST or the first field that changed with OLD->NEW values.
    """
    if not prev:
        return "FIRST"
    for k in ("hdr2", "blk16", "tail"):
        if prev.get(k, b"") != cur.get(k, b""):
            return f"{k.upper()}:{hx(prev.get(k,b''))}->{hx(cur.get(k,b''))}"
    return ""


async def run(args):
    # Per-device state
    last_print_time: Dict[str, float] = {}
    last_parts: Dict[str, Dict[str, bytes]] = {}  # addr -> {"hdr2","blk16","tail"}

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

        parts = decode_1219(match.mfg_payload)
        prev = last_parts.get(addr, {})
        is_changed, reason = changed_reason(prev, parts, args.change_field)

        # Decide whether to print
        if args.print_on_change:
            if not is_changed:
                return
        else:
            if not should_print(addr):
                return

        # Update state AFTER deciding to print
        last_parts[addr] = parts

        hdr2 = parts["hdr2"]
        blk16 = parts["blk16"]
        tail = parts["tail"]

        # For mode=any, include old->new diff
        label = diff_any(prev, parts) if args.change_field == "any" else reason
        change_tag = f" CHANGED({label})" if args.print_on_change else ""

        print(
            f"[AIRTAG?]{change_tag} {addr} RSSI:{match.rssi:4d} "
            f"type:0x{match.apple_type:02X} len:0x{match.apple_len:02X} "
            f"adlen:0x{match.ad_struct_len_byte:02X} "
            f"hdr2:{hx(hdr2)} blk16:{hx(blk16)} tail:{hx(tail)} "
            f"fp_full:{fp12(match.mfg_payload)} fp_blk16:{fp12(blk16)} fp_tail:{fp12(tail)} "
            f"mfg:{hx(match.mfg_payload)}"
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
    ap = argparse.ArgumentParser(description="Detect Apple (0x004C) AirTag/Find My BLE manufacturer frames.")
    ap.add_argument("--duration", type=float, default=300, help="Scan duration in seconds (default: 300)")
    ap.add_argument(
        "--require-1e",
        action="store_true",
        help="Require reconstructed manufacturer AD structure length byte to be 0x1E",
    )
    ap.add_argument(
        "--show-all-apple",
        action="store_true",
        help="Also print all Apple (0x004C) manufacturer frames (useful for tuning)",
    )
    ap.add_argument(
        "--dedup",
        type=float,
        default=2.0,
        help="Deduplicate prints per address within this many seconds (default: 2.0). Use 0 to disable.",
    )
    ap.add_argument(
        "--print-on-change",
        action="store_true",
        help="Only print when selected field changes per address",
    )
    ap.add_argument(
        "--change-field",
        choices=["blk16", "tail", "any"],
        default="blk16",
        help="Which part must change to print when --print-on-change is enabled",
    )
    ap.add_argument(
        "--print-ad-struct",
        action="store_true",
        help="Also print reconstructed AD structure hex on a second line",
    )
    args = ap.parse_args()

    asyncio.run(run(args))


if __name__ == "__main__":
    main()
