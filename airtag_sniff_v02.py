#!/usr/bin/env python3
"""
Enhanced AirTag/FindMy Device Detection Script

Improvements over basic version:
- Confidence scoring system
- Status byte decoding
- Rotation pattern tracking
- RSSI validation
- Timing analysis
- False positive filtering
- Multi-device correlation across address changes
"""

import argparse
import asyncio
import binascii
import hashlib
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple, List

from bleak import BleakScanner

APPLE_COMPANY_ID = 0x004C


def hx(b: bytes) -> str:
    return binascii.hexlify(b).decode("ascii").upper()


def fp12(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()[:12] if b else ""


@dataclass
class DeviceHistory:
    """Track historical data for a single MAC address"""
    first_seen: float
    last_seen: float
    rssi_history: deque = field(default_factory=lambda: deque(maxlen=10))
    timestamps: deque = field(default_factory=lambda: deque(maxlen=20))
    blk16_history: deque = field(default_factory=lambda: deque(maxlen=5))
    tail_history: deque = field(default_factory=lambda: deque(maxlen=5))
    status_history: deque = field(default_factory=lambda: deque(maxlen=5))
    rotation_count: int = 0
    last_blk16: bytes = b""
    last_tail: bytes = b""


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
    confidence: float = 0.0
    confidence_breakdown: Dict[str, float] = field(default_factory=dict)


def parse_apple_mfg_for_airtag(payload: bytes) -> Optional[Tuple[int, int]]:
    """
    Enhanced detection heuristic:
      payload[0] == 0x12 (FindMy/Offline Finding protocol)
      payload[1] == 0x19 (classic length, can be 0x19-0x1B)
    """
    if not payload or len(payload) < 2:
        return None
    
    apple_type = payload[0]
    apple_len = payload[1]
    
    # 0x12 = FindMy/Offline Finding
    if apple_type != 0x12:
        return None
    
    # Standard AirTag length is 0x19, but be slightly flexible
    if apple_len < 0x19 or apple_len > 0x1B:
        return None
    
    return apple_type, apple_len


def decode_status_bytes(hdr2: bytes) -> Dict[str, any]:
    """
    Decode the 2-byte status/state header
    Note: This is a heuristic interpretation
    """
    if len(hdr2) < 2:
        return {"valid": False}
    
    status = {
        "valid": True,
        "byte0": hdr2[0],
        "byte1": hdr2[1],
        "state_nibble": (hdr2[0] >> 4) & 0x0F,
        "lower_nibble": hdr2[0] & 0x0F,
        "raw": hx(hdr2)
    }
    return status


def is_known_non_airtag(payload: bytes) -> bool:
    """Filter out known non-AirTag Apple device types"""
    if not payload or len(payload) < 1:
        return False
    
    apple_type = payload[0]
    
    # Known non-AirTag types
    NON_AIRTAG_TYPES = {
        0x07,  # AirPods proximity pairing
        0x10,  # Nearby
        0x0C,  # Handoff
        0x05,  # Magic Switch
        0x09,  # AirPlay target
        0x0A,  # AirPlay source
    }
    
    return apple_type in NON_AIRTAG_TYPES


def validate_rssi(rssi: int, history: deque) -> Tuple[bool, str]:
    """
    Validate RSSI is within reasonable bounds
    Returns: (is_valid, reason)
    """
    # Unrealistic values
    if rssi > -20 or rssi < -100:
        return False, f"out_of_range({rssi})"
    
    # Check for unrealistic jumps if we have history
    if len(history) >= 3:
        avg = sum(history) / len(history)
        if abs(rssi - avg) > 35:
            return False, f"sudden_jump({rssi}_vs_avg_{avg:.1f})"
    
    return True, "ok"


def analyze_timing(timestamps: deque) -> Dict[str, any]:
    """
    Analyze advertisement timing patterns
    AirTags typically advertise every 2 seconds when separated
    """
    if len(timestamps) < 3:
        return {"valid": False}
    
    intervals = [timestamps[i] - timestamps[i-1] 
                 for i in range(1, len(timestamps))]
    
    avg_interval = sum(intervals) / len(intervals)
    min_interval = min(intervals)
    max_interval = max(intervals)
    
    # AirTags typically: 0.5-5 seconds between advertisements
    is_airtag_like = 0.5 <= avg_interval <= 5.0
    
    return {
        "valid": True,
        "avg_interval": avg_interval,
        "min_interval": min_interval,
        "max_interval": max_interval,
        "is_airtag_like": is_airtag_like,
        "sample_count": len(intervals)
    }


def detect_rotation(current_blk16: bytes, history: deque) -> bool:
    """
    Detect if the public key (blk16) has rotated
    AirTags rotate their public key periodically
    """
    if not current_blk16 or len(current_blk16) != 16:
        return False
    
    for prev_blk16 in history:
        if prev_blk16 != current_blk16:
            return True
    
    return False


def calculate_confidence(
    match: AirtagMatch,
    parts: Dict[str, bytes],
    history: DeviceHistory,
    timing_info: Dict
) -> Tuple[float, Dict[str, float]]:
    """
    Calculate confidence score (0.0-1.0) that this is an AirTag
    Returns: (total_score, breakdown_dict)
    """
    breakdown = {}
    
    # 1. Perfect type/length match (40%)
    if match.apple_type == 0x12 and match.apple_len == 0x19:
        breakdown["type_match"] = 0.40
    elif match.apple_type == 0x12:
        breakdown["type_match"] = 0.25
    else:
        breakdown["type_match"] = 0.0
    
    # 2. Correct AD structure length (15%)
    if match.ad_struct_len_byte == 0x1E:
        breakdown["ad_struct"] = 0.15
    elif 0x1C <= match.ad_struct_len_byte <= 0x20:
        breakdown["ad_struct"] = 0.08
    else:
        breakdown["ad_struct"] = 0.0
    
    # 3. Valid payload structure (15%)
    if len(parts.get("blk16", b"")) == 16:
        breakdown["payload_struct"] = 0.15
    elif len(parts.get("blk16", b"")) > 0:
        breakdown["payload_struct"] = 0.05
    else:
        breakdown["payload_struct"] = 0.0
    
    # 4. RSSI validation (10%)
    rssi_valid, _ = validate_rssi(match.rssi, history.rssi_history)
    breakdown["rssi"] = 0.10 if rssi_valid else 0.0
    
    # 5. Timing pattern (10%)
    if timing_info.get("valid") and timing_info.get("is_airtag_like"):
        breakdown["timing"] = 0.10
    elif timing_info.get("valid"):
        breakdown["timing"] = 0.03
    else:
        breakdown["timing"] = 0.0
    
    # 6. Rotation detection (10%)
    if history.rotation_count > 0:
        breakdown["rotation"] = 0.10
    else:
        breakdown["rotation"] = 0.0
    
    total = sum(breakdown.values())
    return total, breakdown


def reconstruct_mfg_ad_structure(company_id: int, payload: bytes) -> bytes:
    """
    AD structure:
      [len][type=0xFF][company_id LE 2 bytes][payload...]
    """
    ad_type = 0xFF
    company_le = company_id.to_bytes(2, byteorder="little")
    length = 1 + 2 + len(payload)
    if length > 0xFF:
        raise ValueError("AD structure too large")
    return bytes([length, ad_type]) + company_le + payload


def decode_1219(payload: bytes) -> Dict[str, bytes]:
    """
    Decode 0x12 0x19 frame structure:
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
    """Return FIRST or the first field that changed with OLD->NEW values"""
    if not prev:
        return "FIRST"
    for k in ("hdr2", "blk16", "tail"):
        if prev.get(k, b"") != cur.get(k, b""):
            return f"{k.upper()}:{hx(prev.get(k,b''))}->{hx(cur.get(k,b''))}"
    return ""


async def run(args):
    # Per-device tracking
    device_history: Dict[str, DeviceHistory] = {}
    last_print_time: Dict[str, float] = {}
    last_parts: Dict[str, Dict[str, bytes]] = {}

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
        now = time.time()

        # Show all Apple devices if requested
        if args.show_all_apple and APPLE_COMPANY_ID in mfg and should_print(addr):
            payload = mfg[APPLE_COMPANY_ID]
            if not is_known_non_airtag(payload):
                ad_struct = reconstruct_mfg_ad_structure(APPLE_COMPANY_ID, payload)
                print(
                    f"[APPLE]  {addr} RSSI:{int(rssi):4d} "
                    f"type:0x{payload[0]:02X} len:0x{payload[1]:02X} "
                    f"adlen:0x{ad_struct[0]:02X} mfg:{hx(payload)}"
                )

        # Skip non-AirTag Apple devices
        if APPLE_COMPANY_ID in mfg and is_known_non_airtag(mfg[APPLE_COMPANY_ID]):
            return

        # Parse for AirTag signature
        if APPLE_COMPANY_ID not in mfg:
            return

        payload = mfg[APPLE_COMPANY_ID]
        parsed = parse_apple_mfg_for_airtag(payload)
        if not parsed:
            return

        apple_type, apple_len = parsed
        ad_struct = reconstruct_mfg_ad_structure(APPLE_COMPANY_ID, payload)
        adlen = ad_struct[0]

        if args.require_1e and adlen != 0x1E:
            return

        # Initialize or update device history
        if addr not in device_history:
            device_history[addr] = DeviceHistory(first_seen=now, last_seen=now)
        
        hist = device_history[addr]
        hist.last_seen = now
        hist.rssi_history.append(int(rssi))
        hist.timestamps.append(now)

        # Decode payload parts
        parts = decode_1219(payload)
        hdr2 = parts["hdr2"]
        blk16 = parts["blk16"]
        tail = parts["tail"]

        # Track rotation
        if blk16 and len(blk16) == 16:
            if hist.last_blk16 and hist.last_blk16 != blk16:
                hist.rotation_count += 1
            hist.last_blk16 = blk16
            hist.blk16_history.append(blk16)
        
        hist.tail_history.append(tail)
        hist.status_history.append(hdr2)

        # Analyze timing
        timing_info = analyze_timing(hist.timestamps)

        # Create match object
        match = AirtagMatch(
            address=addr,
            rssi=int(rssi),
            apple_type=apple_type,
            apple_len=apple_len,
            mfg_payload=payload,
            ad_struct_len_byte=adlen,
            ad_struct_hex=hx(ad_struct),
            timestamp=now
        )

        # Calculate confidence
        confidence, breakdown = calculate_confidence(match, parts, hist, timing_info)
        match.confidence = confidence
        match.confidence_breakdown = breakdown

        # Filter by minimum confidence
        if confidence < args.min_confidence:
            return

        # Check change detection
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

        # Build output
        change_label = diff_any(prev, parts) if args.change_field == "any" else reason
        change_tag = f" CHANGED({change_label})" if args.print_on_change else ""
        
        confidence_str = f"conf:{confidence:.2f}"
        if args.verbose:
            breakdown_str = " ".join([f"{k}:{v:.2f}" for k, v in breakdown.items() if v > 0])
            confidence_str = f"conf:{confidence:.2f} [{breakdown_str}]"

        status = decode_status_bytes(hdr2)
        rotation_str = f" rot:{hist.rotation_count}" if hist.rotation_count > 0 else ""

        print(
            f"[AIRTAG]{change_tag} {addr} RSSI:{match.rssi:4d} {confidence_str}{rotation_str} "
            f"type:0x{match.apple_type:02X} len:0x{match.apple_len:02X} "
            f"adlen:0x{match.ad_struct_len_byte:02X}"
        )
        
        if args.verbose:
            print(f"          hdr2:{hx(hdr2)} status:{status}")
            if timing_info.get("valid"):
                print(f"          timing: avg={timing_info['avg_interval']:.2f}s "
                      f"min={timing_info['min_interval']:.2f}s "
                      f"max={timing_info['max_interval']:.2f}s")
        
        print(f"          blk16:{hx(blk16)} tail:{hx(tail)}")
        print(f"          fp_blk16:{fp12(blk16)} fp_tail:{fp12(tail)} fp_full:{fp12(match.mfg_payload)}")
        
        if args.print_ad_struct or args.verbose:
            print(f"          ad_struct:{match.ad_struct_hex}")
        
        if args.verbose:
            print(f"          mfg:{hx(match.mfg_payload)}")

    scanner = BleakScanner(detection_callback=cb)

    print(f"Starting scan for {args.duration} seconds...")
    print(f"Minimum confidence threshold: {args.min_confidence}")
    if args.print_on_change:
        print(f"Print mode: on-change ({args.change_field})")
    else:
        print(f"Print mode: dedup every {args.dedup}s")
    print("-" * 80)

    await scanner.start()
    try:
        await asyncio.sleep(args.duration)
    finally:
        await scanner.stop()
        
        # Summary
        print("-" * 80)
        print(f"Scan complete. Found {len(device_history)} potential AirTag device(s)")
        for addr, hist in device_history.items():
            duration = hist.last_seen - hist.first_seen
            avg_rssi = sum(hist.rssi_history) / len(hist.rssi_history) if hist.rssi_history else 0
            print(f"  {addr}: duration={duration:.1f}s packets={len(hist.timestamps)} "
                  f"avg_rssi={avg_rssi:.1f} rotations={hist.rotation_count}")


def main():
    ap = argparse.ArgumentParser(
        description="Enhanced AirTag/FindMy device detection with confidence scoring",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic scan with default settings
  %(prog)s
  
  # High confidence detections only
  %(prog)s --min-confidence 0.8
  
  # Verbose output with all details
  %(prog)s --verbose
  
  # Only print when blk16 (public key) changes
  %(prog)s --print-on-change --change-field blk16
  
  # Show all Apple devices for tuning
  %(prog)s --show-all-apple --verbose
        """
    )
    ap.add_argument("--duration", type=float, default=300, 
                    help="Scan duration in seconds (default: 300)")
    ap.add_argument("--require-1e", action="store_true",
                    help="Require reconstructed AD structure length to be 0x1E")
    ap.add_argument("--show-all-apple", action="store_true",
                    help="Show all Apple (0x004C) manufacturer frames")
    ap.add_argument("--dedup", type=float, default=2.0,
                    help="Deduplicate prints per address (seconds, default: 2.0, 0=disable)")
    ap.add_argument("--print-on-change", action="store_true",
                    help="Only print when selected field changes")
    ap.add_argument("--change-field", choices=["blk16", "tail", "any"], default="blk16",
                    help="Which part must change to print (with --print-on-change)")
    ap.add_argument("--print-ad-struct", action="store_true",
                    help="Print reconstructed AD structure hex")
    ap.add_argument("--min-confidence", type=float, default=0.6,
                    help="Minimum confidence threshold 0.0-1.0 (default: 0.6)")
    ap.add_argument("--verbose", "-v", action="store_true",
                    help="Verbose output with timing, status decode, and full breakdown")
    
    args = ap.parse_args()

    if args.min_confidence < 0.0 or args.min_confidence > 1.0:
        ap.error("--min-confidence must be between 0.0 and 1.0")

    asyncio.run(run(args))


if __name__ == "__main__":
    main()
