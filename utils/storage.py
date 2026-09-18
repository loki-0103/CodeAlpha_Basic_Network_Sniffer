"""Export and file saving utilities for captured network packets.

Supports PCAP (Wireshark), JSON, CSV, and text report formats, with automatic
fallback handling for protected directories on Windows.
"""

import os
import csv
import json
from datetime import datetime
from typing import List, Dict, Any, Optional

from scapy.all import wrpcap, Packet
from colorama import Fore, Style


def generate_default_filename(ext: str = "pcap") -> str:
    """Generate a timestamped filename like capture_20260918_114500.pcap."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"capture_{timestamp}.{ext.lstrip('.')}"


def _resolve_save_path(filepath: str) -> str:
    """
    Ensure the path is valid. If target directory is not writable (e.g. Windows Protected Folders),
    fall back to the user's Downloads directory.
    """
    filepath = os.path.abspath(filepath)
    target_dir = os.path.dirname(filepath)
    basename = os.path.basename(filepath)

    # Test if target directory is writable
    try:
        test_file = os.path.join(target_dir, f".write_test_{os.getpid()}.tmp")
        with open(test_file, "w") as f:
            f.write("ok")
        os.remove(test_file)
        return filepath
    except (PermissionError, OSError):
        # Fallback to Downloads folder
        downloads_dir = os.path.expanduser("~/Downloads")
        fallback_path = os.path.join(downloads_dir, basename)
        return fallback_path


def export_pcap(packets: List[Packet], filepath: str) -> str:
    """Save raw Scapy packets to a PCAP file."""
    actual_path = _resolve_save_path(filepath)
    wrpcap(actual_path, packets)
    return actual_path


def export_json(parsed_records: List[Dict[str, Any]], stats: Optional[Any], filepath: str) -> str:
    """Save parsed packet records and session summary to a JSON file."""
    actual_path = _resolve_save_path(filepath)
    
    # Format records for JSON serialization (convert bytes to hex/ascii)
    serializable_records = []
    for r in parsed_records:
        rec = dict(r)
        if "payload_bytes" in rec:
            payload = rec.pop("payload_bytes")
            rec["payload_hex"] = payload.hex() if isinstance(payload, bytes) else ""
            rec["payload_len"] = len(payload) if isinstance(payload, bytes) else 0
        serializable_records.append(rec)

    data = {
        "export_time": datetime.now().isoformat(),
        "total_packets": len(serializable_records),
        "packets": serializable_records,
    }

    if stats:
        data["summary"] = {
            "duration_seconds": stats.get_duration(),
            "total_bytes": stats.total_bytes,
            "protocol_counts": dict(stats.protocols),
            "top_source_ips": dict(stats.src_ips.most_common(5)),
            "top_destination_ips": dict(stats.dst_ips.most_common(5)),
            "tcp_flags": dict(stats.tcp_flags),
        }

    with open(actual_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    return actual_path


def export_csv(parsed_records: List[Dict[str, Any]], filepath: str) -> str:
    """Save packet records as a tabular CSV spreadsheet."""
    actual_path = _resolve_save_path(filepath)
    
    fieldnames = [
        "Index", "Timestamp", "Protocol", "Source_IP", "Source_Port",
        "Dest_IP", "Dest_Port", "Length", "TCP_Flags", "Info"
    ]

    with open(actual_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in parsed_records:
            writer.writerow({
                "Index": r.get("index"),
                "Timestamp": r.get("timestamp"),
                "Protocol": r.get("protocol"),
                "Source_IP": r.get("src"),
                "Source_Port": r.get("sport") or "",
                "Dest_IP": r.get("dst"),
                "Dest_Port": r.get("dport") or "",
                "Length": r.get("length"),
                "TCP_Flags": ",".join(r.get("tcp_flags", [])),
                "Info": r.get("info", ""),
            })
    return actual_path


def export_text(parsed_records: List[Dict[str, Any]], stats: Optional[Any], filepath: str) -> str:
    """Save human-readable packet logs and summary to a text file."""
    actual_path = _resolve_save_path(filepath)
    with open(actual_path, "w", encoding="utf-8") as f:
        f.write("==================== NETWORK PACKET CAPTURE LOG ====================\n")
        f.write(f"Export Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Total Packets: {len(parsed_records)}\n\n")
        
        for r in parsed_records:
            src = f"{r.get('src')}:{r.get('sport')}" if r.get("sport") else r.get("src")
            dst = f"{r.get('dst')}:{r.get('dport')}" if r.get("dport") else r.get("dst")
            f.write(f"#{r.get('index', 0):<5} [{r.get('protocol', 'UNKNOWN'):<5}] {src:<24} -> {dst:<24} {r.get('length', 0):>5}B | {r.get('info', '')}\n")
            
        if stats:
            f.write("\n==================== SESSION SUMMARY ====================\n")
            f.write(f"Duration: {stats.get_duration():.2f}s\n")
            f.write(f"Total Volume: {stats.total_bytes / 1024:.2f} KB ({stats.total_bytes} bytes)\n")
            f.write(f"Protocols: {dict(stats.protocols)}\n")
    return actual_path


def save_capture(
    filepath: str,
    raw_packets: List[Packet] = None,
    parsed_records: List[Dict[str, Any]] = None,
    stats: Optional[Any] = None,
) -> Optional[str]:
    """
    Save captured traffic to the specified format (auto-detected from file extension).
    
    Supported formats:
      - .pcap / .pcapng : Binary PCAP for Wireshark
      - .json           : Structured JSON data
      - .csv            : CSV spreadsheet
      - .txt / .log     : Human-readable text log
    """
    if not filepath:
        return None

    # Auto-generate name if user passed 'auto' or directory
    if filepath.lower() == "auto":
        filepath = generate_default_filename("pcap")
    elif os.path.isdir(filepath):
        filepath = os.path.join(filepath, generate_default_filename("pcap"))

    ext = os.path.splitext(filepath)[1].lower()
    if not ext:
        ext = ".pcap"
        filepath += ".pcap"

    try:
        saved_path = filepath
        if ext in [".pcap", ".pcapng"]:
            if raw_packets:
                saved_path = export_pcap(raw_packets, filepath)
            else:
                print(f"{Fore.YELLOW}[!] Note: Raw packets not available for PCAP export. Exporting JSON instead.{Style.RESET_ALL}")
                saved_path = export_json(parsed_records or [], stats, filepath.replace(ext, ".json"))
        elif ext == ".json":
            saved_path = export_json(parsed_records or [], stats, filepath)
        elif ext == ".csv":
            saved_path = export_csv(parsed_records or [], filepath)
        elif ext in [".txt", ".log"]:
            saved_path = export_text(parsed_records or [], stats, filepath)
        else:
            # Default to PCAP
            saved_path = export_pcap(raw_packets, filepath)

        file_size = os.path.getsize(saved_path) / 1024 if os.path.exists(saved_path) else 0
        print(f"\n{Fore.GREEN}{Style.BRIGHT}[+] Capture saved successfully!{Style.RESET_ALL}")
        print(f"    File: {Fore.YELLOW}{saved_path}{Style.RESET_ALL} ({file_size:.2f} KB)")
        if saved_path != os.path.abspath(filepath):
            print(f"    {Fore.CYAN}(Target directory was protected by Windows Defender; saved to Downloads instead){Style.RESET_ALL}")
        return saved_path

    except Exception as e:
        print(f"{Fore.RED}[x] Failed to save capture: {e}{Style.RESET_ALL}")
        return None
