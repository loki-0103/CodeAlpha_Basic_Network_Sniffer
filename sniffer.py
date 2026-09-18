#!/usr/bin/env python3
"""
Network Traffic Packet Sniffer & Protocol Analyzer

A comprehensive tool to capture, dissect, inspect, and analyze network packets,
study the TCP/IP stack, and explore protocol architectures.
"""

import argparse
import sys

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from colorama import Fore, Style

from utils.display import print_banner
from core.scapy_engine import ScapySniffer, list_interfaces, get_best_interface
from core.raw_socket_engine import RawSocketSniffer
from education.protocol_guide import show_guide


def build_parser() -> argparse.ArgumentParser:
    """Configure CLI command-line arguments and subcommands."""
    parser = argparse.ArgumentParser(
        description="Network Traffic Packet Sniffer & Protocol Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # 1. Quick live capture on default active interface (Wi-Fi):
  python sniffer.py sniff --count 20

  # 2. Capture only DNS or HTTP traffic with BPF filter:
  python sniffer.py sniff --filter "udp port 53 or tcp port 80" --count 10

  # 3. Deep-dive verbose inspection with full headers and hex dump:
  python sniffer.py sniff --verbose --count 5

  # 4. Save live capture to a PCAP file for Wireshark:
  python sniffer.py sniff --count 50 --output capture.pcap

  # 5. Read and analyze an existing PCAP file:
  python sniffer.py read capture.pcap

  # 6. List all network adapters and active IPs:
  python sniffer.py interfaces

  # 7. Learn protocol internals and view RFC diagrams:
  python sniffer.py learn tcp
  python sniffer.py learn handshake

  # 8. Run educational raw socket unpacking engine (requires Admin):
  python sniffer.py raw --count 20
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Operational mode")

    # --- Sniff Subcommand ---
    sniff_parser = subparsers.add_parser("sniff", help="Capture live network traffic (Default)")
    sniff_parser.add_argument("-i", "--interface", type=str, default=None,
                              help="Network interface name or index (defaults to auto-detected active adapter)")
    sniff_parser.add_argument("-c", "--count", type=int, default=0,
                              help="Number of packets to capture (0 = continuous until Ctrl+C)")
    sniff_parser.add_argument("-t", "--timeout", type=int, default=None,
                              help="Stop capture after N seconds")
    sniff_parser.add_argument("-f", "--filter", type=str, default="",
                              help="BPF filter expression (e.g. 'tcp port 443', 'icmp', 'host 1.1.1.1')")
    sniff_parser.add_argument("-s", "--save", "-o", "--output", dest="save_file", nargs="?", const="auto", default=None,
                              help="Save captured packets to file (.pcap, .json, .csv, .txt). If specified without filename, auto-generates timestamped .pcap")
    sniff_parser.add_argument("-v", "--verbose", action="store_true",
                              help="Verbose mode: Print detailed header fields and payload hexdump")
    sniff_parser.add_argument("--no-stats", action="store_true",
                              help="Suppress the post-capture traffic statistics report")

    # --- Read Subcommand ---
    read_parser = subparsers.add_parser("read", help="Read and analyze an existing PCAP file")
    read_parser.add_argument("file", type=str, help="Path to .pcap or .pcapng file")
    read_parser.add_argument("-v", "--verbose", action="store_true",
                             help="Verbose mode: Print detailed header fields and payload hexdump")
    read_parser.add_argument("-f", "--filter", type=str, default="",
                             help="BPF filter expression to filter packets")
    read_parser.add_argument("-s", "--save", dest="save_file", type=str, default=None,
                             help="Export analyzed packets to another format (.json, .csv, .txt)")

    # --- Interfaces Subcommand ---
    subparsers.add_parser("interfaces", help="List all available network interfaces and IP addresses")

    # --- Learn Subcommand ---
    learn_parser = subparsers.add_parser("learn", help="Interactive educational guide for network protocols")
    learn_parser.add_argument("topic", nargs="?", default="all",
                              choices=["all", "osi", "ip", "ipv4", "tcp", "handshake", "udp", "icmp"],
                              help="Protocol topic to study (default: all)")

    # --- Raw Socket Subcommand ---
    raw_parser = subparsers.add_parser("raw", help="Educational pure-Python raw socket packet capture")
    raw_parser.add_argument("--ip", type=str, default="0.0.0.0",
                            help="Local IP to bind socket to (default: auto-detected)")
    raw_parser.add_argument("-c", "--count", type=int, default=0,
                            help="Number of packets to capture")
    raw_parser.add_argument("-t", "--timeout", type=int, default=None,
                            help="Stop capture after N seconds")
    raw_parser.add_argument("-v", "--verbose", action="store_true",
                            help="Verbose mode with raw payload hexdump")
    raw_parser.add_argument("-s", "--save", "-o", "--output", dest="save_file", nargs="?", const="auto", default=None,
                            help="Save captured packets to file (.json, .csv, .txt)")

    return parser


def main():
    print_banner()
    parser = build_parser()

    # Default to 'sniff' if no arguments provided
    if len(sys.argv) == 1:
        parser.print_help()
        print(f"\n{Fore.YELLOW}[*] Tip: Running continuous sniff mode. Press Ctrl+C to stop at any time.{Style.RESET_ALL}\n")
        args = parser.parse_args(["sniff", "--count", "0"])
    else:
        args = parser.parse_args()

    if args.command == "interfaces":
        list_interfaces()
        return

    elif args.command == "learn":
        show_guide(args.topic)
        return

    elif args.command == "read":
        sniffer = ScapySniffer()
        stats = sniffer.read_pcap(filepath=args.file, bpf_filter=args.filter, verbose=args.verbose)
        if stats:
            stats.print_summary()
        if args.save_file and sniffer.parsed_records:
            from utils.storage import save_capture
            save_capture(args.save_file, parsed_records=sniffer.parsed_records, stats=stats)
        return

    elif args.command == "raw":
        raw_sniffer = RawSocketSniffer(host_ip=args.ip)
        stats = raw_sniffer.start_sniff(
            count=args.count,
            timeout=args.timeout,
            verbose=args.verbose,
            save_file=args.save_file,
        )
        stats.print_summary()
        return

    elif args.command == "sniff":
        # Resolve interface if specified by number/name
        target_iface = None
        if args.interface:
            try:
                # Check if interface index was given
                idx = int(args.interface)
                ifaces = list_interfaces()
                for item in ifaces:
                    if item["index"] == idx:
                        target_iface = item["iface"]
                        break
            except ValueError:
                target_iface = args.interface

        sniffer = ScapySniffer()
        stats = sniffer.start_sniff(
            iface=target_iface,
            count=args.count,
            timeout=args.timeout,
            bpf_filter=args.filter,
            verbose=args.verbose,
            save_file=args.save_file,
        )

        if not args.no_stats and stats and stats.total_packets > 0:
            stats.print_summary()
        return


if __name__ == "__main__":
    main()
