"""Scapy-based live sniffing and PCAP reading engine."""

import os
import sys
import time
from typing import Optional, List, Dict

from scapy.all import conf, sniff, PcapWriter, PcapReader
from colorama import Fore, Style

from core.analyzer import PacketAnalyzer
from utils.display import print_packet_summary, print_packet_detail
from utils.stats import TrafficStats
from utils.storage import save_capture


def list_interfaces() -> List[Dict]:
    """Retrieve and display all available network interfaces."""
    interfaces = []
    print(f"\n{Fore.CYAN}{Style.BRIGHT}==================== AVAILABLE NETWORK INTERFACES ===================={Style.RESET_ALL}")
    print(f"  {'#':<3} {'Interface Name':<32} {'IP Address':<18} {'MAC Address'}")
    print(f"  {'-'*70}")

    idx = 0
    for key, iface in conf.ifaces.items():
        idx += 1
        name = getattr(iface, "name", str(key))
        description = getattr(iface, "description", "")
        ip = getattr(iface, "ip", "") or "No IPv4"
        mac = getattr(iface, "mac", "") or "N/A"
        
        display_name = name if len(name) <= 30 else name[:27] + "..."
        print(f"  {idx:<3} {Fore.GREEN}{display_name:<32}{Style.RESET_ALL} {Fore.YELLOW}{ip:<18}{Style.RESET_ALL} {mac}")
        interfaces.append({
            "index": idx,
            "id": key,
            "iface": iface,
            "name": name,
            "description": description,
            "ip": ip,
            "mac": mac,
        })

    print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")
    return interfaces


def get_best_interface():
    """
    Intelligently select the best active network interface.
    Prioritizes active non-loopback interfaces with routable private/public IPv4.
    """
    candidates = []
    for key, iface in conf.ifaces.items():
        ip = getattr(iface, "ip", "")
        name = getattr(iface, "name", "").lower()
        desc = getattr(iface, "description", "").lower()
        
        # Exclude loopback unless no other options
        is_loopback = "loopback" in name or "loopback" in desc or ip.startswith("127.")
        # Exclude link-local autoconfigured (169.254.x.x)
        is_link_local = ip.startswith("169.254.")
        
        if ip and not is_loopback and not is_link_local:
            # High priority: Wi-Fi or active Ethernet
            score = 10
            if "wi-fi" in name or "wireless" in desc or "wireless" in name:
                score += 5
            candidates.append((score, iface))

    if candidates:
        candidates.sort(key=lambda x: x[0], reverse=True)
        return candidates[0][1]

    # Fallback to Scapy default
    return conf.iface


class ScapySniffer:
    """Manages live packet sniffing and PCAP replay."""

    def __init__(self):
        self.stats = TrafficStats()
        self.packet_counter = 0
        self.captured_packets = []
        self.parsed_records = []

    def start_sniff(
        self,
        iface=None,
        count: int = 0,
        timeout: Optional[int] = None,
        bpf_filter: str = "",
        verbose: bool = False,
        save_file: Optional[str] = None,
    ):
        """
        Start live packet capture.
        
        Args:
            iface: Interface name or object. If None, auto-selects best.
            count: Number of packets to capture (0 = infinite until Ctrl+C).
            timeout: Stop capture after N seconds.
            bpf_filter: BPF syntax filter string (e.g. 'tcp port 80', 'icmp').
            verbose: If True, prints full packet detail trees.
            save_file: Output file path (.pcap, .json, .csv, .txt) or 'auto'.
        """
        target_iface = iface or get_best_interface()
        iface_name = getattr(target_iface, "name", str(target_iface))
        iface_ip = getattr(target_iface, "ip", "Unknown")

        print(f"{Fore.CYAN}[*] Starting packet capture on interface: {Fore.GREEN}{iface_name}{Fore.CYAN} ({iface_ip}){Style.RESET_ALL}")
        if bpf_filter:
            print(f"{Fore.CYAN}[*] Applied BPF Filter: {Fore.YELLOW}{bpf_filter}{Style.RESET_ALL}")
        if count > 0:
            print(f"{Fore.CYAN}[*] Capture limit: {count} packets{Style.RESET_ALL}")
        if timeout:
            print(f"{Fore.CYAN}[*] Capture timeout: {timeout} seconds{Style.RESET_ALL}")
        if save_file:
            print(f"{Fore.CYAN}[*] Save option enabled: {Fore.YELLOW}{save_file}{Style.RESET_ALL}")
        print(f"{Fore.LIGHTBLACK_EX}[*] Press Ctrl+C at any time to halt capture and review statistics.{Style.RESET_ALL}\n")

        self.packet_counter = 0
        self.captured_packets = []
        self.parsed_records = []

        def packet_handler(pkt):
            self.packet_counter += 1
            self.captured_packets.append(pkt)

            details = PacketAnalyzer.dissect(pkt, index=self.packet_counter)
            self.parsed_records.append(details)
            
            # Update stats
            self.stats.update(
                proto=details["protocol"],
                src=details["src"],
                dst=details["dst"],
                length=details["length"],
                sport=details["sport"],
                dport=details["dport"],
                flags=details["tcp_flags"],
            )

            # Display
            if verbose:
                print_packet_detail(details)
            else:
                print_packet_summary(
                    packet_idx=details["index"],
                    timestamp=details["timestamp"],
                    proto=details["protocol"],
                    src=f"{details['src']}:{details['sport']}" if details['sport'] else details['src'],
                    dst=f"{details['dst']}:{details['dport']}" if details['dport'] else details['dst'],
                    length=details["length"],
                    info=details["info"],
                )

        try:
            sniff(
                iface=target_iface,
                prn=packet_handler,
                count=count,
                timeout=timeout,
                filter=bpf_filter if bpf_filter else None,
                store=False,
            )
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[!] Capture interrupted by user (Ctrl+C).{Style.RESET_ALL}")
        except PermissionError:
            print(f"\n{Fore.RED}[x] Permission Denied! Live packet capture requires Administrator privileges.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[!] Please reopen PowerShell or Terminal as Administrator.{Style.RESET_ALL}")
        except Exception as e:
            print(f"\n{Fore.RED}[x] Capture Error: {e}{Style.RESET_ALL}")
        finally:
            if save_file and self.captured_packets:
                save_capture(
                    filepath=save_file,
                    raw_packets=self.captured_packets,
                    parsed_records=self.parsed_records,
                    stats=self.stats,
                )

        return self.stats

    def read_pcap(self, filepath: str, bpf_filter: str = "", verbose: bool = False):
        """
        Analyze an existing PCAP file.
        
        Args:
            filepath: Path to .pcap or .pcapng file.
            bpf_filter: Optional BPF filter to match packets.
            verbose: If True, prints full packet detail trees.
        """
        if not os.path.exists(filepath):
            print(f"{Fore.RED}[x] Error: File '{filepath}' does not exist.{Style.RESET_ALL}")
            return None

        print(f"\n{Fore.CYAN}[*] Reading and analyzing PCAP file: {Fore.YELLOW}{filepath}{Style.RESET_ALL}")
        self.packet_counter = 0

        try:
            reader = PcapReader(filepath)
            for pkt in reader:
                self.packet_counter += 1
                details = PacketAnalyzer.dissect(pkt, index=self.packet_counter)
                
                self.stats.update(
                    proto=details["protocol"],
                    src=details["src"],
                    dst=details["dst"],
                    length=details["length"],
                    sport=details["sport"],
                    dport=details["dport"],
                    flags=details["tcp_flags"],
                )

                if verbose:
                    print_packet_detail(details)
                else:
                    print_packet_summary(
                        packet_idx=details["index"],
                        timestamp=details["timestamp"],
                        proto=details["protocol"],
                        src=f"{details['src']}:{details['sport']}" if details['sport'] else details['src'],
                        dst=f"{details['dst']}:{details['dport']}" if details['dport'] else details['dst'],
                        length=details["length"],
                        info=details["info"],
                    )
            reader.close()
            print(f"\n{Fore.GREEN}[+] Processed {self.packet_counter} packets from '{filepath}'.{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[x] Failed to read PCAP: {e}{Style.RESET_ALL}")

        return self.stats
