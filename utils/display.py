"""Terminal display, color formatting, and hexdump utilities for packet sniffing."""

import sys
from datetime import datetime
from colorama import Fore, Back, Style, init

# Initialize colorama (autoreset for Windows terminals)
init(autoreset=True)

# Protocol badge color mappings
PROTO_COLORS = {
    "TCP": Fore.CYAN,
    "UDP": Fore.GREEN,
    "ICMP": Fore.YELLOW,
    "DNS": Fore.MAGENTA,
    "ARP": Fore.BLUE,
    "HTTP": Fore.LIGHTYELLOW_EX,
    "HTTPS": Fore.LIGHTCYAN_EX,
    "TLS": Fore.LIGHTCYAN_EX,
    "DHCP": Fore.LIGHTBLUE_EX,
    "IPv4": Fore.WHITE,
    "IPv6": Fore.LIGHTMAGENTA_EX,
    "RAW": Fore.LIGHTBLACK_EX,
}


def color_protocol(proto: str) -> str:
    """Format a protocol name with its associated color tag."""
    proto_upper = proto.upper()
    color = PROTO_COLORS.get(proto_upper, Fore.WHITE)
    return f"{Style.BRIGHT}{color}[{proto_upper:<5}]{Style.RESET_ALL}"


def print_banner():
    """Print the application title banner."""
    art = r"""
========================================================================
   _  __     __                   __   ____        _ ______         
  / |/ /__  / /__    _____  _____/ /__/ __/ ___  (_) _/ _/__ ____ 
 /    / -_)/ __/ |/|/ / _ \/ __/  '_/\ \/ _ \/ / _// _/ -_) __/ 
/_/|_/\__/ \__/|__,__/\___/_/ /_/\_\/___/_//_/_/_/ /_/  \__/_/   
          Packet Capture, Protocol Dissection & Traffic Analysis
========================================================================"""
    print(f"{Fore.CYAN}{Style.BRIGHT}{art}{Style.RESET_ALL}")


def format_timestamp(ts: float = None) -> str:
    """Return formatted human-readable timestamp."""
    dt = datetime.fromtimestamp(ts) if ts else datetime.now()
    return f"{Fore.LIGHTBLACK_EX}{dt.strftime('%H:%M:%S.%f')[:-3]}{Style.RESET_ALL}"


def hexdump(data: bytes, length: int = 16, max_bytes: int = 256) -> str:
    """
    Format raw bytes into traditional 16-byte hex + ASCII view (like Wireshark/tcpdump -X).
    
    Args:
        data: Raw payload byte string.
        length: Number of bytes per line (standard 16).
        max_bytes: Maximum total bytes to display to prevent terminal flooding.
        
    Returns:
        Formatted multi-line hexdump string.
    """
    if not data:
        return f"    {Fore.LIGHTBLACK_EX}(empty payload){Style.RESET_ALL}"
    
    lines = []
    truncated = False
    display_data = data
    if len(data) > max_bytes:
        display_data = data[:max_bytes]
        truncated = True

    for i in range(0, len(display_data), length):
        chunk = display_data[i:i + length]
        # Offset
        offset = f"{Fore.LIGHTBLACK_EX}0x{i:04x}{Style.RESET_ALL}"
        
        # Hex representation
        hex_bytes = " ".join(f"{b:02x}" for b in chunk)
        # Pad if short
        hex_padded = f"{hex_bytes:<{length * 3}}"
        
        # Printable ASCII representation
        ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        
        lines.append(f"    {offset}  {Fore.YELLOW}{hex_padded}{Style.RESET_ALL} |{Fore.WHITE}{ascii_str}{Style.RESET_ALL}|")

    if truncated:
        lines.append(f"    {Fore.LIGHTBLACK_EX}... ({len(data) - max_bytes} more bytes truncated) ...{Style.RESET_ALL}")
        
    return "\n".join(lines)


def print_packet_summary(packet_idx: int, timestamp: float, proto: str, src: str, dst: str, length: int, info: str):
    """Print a single-line packet summary suitable for high-speed live monitoring."""
    time_str = format_timestamp(timestamp)
    badge = color_protocol(proto)
    idx_str = f"{Fore.LIGHTBLACK_EX}#{packet_idx:<5}{Style.RESET_ALL}"
    src_dst = f"{Fore.WHITE}{src:<21}{Style.RESET_ALL} -> {Fore.WHITE}{dst:<21}{Style.RESET_ALL}"
    len_str = f"{Fore.LIGHTBLACK_EX}{length:>5}B{Style.RESET_ALL}"
    info_str = f"{Style.BRIGHT}{info}{Style.RESET_ALL}"
    
    print(f"{idx_str} {time_str} {badge} {src_dst} {len_str} | {info_str}")


def print_packet_detail(details: dict):
    """Print a deep-dive tree breakdown of a single packet's layers and headers."""
    print(f"\n{Fore.CYAN}{'='*72}{Style.RESET_ALL}")
    print(f"{Style.BRIGHT}PACKET #{details.get('index', 0)} DETAIL - {details.get('protocol', 'UNKNOWN')}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'-'*72}{Style.RESET_ALL}")
    
    # Layer 2: Ethernet
    if "ethernet" in details:
        eth = details["ethernet"]
        print(f"{Fore.LIGHTBLUE_EX}[+] Layer 2 (Data Link - Ethernet II){Style.RESET_ALL}")
        print(f"    ├── Source MAC:      {eth.get('src_mac', 'N/A')}")
        print(f"    ├── Destination MAC: {eth.get('dst_mac', 'N/A')}")
        print(f"    └── EtherType:       {eth.get('type', 'N/A')}")
    
    # Layer 3: Network (IPv4, IPv6, ARP)
    if "network" in details:
        net = details["network"]
        net_type = net.get("type", "IP")
        print(f"{Fore.LIGHTGREEN_EX}[+] Layer 3 (Network - {net_type}){Style.RESET_ALL}")
        for k, v in net.items():
            if k != "type":
                print(f"    ├── {k.replace('_', ' ').title():<17}: {v}")
                
    # Layer 4: Transport (TCP, UDP, ICMP)
    if "transport" in details:
        trans = details["transport"]
        trans_proto = trans.get("protocol", "Transport")
        print(f"{Fore.LIGHTYELLOW_EX}[+] Layer 4 (Transport - {trans_proto}){Style.RESET_ALL}")
        for k, v in trans.items():
            if k != "protocol":
                print(f"    ├── {k.replace('_', ' ').title():<17}: {v}")
                
    # Layer 7: Application
    if "application" in details:
        app = details["application"]
        app_name = app.get("name", "Application")
        print(f"{Fore.MAGENTA}[+] Layer 7 (Application - {app_name}){Style.RESET_ALL}")
        for k, v in app.items():
            if k != "name":
                print(f"    ├── {k.replace('_', ' ').title():<17}: {v}")

    # Payload
    payload = details.get("payload_bytes", b"")
    if payload:
        print(f"{Fore.WHITE}[+] Raw Payload ({len(payload)} bytes):{Style.RESET_ALL}")
        print(hexdump(payload))
    print(f"{Fore.CYAN}{'='*72}{Style.RESET_ALL}\n")
