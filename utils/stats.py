"""Traffic statistics collector and metrics aggregator."""

import time
from collections import Counter
from colorama import Fore, Style


class TrafficStats:
    """Aggregates real-time packet statistics, protocol distributions, and top talkers."""

    def __init__(self):
        self.start_time = time.time()
        self.end_time = None
        self.total_packets = 0
        self.total_bytes = 0
        
        self.protocols = Counter()
        self.protocols_bytes = Counter()
        
        self.src_ips = Counter()
        self.dst_ips = Counter()
        self.conversations = Counter()
        
        self.ports = Counter()
        self.tcp_flags = Counter()

    def update(self, proto: str, src: str, dst: str, length: int, sport: int = None, dport: int = None, flags: list = None):
        """Update metrics with a new packet."""
        self.total_packets += 1
        self.total_bytes += length
        
        self.protocols[proto] += 1
        self.protocols_bytes[proto] += length
        
        if src:
            self.src_ips[src] += 1
        if dst:
            self.dst_ips[dst] += 1
        if src and dst:
            self.conversations[f"{src} <-> {dst}"] += 1
            
        if sport:
            self.ports[sport] += 1
        if dport:
            self.ports[dport] += 1
            
        if flags:
            for flag in flags:
                self.tcp_flags[flag] += 1

    def close(self):
        """Finalize the session timer."""
        if not self.end_time:
            self.end_time = time.time()

    def get_duration(self) -> float:
        """Get total capture duration in seconds."""
        current = self.end_time or time.time()
        return max(0.001, current - self.start_time)

    def print_summary(self):
        """Print a structured statistics report."""
        self.close()
        duration = self.get_duration()
        pps = self.total_packets / duration
        kbps = (self.total_bytes / 1024) / duration

        print(f"\n{Fore.GREEN}{Style.BRIGHT}==================== CAPTURE TRAFFIC SUMMARY ===================={Style.RESET_ALL}")
        print(f"  Duration:            {Fore.WHITE}{duration:.2f} seconds{Style.RESET_ALL}")
        print(f"  Total Packets:       {Fore.CYAN}{self.total_packets:,}{Style.RESET_ALL}")
        print(f"  Total Volume:        {Fore.CYAN}{self.total_bytes / 1024:.2f} KB ({self.total_bytes:,} bytes){Style.RESET_ALL}")
        print(f"  Average Throughput:  {Fore.YELLOW}{pps:.1f} packets/sec | {kbps:.2f} KB/sec{Style.RESET_ALL}")
        print(f"{Fore.GREEN}{'-'*64}{Style.RESET_ALL}")

        # Protocol Breakdown
        print(f"\n{Fore.LIGHTCYAN_EX}[+] Protocol Distribution:{Style.RESET_ALL}")
        print(f"  {'Protocol':<12} {'Packets':<10} {'% Packets':<12} {'Bytes':<12} {'% Volume'}")
        print(f"  {'-'*56}")
        for proto, count in self.protocols.most_common(8):
            pkt_pct = (count / self.total_packets) * 100 if self.total_packets else 0
            p_bytes = self.protocols_bytes.get(proto, 0)
            byte_pct = (p_bytes / self.total_bytes) * 100 if self.total_bytes else 0
            print(f"  {proto:<12} {count:<10} {pkt_pct:>6.1f}%     {p_bytes:<12} {byte_pct:>6.1f}%")

        # Top Source IPs
        if self.src_ips:
            print(f"\n{Fore.LIGHTGREEN_EX}[+] Top Source Talkers (IPs):{Style.RESET_ALL}")
            for ip, count in self.src_ips.most_common(5):
                pct = (count / self.total_packets) * 100
                print(f"  - {ip:<28} : {count:>5} pkts ({pct:4.1f}%)")

        # Top Destination IPs
        if self.dst_ips:
            print(f"\n{Fore.LIGHTMAGENTA_EX}[+] Top Destination Endpoints:{Style.RESET_ALL}")
            for ip, count in self.dst_ips.most_common(5):
                pct = (count / self.total_packets) * 100
                print(f"  - {ip:<28} : {count:>5} pkts ({pct:4.1f}%)")

        # Top Ports
        if self.ports:
            print(f"\n{Fore.LIGHTYELLOW_EX}[+] Top Active Ports:{Style.RESET_ALL}")
            for port, count in self.ports.most_common(5):
                service = self._lookup_service(port)
                print(f"  - Port {port:<6} ({service:<10}) : {count:>5} hits")

        # TCP Flags Distribution
        if self.tcp_flags:
            print(f"\n{Fore.LIGHTWHITE_EX}[+] TCP Flag Distribution:{Style.RESET_ALL}")
            flags_str = " | ".join(f"{flag}: {count}" for flag, count in self.tcp_flags.most_common())
            print(f"  {flags_str}")

        print(f"\n{Fore.GREEN}{'='*64}{Style.RESET_ALL}\n")

    @staticmethod
    def _lookup_service(port: int) -> str:
        """Map common port numbers to service names."""
        common = {
            20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet",
            25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
            80: "HTTP", 110: "POP3", 123: "NTP", 143: "IMAP",
            443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
            3389: "RDP", 5353: "mDNS", 8080: "HTTP-Alt"
        }
        return common.get(port, "Unknown")
