"""Low-level educational packet sniffer using Python standard library 'socket' and 'struct'.

Demonstrates how network protocols are unpacked from binary memory buffers byte-by-byte
according to IETF RFC specifications (RFC 791, RFC 792, RFC 793, RFC 768).
"""

import socket
import struct
import sys
import time
from typing import Optional, Tuple
from colorama import Fore, Style

from utils.display import color_protocol, hexdump, format_timestamp
from utils.stats import TrafficStats
from utils.storage import save_capture


class RawSocketSniffer:
    """Captures and unpacks packets using pure Python raw sockets without third-party drivers."""

    def __init__(self, host_ip: str = "0.0.0.0"):
        self.host_ip = host_ip
        self.stats = TrafficStats()
        self.parsed_records = []

    @staticmethod
    def get_local_ip() -> str:
        """Find the local routable IP address for socket binding."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    @staticmethod
    def unpack_ipv4(data: bytes) -> dict:
        """
        Unpack IPv4 Header (RFC 791).
        
        Byte Layout (First 20 bytes):
          0                   1                   2                   3
          0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |Version|  IHL  |Type of Service|          Total Length         |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |         Identification        |Flags|      Fragment Offset    |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |  Time to Live |    Protocol   |         Header Checksum       |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |                       Source Address                          |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |                    Destination Address                        |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        """
        # Format string '!BBHHHBBH4s4s':
        # ! = Network byte order (Big-Endian)
        # B = unsigned char (1 byte)
        # H = unsigned short (2 bytes)
        # 4s = 4-byte string
        version_ihl, tos, total_len, ident, flags_frag, ttl, proto, chksum, src, dst = struct.unpack(
            "!BBHHHBBH4s4s", data[:20]
        )

        version = version_ihl >> 4
        ihl = (version_ihl & 0x0F) * 4  # Header length in bytes (32-bit words * 4)

        df_flag = bool(flags_frag & 0x4000)
        mf_flag = bool(flags_frag & 0x2000)
        frag_offset = flags_frag & 0x1FFF

        src_ip = socket.inet_ntoa(src)
        dst_ip = socket.inet_ntoa(dst)

        payload = data[ihl:]

        return {
            "version": version,
            "ihl": ihl,
            "tos": tos,
            "total_len": total_len,
            "ident": ident,
            "df": df_flag,
            "mf": mf_flag,
            "frag_offset": frag_offset,
            "ttl": ttl,
            "proto": proto,
            "checksum": hex(chksum),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "payload": payload,
        }

    @staticmethod
    def unpack_icmp(data: bytes) -> dict:
        """Unpack ICMP Header (RFC 792) - 4 bytes base."""
        icmp_type, code, chksum = struct.unpack("!BBH", data[:4])
        return {
            "type": icmp_type,
            "code": code,
            "checksum": hex(chksum),
            "payload": data[4:],
        }

    @staticmethod
    def unpack_tcp(data: bytes) -> dict:
        """
        Unpack TCP Header (RFC 793) - 20 bytes base.
        
        Byte Layout:
          0                   1                   2                   3
          0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |          Source Port          |       Destination Port        |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |                        Sequence Number                        |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |                    Acknowledgment Number                      |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |  Data |           |U|A|P|R|S|F|                               |
         | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
         |       |           |G|K|H|T|N|N|                               |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |           Checksum            |         Urgent Pointer        |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        """
        sport, dport, seq, ack, offset_reserved_flags, window, chksum, urg = struct.unpack(
            "!HHIIHHHH", data[:20]
        )
        
        data_offset = (offset_reserved_flags >> 12) * 4  # Header length in bytes
        flags = offset_reserved_flags & 0x01FF

        parsed_flags = []
        if flags & 0x020: parsed_flags.append("URG")
        if flags & 0x010: parsed_flags.append("ACK")
        if flags & 0x008: parsed_flags.append("PSH")
        if flags & 0x004: parsed_flags.append("RST")
        if flags & 0x002: parsed_flags.append("SYN")
        if flags & 0x001: parsed_flags.append("FIN")

        return {
            "sport": sport,
            "dport": dport,
            "seq": seq,
            "ack": ack,
            "data_offset": data_offset,
            "flags": parsed_flags,
            "window": window,
            "checksum": hex(chksum),
            "urgent": urg,
            "payload": data[data_offset:],
        }

    @staticmethod
    def unpack_udp(data: bytes) -> dict:
        """Unpack UDP Header (RFC 768) - 8 bytes."""
        sport, dport, length, chksum = struct.unpack("!HHHH", data[:8])
        return {
            "sport": sport,
            "dport": dport,
            "length": length,
            "checksum": hex(chksum),
            "payload": data[8:],
        }

    def start_sniff(
        self,
        count: int = 0,
        timeout: Optional[int] = None,
        verbose: bool = False,
        save_file: Optional[str] = None,
    ):
        """
        Start raw socket capture.
        
        Note: On Windows, raw sockets require Administrator privileges and binding to an active local IP.
        """
        bind_ip = self.host_ip if self.host_ip != "0.0.0.0" else self.get_local_ip()

        print(f"\n{Fore.CYAN}[*] Starting Raw Socket Engine (Python 'socket' & 'struct'){Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Binding to interface IP: {Fore.GREEN}{bind_ip}{Style.RESET_ALL}")
        if save_file:
            print(f"{Fore.CYAN}[*] Save option enabled: {Fore.YELLOW}{save_file}{Style.RESET_ALL}")
        print(f"{Fore.LIGHTBLACK_EX}[*] Raw sockets require Administrator privileges on Windows.{Style.RESET_ALL}\n")

        sock = None
        self.parsed_records = []
        try:
            # Create raw IP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            sock.bind((bind_ip, 0))
            
            # Windows specific: Enable promiscuous receive all
            if sys.platform == "win32":
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
                
            if timeout:
                sock.settimeout(timeout)

            packet_count = 0
            start_time = time.time()

            while True:
                if count > 0 and packet_count >= count:
                    break
                if timeout and (time.time() - start_time) > timeout:
                    break

                raw_buffer, addr = sock.recvfrom(65535)
                packet_count += 1
                pkt_time = time.time()
                
                # Unpack IPv4 Header
                ip_info = self.unpack_ipv4(raw_buffer)
                proto_id = ip_info["proto"]
                payload = ip_info["payload"]
                
                proto_name = "IP"
                info_str = ""
                sport, dport = None, None
                flags = []

                if proto_id == 1:  # ICMP
                    proto_name = "ICMP"
                    icmp_info = self.unpack_icmp(payload)
                    info_str = f"ICMP Type={icmp_info['type']} Code={icmp_info['code']} Chksum={icmp_info['checksum']}"
                    trans_payload = icmp_info["payload"]
                elif proto_id == 6:  # TCP
                    proto_name = "TCP"
                    tcp_info = self.unpack_tcp(payload)
                    sport, dport = tcp_info["sport"], tcp_info["dport"]
                    flags = tcp_info["flags"]
                    flags_str = f"[{','.join(flags)}]"
                    info_str = f"Port {sport} -> {dport} {flags_str} Seq={tcp_info['seq']} Ack={tcp_info['ack']} Win={tcp_info['window']}"
                    trans_payload = tcp_info["payload"]
                elif proto_id == 17:  # UDP
                    proto_name = "UDP"
                    udp_info = self.unpack_udp(payload)
                    sport, dport = udp_info["sport"], udp_info["dport"]
                    info_str = f"Port {sport} -> {dport} Len={udp_info['length']}"
                    trans_payload = udp_info["payload"]
                else:
                    proto_name = f"PROTO-{proto_id}"
                    info_str = f"Protocol ID {proto_id}"
                    trans_payload = payload

                record = {
                    "index": packet_count,
                    "timestamp": pkt_time,
                    "protocol": proto_name,
                    "src": ip_info["src_ip"],
                    "dst": ip_info["dst_ip"],
                    "sport": sport,
                    "dport": dport,
                    "length": len(raw_buffer),
                    "tcp_flags": flags,
                    "info": info_str,
                    "payload_bytes": trans_payload,
                }
                self.parsed_records.append(record)

                # Update stats
                self.stats.update(
                    proto=proto_name,
                    src=ip_info["src_ip"],
                    dst=ip_info["dst_ip"],
                    length=len(raw_buffer),
                    sport=sport,
                    dport=dport,
                    flags=flags,
                )

                # Display
                if verbose:
                    print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
                    print(f"RAW PACKET #{packet_count} - Protocol: {proto_name}")
                    print(f"  Source IP:      {ip_info['src_ip']}")
                    print(f"  Destination IP: {ip_info['dst_ip']}")
                    print(f"  TTL:            {ip_info['ttl']}")
                    print(f"  Total Length:   {ip_info['total_len']} bytes")
                    print(f"  Header Details: {info_str}")
                    if trans_payload:
                        print(f"  Payload ({len(trans_payload)} bytes):")
                        print(hexdump(trans_payload))
                    print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")
                else:
                    time_s = format_timestamp(pkt_time)
                    badge = color_protocol(proto_name)
                    idx_s = f"{Fore.LIGHTBLACK_EX}#{packet_count:<5}{Style.RESET_ALL}"
                    src_s = f"{ip_info['src_ip']}:{sport}" if sport else ip_info['src_ip']
                    dst_s = f"{ip_info['dst_ip']}:{dport}" if dport else ip_info['dst_ip']
                    print(f"{idx_s} {time_s} {badge} {src_s:<21} -> {dst_s:<21} {len(raw_buffer):>5}B | {info_str}")

        except socket.timeout:
            print(f"\n{Fore.YELLOW}[*] Socket capture timed out.{Style.RESET_ALL}")
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[!] Raw capture interrupted by user.{Style.RESET_ALL}")
        except PermissionError:
            print(f"\n{Fore.RED}[x] Permission Denied: Raw sockets on Windows require Administrator privileges.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[!] Please run your terminal/IDE as Administrator to use SOCK_RAW.{Style.RESET_ALL}")
        except OSError as e:
            if "10013" in str(e):
                print(f"\n{Fore.RED}[x] WinError 10013: An attempt was made to access a socket in a way forbidden by its access permissions.{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}[!] You must run the prompt as Administrator to use raw sockets on Windows.{Style.RESET_ALL}")
            else:
                print(f"\n{Fore.RED}[x] Socket error: {e}{Style.RESET_ALL}")
        finally:
            if sock and sys.platform == "win32":
                try:
                    sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                except Exception:
                    pass
            if sock:
                sock.close()

            if save_file and self.parsed_records:
                save_capture(
                    filepath=save_file,
                    parsed_records=self.parsed_records,
                    stats=self.stats,
                )

        return self.stats
