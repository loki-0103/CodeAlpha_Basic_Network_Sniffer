"""Packet analyzer and layer-by-layer protocol dissector."""

from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, ICMPv6EchoReply
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.packet import Raw

# ICMP Type mapping (RFC 792)
ICMP_TYPES = {
    0: "Echo Reply (Ping reply)",
    3: "Destination Unreachable",
    4: "Source Quench",
    5: "Redirect Message",
    8: "Echo Request (Ping request)",
    11: "Time Exceeded (TTL expired in transit)",
    12: "Parameter Problem",
    13: "Timestamp Request",
    14: "Timestamp Reply",
}

# TCP Flags bitmask mapping
TCP_FLAG_NAMES = {
    "F": "FIN",
    "S": "SYN",
    "R": "RST",
    "P": "PSH",
    "A": "ACK",
    "U": "URG",
    "E": "ECE",
    "C": "CWR",
}

# Common Service Ports
PORT_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 80: "HTTP",
    110: "POP3", 123: "NTP", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 993: "IMAPS", 995: "POP3S", 3389: "RDP",
    5353: "mDNS", 8080: "HTTP-Alt", 8443: "HTTPS-Alt"
}


class PacketAnalyzer:
    """Dissects packets across L2, L3, L4, and L7."""

    @staticmethod
    def dissect(packet, index: int = 1) -> dict:
        """
        Dissect a Scapy packet into a structured dictionary of layers.
        
        Args:
            packet: Scapy Packet instance.
            index: Sequential packet number.
            
        Returns:
            dict containing parsed layers, summary info, and raw payload.
        """
        result = {
            "index": index,
            "timestamp": float(getattr(packet, "time", 0)),
            "length": len(packet),
            "protocol": "OTHER",
            "src": "Unknown",
            "dst": "Unknown",
            "sport": None,
            "dport": None,
            "tcp_flags": [],
            "info": "",
            "payload_bytes": b"",
        }

        # -------------------------------------------------------------
        # Layer 2: Data Link (Ethernet / ARP)
        # -------------------------------------------------------------
        if packet.haslayer(Ether):
            eth = packet[Ether]
            result["ethernet"] = {
                "src_mac": eth.src,
                "dst_mac": eth.dst,
                "type": hex(eth.type),
            }

        if packet.haslayer(ARP):
            arp = packet[ARP]
            op_str = "Who has" if arp.op == 1 else "Is at" if arp.op == 2 else f"Op={arp.op}"
            result["protocol"] = "ARP"
            result["src"] = arp.psrc
            result["dst"] = arp.pdst
            result["info"] = f"ARP: {op_str} {arp.pdst}? Tell {arp.psrc}"
            result["network"] = {
                "type": "ARP",
                "operation": f"{op_str} ({arp.op})",
                "sender_mac": arp.hwsrc,
                "sender_ip": arp.psrc,
                "target_mac": arp.hwdst,
                "target_ip": arp.pdst,
            }
            return result

        # -------------------------------------------------------------
        # Layer 3: Network (IPv4 / IPv6)
        # -------------------------------------------------------------
        if packet.haslayer(IP):
            ip = packet[IP]
            result["src"] = ip.src
            result["dst"] = ip.dst
            result["protocol"] = "IPv4"
            flags = []
            if getattr(ip.flags, "DF", False): flags.append("DF")
            if getattr(ip.flags, "MF", False): flags.append("MF")
            
            ihl = getattr(ip, "ihl", 5) or 5
            total_len = getattr(ip, "len", len(ip)) or len(ip)
            ident = getattr(ip, "id", 0) or 0
            chksum = getattr(ip, "chksum", 0) or 0

            result["network"] = {
                "type": "IPv4",
                "source_ip": ip.src,
                "dest_ip": ip.dst,
                "version": getattr(ip, "version", 4) or 4,
                "header_length": f"{ihl * 4} bytes",
                "total_length": f"{total_len} bytes",
                "identification": hex(ident),
                "ttl": getattr(ip, "ttl", 64),
                "protocol_id": getattr(ip, "proto", 0),
                "flags": ",".join(flags) if flags else "None",
                "checksum": hex(chksum),
            }
        elif packet.haslayer(IPv6):
            ip6 = packet[IPv6]
            result["src"] = ip6.src
            result["dst"] = ip6.dst
            result["protocol"] = "IPv6"
            result["network"] = {
                "type": "IPv6",
                "source_ip": ip6.src,
                "dest_ip": ip6.dst,
                "version": getattr(ip6, "version", 6),
                "traffic_class": getattr(ip6, "tc", 0),
                "flow_label": getattr(ip6, "fl", 0),
                "payload_length": f"{getattr(ip6, 'plen', 0)} bytes",
                "next_header": getattr(ip6, "nh", 0),
                "hop_limit": getattr(ip6, "hlim", 64),
            }

        # -------------------------------------------------------------
        # Layer 4: Transport (TCP / UDP / ICMP)
        # -------------------------------------------------------------
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            result["protocol"] = "TCP"
            result["sport"] = tcp.sport
            result["dport"] = tcp.dport
            
            # Parse flags
            flag_str = str(tcp.flags) if tcp.flags is not None else ""
            parsed_flags = [TCP_FLAG_NAMES.get(f, f) for f in flag_str]
            result["tcp_flags"] = parsed_flags
            flags_repr = f"[{','.join(parsed_flags)}]"
            
            # Service identification
            svc = PORT_SERVICES.get(tcp.dport) or PORT_SERVICES.get(tcp.sport)
            svc_str = f" ({svc})" if svc else ""
            
            dataofs = getattr(tcp, "dataofs", 5) or 5
            chksum = getattr(tcp, "chksum", 0) or 0
            flags_int = int(tcp.flags) if tcp.flags is not None else 0

            result["info"] = f"Port {tcp.sport} -> {tcp.dport}{svc_str} {flags_repr} Seq={getattr(tcp, 'seq', 0)} Ack={getattr(tcp, 'ack', 0)} Win={getattr(tcp, 'window', 0)}"
            result["transport"] = {
                "protocol": "TCP",
                "source_port": tcp.sport,
                "dest_port": tcp.dport,
                "sequence_number": getattr(tcp, "seq", 0),
                "ack_number": getattr(tcp, "ack", 0),
                "data_offset": f"{dataofs * 4} bytes",
                "flags": f"{flags_repr} (0x{flags_int:02x})",
                "window_size": getattr(tcp, "window", 0),
                "checksum": hex(chksum),
                "urgent_pointer": getattr(tcp, "urgptr", 0),
            }

        elif packet.haslayer(UDP):
            udp = packet[UDP]
            result["protocol"] = "UDP"
            result["sport"] = udp.sport
            result["dport"] = udp.dport
            svc = PORT_SERVICES.get(udp.dport) or PORT_SERVICES.get(udp.sport)
            svc_str = f" ({svc})" if svc else ""
            
            udp_len = getattr(udp, "len", len(udp)) or len(udp)
            chksum = getattr(udp, "chksum", 0) or 0

            result["info"] = f"Port {udp.sport} -> {udp.dport}{svc_str} Len={udp_len}"
            result["transport"] = {
                "protocol": "UDP",
                "source_port": udp.sport,
                "dest_port": udp.dport,
                "length": f"{udp_len} bytes",
                "checksum": hex(chksum),
            }

        elif packet.haslayer(ICMP):
            icmp = packet[ICMP]
            result["protocol"] = "ICMP"
            type_desc = ICMP_TYPES.get(icmp.type, f"Type {icmp.type}")
            chksum = getattr(icmp, "chksum", 0) or 0
            result["info"] = f"ICMP: {type_desc} (Code {icmp.code})"
            result["transport"] = {
                "protocol": "ICMP",
                "type": f"{icmp.type} ({type_desc})",
                "code": icmp.code,
                "checksum": hex(chksum),
                "id": getattr(icmp, "id", "N/A"),
                "sequence": getattr(icmp, "seq", "N/A"),
            }

        # -------------------------------------------------------------
        # Layer 7: Application Layer Inspection (DNS, HTTP, TLS)
        # -------------------------------------------------------------
        if packet.haslayer(DNS):
            dns = packet[DNS]
            result["protocol"] = "DNS"
            if dns.qr == 0:  # Query
                qname = "Unknown"
                if dns.qd:
                    try:
                        qd_layer = dns.qd[0] if isinstance(dns.qd, list) or hasattr(dns.qd, "__getitem__") else dns.qd
                        qname = qd_layer.qname.decode(errors="ignore") if hasattr(qd_layer, "qname") else str(qd_layer)
                    except Exception:
                        qname = str(dns.qd)
                result["info"] = f"DNS Query: {qname}"
                result["application"] = {
                    "name": "DNS",
                    "transaction_id": hex(dns.id),
                    "type": "Standard Query",
                    "query_domain": qname,
                }
            else:  # Response
                answers = []
                if dns.an:
                    try:
                        an_list = dns.an if isinstance(dns.an, list) or hasattr(dns.an, "__iter__") else [dns.an]
                        for rr in an_list:
                            if hasattr(rr, "rdata"):
                                answers.append(str(rr.rdata))
                    except Exception:
                        pass
                ans_str = ", ".join(answers[:3]) if answers else "No Answers"
                result["info"] = f"DNS Response: {ans_str}"
                result["application"] = {
                    "name": "DNS",
                    "transaction_id": hex(dns.id),
                    "type": "Standard Response",
                    "answers": ans_str,
                }

        # Extract Raw Payload
        if packet.haslayer(Raw):
            raw_bytes = bytes(packet[Raw].load)
            result["payload_bytes"] = raw_bytes

            # Check for HTTP text
            if raw_bytes.startswith((b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"HTTP/1.0", b"HTTP/1.1")):
                try:
                    first_line = raw_bytes.split(b"\r\n")[0].decode("ascii", errors="ignore")
                    result["protocol"] = "HTTP"
                    result["info"] = f"HTTP: {first_line}"
                    result["application"] = {
                        "name": "HTTP",
                        "first_line": first_line,
                    }
                except Exception:
                    pass
            # Check for TLS Handshake (0x16 0x03 0x01/02/03)
            elif len(raw_bytes) > 5 and raw_bytes[0] == 0x16 and raw_bytes[1] == 0x03:
                result["protocol"] = "TLS"
                sni = PacketAnalyzer._extract_tls_sni(raw_bytes)
                if sni:
                    result["info"] = f"TLS Client Hello (SNI: {sni})"
                    result["application"] = {
                        "name": "TLS/HTTPS",
                        "handshake_type": "Client Hello",
                        "sni_server_name": sni,
                    }
                else:
                    result["info"] = "TLS Handshake Record"

        # If info still empty, create default
        if not result["info"]:
            result["info"] = f"Length {result['length']} bytes"

        return result

    @staticmethod
    def _extract_tls_sni(payload: bytes) -> str:
        """Attempt to extract the Server Name Indication (SNI) from a TLS Client Hello packet."""
        try:
            # Check if Client Hello (handshake type 1)
            if len(payload) > 43 and payload[0] == 0x16 and payload[5] == 0x01:
                # Session ID length offset is 43
                pos = 43
                sess_id_len = payload[pos]
                pos += 1 + sess_id_len
                # Cipher suites length (2 bytes)
                cipher_len = int.from_bytes(payload[pos:pos+2], "big")
                pos += 2 + cipher_len
                # Compression methods length (1 byte)
                comp_len = payload[pos]
                pos += 1 + comp_len
                # Extensions length (2 bytes)
                ext_total_len = int.from_bytes(payload[pos:pos+2], "big")
                pos += 2
                ext_end = pos + ext_total_len

                while pos + 4 <= ext_end and pos + 4 <= len(payload):
                    ext_type = int.from_bytes(payload[pos:pos+2], "big")
                    ext_len = int.from_bytes(payload[pos+2:pos+4], "big")
                    pos += 4
                    if ext_type == 0x00:  # server_name extension
                        # SNI list length (2 bytes) + type (1 byte: 0=host_name) + host length (2 bytes)
                        if pos + 5 <= len(payload):
                            host_len = int.from_bytes(payload[pos+3:pos+5], "big")
                            host = payload[pos+5:pos+5+host_len].decode("utf-8", errors="ignore")
                            return host
                    pos += ext_len
        except Exception:
            pass
        return ""
