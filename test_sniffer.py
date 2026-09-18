"""Unit tests for PacketAnalyzer, Display, TrafficStats, and ProtocolGuide."""

import unittest
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.packet import Raw

from core.analyzer import PacketAnalyzer
from utils.stats import TrafficStats
from utils.display import hexdump, color_protocol
from education.protocol_guide import show_guide
from core.raw_socket_engine import RawSocketSniffer


class TestPacketSniffer(unittest.TestCase):
    """Test suite covering packet dissection, statistics, and formatting."""

    def test_hexdump(self):
        """Verify hex dump output formatting."""
        payload = b"Hello, Network World! 12345"
        dump = hexdump(payload, length=16)
        self.assertIn("Hello, Network", dump)
        self.assertIn("0x0000", dump)

    def test_color_protocol(self):
        """Verify color protocol tags."""
        badge = color_protocol("TCP")
        self.assertIn("TCP", badge)

    def test_dissect_tcp_packet(self):
        """Construct synthetic TCP packet and verify full dissection."""
        pkt = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / \
              IP(src="192.168.1.50", dst="93.184.216.34") / \
              TCP(sport=54321, dport=80, flags="S", seq=1000) / \
              Raw(load=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")

        details = PacketAnalyzer.dissect(pkt, index=1)
        self.assertEqual(details["protocol"], "HTTP")
        self.assertEqual(details["src"], "192.168.1.50")
        self.assertEqual(details["dst"], "93.184.216.34")
        self.assertEqual(details["sport"], 54321)
        self.assertEqual(details["dport"], 80)
        self.assertIn("SYN", details["tcp_flags"])
        self.assertIn("GET / HTTP/1.1", details["info"])
        self.assertIn(b"Host: example.com", details["payload_bytes"])

    def test_dissect_udp_packet(self):
        """Construct synthetic UDP packet and verify dissection."""
        pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=5000, dport=6000) / Raw(load=b"TEST_PAYLOAD")
        details = PacketAnalyzer.dissect(pkt, index=2)
        self.assertEqual(details["protocol"], "UDP")
        self.assertEqual(details["sport"], 5000)
        self.assertEqual(details["dport"], 6000)
        self.assertEqual(details["payload_bytes"], b"TEST_PAYLOAD")

    def test_dissect_icmp_packet(self):
        """Construct synthetic ICMP Echo Request."""
        pkt = Ether() / IP(src="192.168.1.1", dst="8.8.8.8") / ICMP(type=8, code=0)
        details = PacketAnalyzer.dissect(pkt, index=3)
        self.assertEqual(details["protocol"], "ICMP")
        self.assertIn("Echo Request", details["info"])

    def test_dissect_dns_query(self):
        """Construct synthetic DNS query packet."""
        pkt = Ether() / IP(src="192.168.1.10", dst="8.8.8.8") / UDP(sport=53000, dport=53) / \
              DNS(rd=1, qd=DNSQR(qname="google.com"))
        details = PacketAnalyzer.dissect(pkt, index=4)
        self.assertEqual(details["protocol"], "DNS")
        self.assertIn("google.com", details["info"])

    def test_traffic_stats(self):
        """Verify statistics aggregation and reporting."""
        stats = TrafficStats()
        stats.update(proto="TCP", src="1.1.1.1", dst="2.2.2.2", length=100, sport=80, dport=443, flags=["SYN"])
        stats.update(proto="UDP", src="1.1.1.1", dst="8.8.8.8", length=60, sport=53, dport=53)
        
        self.assertEqual(stats.total_packets, 2)
        self.assertEqual(stats.total_bytes, 160)
        self.assertEqual(stats.protocols["TCP"], 1)
        self.assertEqual(stats.protocols["UDP"], 1)
        self.assertEqual(stats.tcp_flags["SYN"], 1)

    def test_raw_socket_struct_unpack(self):
        """Verify low-level struct unpacking matches byte specifications."""
        # Synthesize 20-byte IPv4 packet header:
        # Version 4, IHL 5 (0x45), TOS 0, TotalLen 40, ID 1234, Flags 0x4000 (DF), TTL 64, Proto 6 (TCP), Checksum 0, 192.168.1.1 -> 192.168.1.2
        import socket, struct
        ip_hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 1234, 0x4000, 64, 6, 0,
                             socket.inet_aton("192.168.1.1"), socket.inet_aton("192.168.1.2"))
        # Synthesize 20-byte TCP header:
        # Sport 12345, Dport 80, Seq 100, Ack 200, Offset 5 (0x50), Flags SYN (0x02), Win 8192, Chksum 0, Urg 0
        tcp_hdr = struct.pack("!HHIIHHHH", 12345, 80, 100, 200, 0x5002, 8192, 0, 0)

        unpacked_ip = RawSocketSniffer.unpack_ipv4(ip_hdr + tcp_hdr)
        self.assertEqual(unpacked_ip["version"], 4)
        self.assertEqual(unpacked_ip["ihl"], 20)
        self.assertEqual(unpacked_ip["src_ip"], "192.168.1.1")
        self.assertEqual(unpacked_ip["dst_ip"], "192.168.1.2")
        self.assertEqual(unpacked_ip["proto"], 6)
        self.assertTrue(unpacked_ip["df"])

        unpacked_tcp = RawSocketSniffer.unpack_tcp(unpacked_ip["payload"])
        self.assertEqual(unpacked_tcp["sport"], 12345)
        self.assertEqual(unpacked_tcp["dport"], 80)
        self.assertEqual(unpacked_tcp["seq"], 100)
        self.assertEqual(unpacked_tcp["ack"], 200)
        self.assertIn("SYN", unpacked_tcp["flags"])


if __name__ == "__main__":
    unittest.main()
