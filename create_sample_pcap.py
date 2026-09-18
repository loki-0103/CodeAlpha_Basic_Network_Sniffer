"""Generates a realistic sample PCAP file for demonstration and offline analysis testing."""

from scapy.all import wrpcap, Ether, IP, TCP, UDP, ICMP, DNS, DNSQR, DNSRR, Raw
import time

def generate_sample_pcap(filepath="sample_traffic.pcap"):
    now = time.time()
    packets = [
        # 1. DNS Query for google.com
        Ether(src="50:76:af:35:c7:a8", dst="e0:cb:bc:12:34:56") /
        IP(src="10.99.181.25", dst="8.8.8.8", ttl=64) /
        UDP(sport=51234, dport=53) /
        DNS(id=0x1a2b, rd=1, qd=DNSQR(qname="google.com")),

        # 2. DNS Response
        Ether(src="e0:cb:bc:12:34:56", dst="50:76:af:35:c7:a8") /
        IP(src="8.8.8.8", dst="10.99.181.25", ttl=118) /
        UDP(sport=53, dport=51234) /
        DNS(id=0x1a2b, qr=1, ancount=1, qd=DNSQR(qname="google.com"), an=DNSRR(rrname="google.com", rdata="142.250.190.46")),

        # 3. TCP 3-Way Handshake: SYN
        Ether(src="50:76:af:35:c7:a8", dst="e0:cb:bc:12:34:56") /
        IP(src="10.99.181.25", dst="142.250.190.46", ttl=64, id=0x4321) /
        TCP(sport=49876, dport=80, flags="S", seq=1000000, window=64240),

        # 4. TCP 3-Way Handshake: SYN-ACK
        Ether(src="e0:cb:bc:12:34:56", dst="50:76:af:35:c7:a8") /
        IP(src="142.250.190.46", dst="10.99.181.25", ttl=57, id=0x9876) /
        TCP(sport=80, dport=49876, flags="SA", seq=5000000, ack=1000001, window=65535),

        # 5. TCP 3-Way Handshake: ACK
        Ether(src="50:76:af:35:c7:a8", dst="e0:cb:bc:12:34:56") /
        IP(src="10.99.181.25", dst="142.250.190.46", ttl=64) /
        TCP(sport=49876, dport=80, flags="A", seq=1000001, ack=5000001, window=64240),

        # 6. HTTP Request
        Ether(src="50:76:af:35:c7:a8", dst="e0:cb:bc:12:34:56") /
        IP(src="10.99.181.25", dst="142.250.190.46", ttl=64) /
        TCP(sport=49876, dport=80, flags="PA", seq=1000001, ack=5000001, window=64240) /
        Raw(load=b"GET /index.html HTTP/1.1\r\nHost: google.com\r\nUser-Agent: NetworkAnalyzer/1.0\r\nAccept: */*\r\n\r\n"),

        # 7. ICMP Ping Echo Request
        Ether(src="50:76:af:35:c7:a8", dst="e0:cb:bc:12:34:56") /
        IP(src="10.99.181.25", dst="1.1.1.1", ttl=128) /
        ICMP(type=8, code=0, id=1, seq=1) /
        Raw(load=b"abcdefghijklmnopqrstuvwabcdefghi"),

        # 8. ICMP Ping Echo Reply
        Ether(src="e0:cb:bc:12:34:56", dst="50:76:af:35:c7:a8") /
        IP(src="1.1.1.1", dst="10.99.181.25", ttl=56) /
        ICMP(type=0, code=0, id=1, seq=1) /
        Raw(load=b"abcdefghijklmnopqrstuvwabcdefghi"),
    ]

    for i, pkt in enumerate(packets):
        pkt.time = now + (i * 0.05)

    wrpcap(filepath, packets)
    print(f"Generated {len(packets)} sample packets in '{filepath}'")

if __name__ == "__main__":
    generate_sample_pcap()
