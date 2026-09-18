# Network Traffic Packet Sniffer & Protocol Analyzer

An educational, modular network packet sniffer and protocol analyzer built in Python. Designed for network engineering students, developers, and security analysts to inspect network traffic, dissect protocol headers (L2 through L7), examine payload content, and understand the fundamentals of data flow across the TCP/IP stack.

---

## Features

- **Dual Capture Engines**:
  - **Scapy Engine**: High-level capture powered by Npcap/libpcap with BPF (Berkeley Packet Filter) syntax, PCAP export/import, and layer dissection.
  - **Raw Socket Engine**: Educational low-level sniffer using standard library `socket` and `struct.unpack` to dissect binary header bytes directly from raw network buffers.
- **Layer-by-Layer Protocol Dissection**:
  - **Layer 2 (Data Link)**: Ethernet frames, MAC addresses, EtherType, ARP requests/replies.
  - **Layer 3 (Network)**: IPv4 & IPv6 headers, TTL, fragmentation flags (DF, MF), identification, checksums.
  - **Layer 4 (Transport)**: TCP flags (SYN, ACK, FIN, RST, PSH, URG), sequence and acknowledgment numbers, window sizes, UDP datagrams, ICMP diagnostics.
  - **Layer 7 (Application)**: DNS queries/responses, HTTP methods/headers, and TLS Server Name Indication (SNI) detection.
- **Hexdump & Payload Inspection**:
  - Side-by-side 16-byte Hex + printable ASCII preview (identical to `tcpdump -X` and Wireshark).
- **Traffic Statistics & Analytics**:
  - Real-time packet throughput, volume, protocol distributions, top talkers (IP addresses and conversation pairs), and port frequency.
- **Interactive Protocol Guide**:
  - Built-in ASCII visual diagrams explaining the OSI 7-layer vs TCP/IP 4-layer models, RFC bit layouts, and the TCP 3-Way Handshake.

---

## Project Structure

```
sniffer/
├── sniffer.py                  # Main CLI entrypoint
├── requirements.txt            # Dependencies (scapy, colorama)
├── README.md                   # Documentation and study guide
├── core/
│   ├── __init__.py
│   ├── analyzer.py             # Layer-by-layer packet dissector & protocol classifiers
│   ├── scapy_engine.py         # Scapy live capture, interface selection, PCAP save/replay
│   └── raw_socket_engine.py    # Low-level RFC struct unpacking with socket.SOCK_RAW
├── utils/
│   ├── __init__.py
│   ├── display.py              # Color-coded badges, tables, and Wireshark-style hexdump
│   └── stats.py                # Traffic metrics, protocol distribution, top talkers
└── education/
    ├── __init__.py
    └── protocol_guide.py       # Educational RFC header diagrams & flow walkthroughs
```

---

## Quickstart

### 1. Requirements

- Python 3.9+
- Windows: **Npcap** installed (Npcap is already running on this machine).
- Install dependencies:
  ```powershell
  pip install -r requirements.txt
  ```

### 2. List Available Interfaces

View all physical, wireless, and virtual adapters with their IP and MAC addresses:
```powershell
python sniffer.py interfaces
```

### 3. Capture Live Packets

Capture 20 packets on the default active network interface (auto-selects active Wi-Fi or Ethernet):
```powershell
python sniffer.py sniff --count 20
```

### 4. Filter Specific Traffic (BPF Syntax)

Capture only Web (HTTP/HTTPS) or DNS traffic:
```powershell
# Web traffic only
python sniffer.py sniff --filter "tcp port 80 or tcp port 443" --count 15

# DNS queries and responses
python sniffer.py sniff --filter "udp port 53" --count 10

# ICMP (Ping) packets only
python sniffer.py sniff --filter "icmp" --count 10
```

### 5. Detailed Packet Inspection (Hexdump + Headers)

View complete header fields and payload bytes:
```powershell
python sniffer.py sniff --verbose --count 3
```

### 6. Save and Replay PCAP Files

Save a capture session for offline analysis or Wireshark inspection:
```powershell
# Capture and save to file
python sniffer.py sniff --count 50 --output my_capture.pcap

# Read and analyze the saved PCAP file
python sniffer.py read my_capture.pcap
```

### 7. Interactive Learning Guide

Study network protocol architectures and RFC specifications directly in your terminal:
```powershell
# View all tutorials
python sniffer.py learn all

# View TCP 3-Way Handshake flow
python sniffer.py learn handshake

# View IPv4 Header bit layout
python sniffer.py learn ip

# View TCP Header bit layout and control flags
python sniffer.py learn tcp
```

### 8. Educational Raw Socket Sniffer

Demonstrates how network protocols are unpacked from binary memory buffers byte-by-byte using `struct`:
```powershell
# Run raw socket capture (requires Administrator terminal)
python sniffer.py raw --count 10 --verbose
```

---

## Educational Concepts Covered

### 1. Encapsulation & Protocol Data Units (PDUs)

As data travels down the network stack, each layer prepends its own header:
1. **Application Layer**: Generates the application data (e.g., HTTP `GET / HTTP/1.1`).
2. **Transport Layer**: Adds a TCP/UDP header containing source and destination port numbers. PDU: **Segment** (TCP) or **Datagram** (UDP).
3. **Network Layer**: Adds an IP header containing source and destination IP addresses, TTL, and protocol ID. PDU: **Packet**.
4. **Data Link Layer**: Adds an Ethernet header containing physical MAC addresses and EtherType. PDU: **Frame**.
5. **Physical Layer**: Converts the frame into electronic/optical/radio signals (Bits).

### 2. TCP 3-Way Handshake

```
CLIENT                                          SERVER
  │                                               │
  │ ─── 1. SYN [Seq=x] ─────────────────────────► │  (Initiate connection)
  │                                               │
  │ ◄── 2. SYN+ACK [Seq=y, Ack=x+1] ──────────── │  (Acknowledge & synchronize)
  │                                               │
  │ ─── 3. ACK [Seq=x+1, Ack=y+1] ─────────────► │  (Connection ESTABLISHED)
```

### 3. TCP vs UDP

| Feature | TCP | UDP |
| :--- | :--- | :--- |
| **Connection Model** | Connection-Oriented (Handshake) | Connectionless |
| **Reliability** | Guaranteed (ACKs, Retransmissions) | Best-effort (No retransmissions) |
| **Ordering** | In-order sequence numbers | Out-of-order possible |
| **Header Overhead**| 20 - 60 bytes | 8 bytes |
| **Use Cases** | Web (HTTP), SSH, Email, File Transfer | DNS, Video Streaming, VoIP, Online Gaming |

---

## Ethical & Security Notice

Packet sniffing captures raw network frames transmitted across a network interface.
- **Authorized Use Only**: This software is built for learning, diagnostics, and monitoring on networks and devices you own or have explicit authorization to inspect.
- **Loopback & Local Traffic**: You can safely capture traffic on `127.0.0.1` (Software Loopback) or your personal Wi-Fi interface.
