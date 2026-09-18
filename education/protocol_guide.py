"""Interactive protocol guide and packet structure visualizer.

Provides educational ASCII diagrams and explanations of the OSI/TCP-IP models,
packet encapsulation, RFC header bit layouts, and connection state flows.
"""

from colorama import Fore, Style


def show_osi_vs_tcpip():
    """Print the OSI 7-Layer vs TCP/IP 4-Layer model and packet encapsulation."""
    print(f"\n{Fore.CYAN}{Style.BRIGHT}==================== NETWORK ARCHITECTURE & ENCAPSULATION ===================={Style.RESET_ALL}")
    print(f"""
  {Fore.YELLOW}OSI 7-LAYER MODEL{Style.RESET_ALL}              {Fore.GREEN}TCP/IP 4-LAYER MODEL{Style.RESET_ALL}     {Fore.MAGENTA}DATA UNIT (PDU){Style.RESET_ALL}
  +------------------------+
  | 7. Application         | --+
  +------------------------+   |
  | 6. Presentation        |   +--> {Fore.GREEN}Application Layer{Style.RESET_ALL}    ---> {Fore.MAGENTA}Data / Message{Style.RESET_ALL} (HTTP, DNS, SSH)
  +------------------------+   |
  | 5. Session             | --+
  +------------------------+---------------------------+---------------------------------
  | 4. Transport           | ----> {Fore.GREEN}Transport Layer{Style.RESET_ALL}      ---> {Fore.MAGENTA}Segment / Datagram{Style.RESET_ALL} (TCP, UDP)
  +------------------------+---------------------------+---------------------------------
  | 3. Network             | ----> {Fore.GREEN}Internet Layer{Style.RESET_ALL}       ---> {Fore.MAGENTA}Packet{Style.RESET_ALL} (IPv4, IPv6, ICMP)
  +------------------------+---------------------------+---------------------------------
  | 2. Data Link           | --+
  +------------------------+   +--> {Fore.GREEN}Network Access Layer{Style.RESET_ALL} ---> {Fore.MAGENTA}Frame{Style.RESET_ALL} (Ethernet, Wi-Fi MAC)
  | 1. Physical            | --+                           {Fore.MAGENTA}Bits{Style.RESET_ALL} (Signals, Radio Waves)
  +------------------------+

{Fore.LIGHTCYAN_EX}[+] Packet Encapsulation Flow (Sender -> Receiver):{Style.RESET_ALL}
  1. Application:    [ User Data / HTTP Request ]
  2. Transport:      [ TCP Header ][ User Data ]
  3. Network:        [ IP Header ][ TCP Header ][ User Data ]
  4. Data Link:      [ Ethernet Header ][ IP Header ][ TCP Header ][ User Data ][ Frame Checksum ]
  5. Physical:       01101001 01101110 01110100 01100101 01110010 01101110 ...
""")


def show_ipv4_header():
    """Print the IPv4 Header bit layout and field explanations."""
    print(f"\n{Fore.CYAN}{Style.BRIGHT}==================== IPv4 HEADER STRUCTURE (RFC 791) ===================={Style.RESET_ALL}")
    print(f"""
   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |Version|  IHL  |Type of Service|          Total Length         |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |         Identification        |Flags|      Fragment Offset    |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |  Time to Live |    Protocol   |         Header Checksum       |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                       Source IP Address                       |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                    Destination IP Address                     |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                    Options (if any) & Padding                 |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

{Fore.YELLOW}Key Fields Explained:{Style.RESET_ALL}
  * {Fore.WHITE}Version (4 bits):{Style.RESET_ALL} Almost always 4 (for IPv4).
  * {Fore.WHITE}IHL (4 bits):{Style.RESET_ALL} Internet Header Length in 32-bit words (Standard is 5 = 20 bytes).
  * {Fore.WHITE}Total Length (16 bits):{Style.RESET_ALL} Entire packet size in bytes (header + payload, max 65,535).
  * {Fore.WHITE}TTL (Time to Live, 8 bits):{Style.RESET_ALL} Decremented by 1 at every router hop. Prevents loops.
  * {Fore.WHITE}Protocol (8 bits):{Style.RESET_ALL} Identifies L4 protocol (1 = ICMP, 6 = TCP, 17 = UDP).
  * {Fore.WHITE}Source / Destination IP (32 bits each):{Style.RESET_ALL} 4-byte addresses (e.g. 192.168.1.1).
""")


def show_tcp_header():
    """Print the TCP Header bit layout, flags, and connection lifecycle."""
    print(f"\n{Fore.CYAN}{Style.BRIGHT}==================== TCP HEADER STRUCTURE (RFC 793) ===================={Style.RESET_ALL}")
    print(f"""
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
  |                    Options (if any) & Padding                 |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

{Fore.YELLOW}The 6 Core TCP Control Flags:{Style.RESET_ALL}
  * {Fore.CYAN}SYN (Synchronize):{Style.RESET_ALL} Initiates a 3-way connection handshake.
  * {Fore.GREEN}ACK (Acknowledgment):{Style.RESET_ALL} Confirms receipt of transmitted packets.
  * {Fore.RED}FIN (Finish):{Style.RESET_ALL} Gracefully requests connection closure.
  * {Fore.LIGHTRED_EX}RST (Reset):{Style.RESET_ALL} Immediately aborts connection (e.g. port closed).
  * {Fore.MAGENTA}PSH (Push):{Style.RESET_ALL} Directs receiver to deliver data to app without buffering.
  * {Fore.YELLOW}URG (Urgent):{Style.RESET_ALL} Designates urgent out-of-band data stream.
""")


def show_tcp_handshake():
    """Print the TCP 3-Way Handshake and 4-Way Teardown flows."""
    print(f"\n{Fore.CYAN}{Style.BRIGHT}==================== TCP CONNECTION LIFECYCLE ===================={Style.RESET_ALL}")
    print(f"""
{Fore.LIGHTGREEN_EX}[1] TCP 3-Way Handshake (Establishing Connection):{Style.RESET_ALL}
     CLIENT                                          SERVER
       |                                               |
       | ---> 1. SYN [Seq=100] ----------------------> |  "I want to connect"
       |                                               |
       | <--- 2. SYN+ACK [Seq=300, Ack=101] ---------- |  "Received, ready to connect"
       |                                               |
       | ---> 3. ACK [Seq=101, Ack=301] -------------> |  "Connection established!"
       |                                               |
    {Fore.LIGHTBLACK_EX}[ ESTABLISHED - Data Transmission Commences ]{Style.RESET_ALL}

{Fore.LIGHTRED_EX}[2] TCP 4-Way Handshake (Graceful Teardown):{Style.RESET_ALL}
     CLIENT                                          SERVER
       |                                               |
       | ---> 1. FIN [Seq=500] ----------------------> |  "I have no more data to send"
       |                                               |
       | <--- 2. ACK [Ack=501] ----------------------- |  "Acknowledged, closing my side"
       |                                               |
       | <--- 3. FIN [Seq=800] ----------------------- |  "I'm also ready to close"
       |                                               |
       | ---> 4. ACK [Ack=801] ----------------------> |  "Connection terminated."
       V                                               V
""")


def show_udp_vs_tcp():
    """Print comparison table between TCP and UDP."""
    print(f"\n{Fore.CYAN}{Style.BRIGHT}==================== TCP vs UDP COMPARISON ===================={Style.RESET_ALL}")
    print(f"""
  {'Feature':<22} {'TCP (Transmission Control Protocol)':<36} {'UDP (User Datagram Protocol)'}
  {'-'*80}
  Connection           Connection-Oriented (3-way handshake)       Connectionless
  Reliability          Guaranteed delivery (ACKs + Retransmit)     Best-effort (No ACKs, data may drop)
  Ordering             Packets delivered in exact sequence         Packets may arrive out-of-order
  Flow Control         Windowing / Congestion control              None
  Header Size          20 - 60 bytes                               8 bytes (Extremely lightweight)
  Speed                Moderate (Reliability overhead)             Maximum / Real-time
  Typical Uses         HTTP/HTTPS, SSH, FTP, Email (SMTP/IMAP)     DNS, VoIP, Live Streaming, Gaming
""")


def show_icmp():
    """Explain ICMP and Ping/Traceroute operations."""
    print(f"\n{Fore.CYAN}{Style.BRIGHT}==================== ICMP & NETWORK DIAGNOSTICS ===================={Style.RESET_ALL}")
    print(f"""
  ICMP (Internet Control Message Protocol - RFC 792) operates at Layer 3 to report network errors
  and diagnostic information. It does not carry application payload.

{Fore.YELLOW}How 'ping' Works:{Style.RESET_ALL}
  1. Your machine sends an {Fore.GREEN}ICMP Echo Request (Type 8, Code 0){Style.RESET_ALL} to the destination.
  2. The destination replies with an {Fore.GREEN}ICMP Echo Reply (Type 0, Code 0){Style.RESET_ALL}.
  3. Round-trip latency (RTT) and packet loss are calculated.

{Fore.YELLOW}How 'traceroute' / 'tracert' Works:{Style.RESET_ALL}
  1. Sends packets with TTL=1. The 1st router drops it and returns {Fore.RED}ICMP Time Exceeded (Type 11){Style.RESET_ALL}.
  2. Sends packets with TTL=2. The 2nd router returns ICMP Time Exceeded.
  3. Repeats incrementally until reaching the target destination.
""")


def show_guide(topic: str = "all"):
    """Interactive guide dispatcher."""
    topic = topic.lower().strip()
    topics = {
        "osi": show_osi_vs_tcpip,
        "ip": show_ipv4_header,
        "ipv4": show_ipv4_header,
        "tcp": show_tcp_header,
        "handshake": show_tcp_handshake,
        "udp": show_udp_vs_tcp,
        "icmp": show_icmp,
    }

    if topic == "all":
        show_osi_vs_tcpip()
        show_ipv4_header()
        show_tcp_header()
        show_tcp_handshake()
        show_udp_vs_tcp()
        show_icmp()
    elif topic in topics:
        topics[topic]()
    else:
        print(f"{Fore.RED}Unknown topic '{topic}'.{Style.RESET_ALL}")
        print(f"Available topics: {Fore.GREEN}{', '.join(topics.keys())}, all{Style.RESET_ALL}")
