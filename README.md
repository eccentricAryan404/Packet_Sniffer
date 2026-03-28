# 🔍 Packet Sniffer — Java

![Java](https://img.shields.io/badge/Java-11%2B-orange?style=for-the-badge&logo=java)
![Maven](https://img.shields.io/badge/Maven-3.8%2B-red?style=for-the-badge&logo=apachemaven)
![Pcap4J](https://img.shields.io/badge/Pcap4J-1.8.2-blue?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-green?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)

A powerful real-time **network packet sniffer** built in Java using the **Pcap4J** library.
Captures, decodes, and analyzes live network traffic across multiple protocol layers —
from Ethernet frames all the way up to TCP/UDP application ports.

Built as a learning project to understand how network protocols work at a low level,
similar to tools like **Wireshark** and **tcpdump** but written from scratch in Java.

---

## 📖 Table of Contents

- [What is a Packet Sniffer?](#-what-is-a-packet-sniffer)
- [Features](#-features)
- [How it Works](#-how-it-works)
- [Tech Stack](#-tech-stack)
- [Project Structure](#-project-structure)
- [Setup & Installation](#-setup--installation)
- [Running the Tool](#-running-the-tool)
- [Sample Output](#-sample-output)
- [BPF Filters](#-bpf-filter-examples)
- [Network Protocols Explained](#-network-protocols-explained)
- [What I Learned](#-what-i-learned)
- [Legal Disclaimer](#-legal-disclaimer)

---

## 📡 What is a Packet Sniffer?

A **packet sniffer** (also called a network analyzer or protocol analyzer) is a tool that
captures and inspects data packets as they travel across a network interface.

Every time you open a website, send a message, or stream a video — your computer is
sending and receiving thousands of small data packets. A packet sniffer intercepts these
packets and lets you see exactly what data is being transmitted, which protocols are being
used, and where the traffic is going.

This is used by:
- 🛡️ **Security professionals** — to detect intrusions and suspicious traffic
- 🐛 **Developers** — to debug network applications
- 🎓 **Students** — to learn how networking protocols actually work
- 🔧 **Network engineers** — to troubleshoot connectivity issues

---

## ✨ Features

- ✅ **Live packet capture** from any network interface (eth0, wlan0, lo, etc.)
- ✅ **Multi-layer protocol decoding:**
  - Layer 2 — Ethernet (MAC addresses, EtherType)
  - Layer 3 — IPv4 and IPv6 (IP addresses, TTL, protocol)
  - Layer 4 — TCP (ports, sequence numbers, flags: SYN/ACK/FIN/RST/PSH/URG)
  - Layer 4 — UDP (ports, length)
  - Layer 3 — ICMP (type, code — ping packets)
- ✅ **BPF filter support** — filter by protocol, port, or IP address
- ✅ **Raw hex payload preview** — first 24 bytes of every packet
- ✅ **Real-time statistics** at end of capture:
  - Total packets and bytes captured
  - Protocol breakdown with percentages
  - Top 5 source IP addresses
  - Top 5 destination ports
- ✅ **Promiscuous mode** — captures all packets on the network, not just your own
- ✅ **Cross-platform** — works on Linux, Kali, macOS, and Windows

---

## ⚙️ How it Works
```
Network Interface (eth0 / wlan0)
         │
         ▼
   libpcap / Npcap          ← Native C library that hooks into the OS network stack
         │
         ▼
      Pcap4J                ← Java wrapper around libpcap
         │
         ▼
   PacketSniffer.java       ← Opens the interface, applies BPF filter, reads packets
         │
         ▼
   PacketAnalyzer.java      ← Decodes each packet layer by layer
         │
         ├──▶ EthernetPacket   (MAC addresses)
         ├──▶ IpV4Packet        (IP addresses, TTL)
         ├──▶ TcpPacket         (ports, flags, sequence numbers)
         ├──▶ UdpPacket         (ports, length)
         └──▶ IcmpPacket        (type, code)
         │
         ▼
   PacketStats.java         ← Tracks counts, bytes, top IPs, top ports
         │
         ▼
   Console Output            ← Human readable decoded packet info + summary
```

Each packet goes through this pipeline in milliseconds. The BPF (Berkeley Packet Filter)
runs at the kernel level — so filtering happens before packets even reach Java,
making it extremely efficient.

---

## 🛠️ Tech Stack

| Technology | Version | Purpose |
|------------|---------|---------|
| Java | 11+ | Core programming language |
| Pcap4J | 1.8.2 | Java library for packet capture |
| Maven | 3.8+ | Dependency management and build tool |
| Maven Shade Plugin | 3.4.1 | Packages all dependencies into one fat JAR |
| libpcap | Latest | Native packet capture on Linux/macOS |
| Npcap | Latest | Native packet capture on Windows |
| SLF4J | 1.7.36 | Logging framework |

---

## 📁 Project Structure
```
packet-sniffer/
│
├── pom.xml                          # Maven config, dependencies, build settings
│
└── src/
    └── main/
        └── java/
            └── com/
                └── sniffer/
                    │
                    ├── Main.java
                    │   # Entry point of the application
                    │   # Lists all network interfaces
                    │   # Prompts user to select interface
                    │   # Takes BPF filter input
                    │   # Takes packet count input
                    │   # Starts the sniffer
                    │
                    ├── PacketSniffer.java
                    │   # Core capture engine
                    │   # Opens network interface in promiscuous mode
                    │   # Applies BPF filter if provided
                    │   # Reads packets in a loop
                    │   # Passes packets to analyzer and stats
                    │
                    ├── PacketAnalyzer.java
                    │   # Decodes packet layer by layer
                    │   # Extracts and prints:
                    │   #   - Ethernet header (MAC, type)
                    │   #   - IPv4/IPv6 header (IPs, TTL, protocol)
                    │   #   - TCP header (ports, seq, ack, flags)
                    │   #   - UDP header (ports, length)
                    │   #   - ICMP header (type, code)
                    │   #   - Raw hex preview
                    │
                    └── PacketStats.java
                        # Tracks running statistics
                        # Counts TCP / UDP / ICMP / Other packets
                        # Tracks total bytes
                        # Records top source IPs
                        # Records top destination ports
                        # Prints final summary table
```

---

## 🔧 Setup & Installation

### Prerequisites

**On Kali Linux / Ubuntu / Debian:**
```bash
# Update packages
sudo apt update

# Install Java
sudo apt install default-jdk -y

# Install Maven
sudo apt install maven -y

# Install libpcap (usually pre-installed on Kali)
sudo apt install libpcap-dev -y

# Verify installations
java -version
mvn -version
```

**On Windows:**
1. Install [JDK 17+](https://adoptium.net) and add to PATH
2. Install [Maven](https://maven.apache.org/download.cgi) and add `bin/` to PATH
3. Install [Npcap](https://npcap.com) — required for raw packet access on Windows

---

### Clone the Repository
```bash
git clone https://github.com/eccentricAryan404/Packet_Sniffer.git
cd Packet_Sniffer
```

### Build
```bash
mvn clean package
```

This creates a fat JAR at `target/packet-sniffer-1.0-SNAPSHOT.jar` with all
dependencies bundled inside.

---

## ▶️ Running the Tool

**Linux / Kali — must run as root:**
```bash
sudo java -jar target/packet-sniffer-1.0-SNAPSHOT.jar
```

**Windows — run terminal as Administrator:**
```bash
java -jar target\packet-sniffer-1.0-SNAPSHOT.jar
```

The program will prompt you step by step:
```
Select interface number [0]: 0
Enter BPF filter (or press Enter for all): tcp
Number of packets to capture [50]: 20
```

---

## 🖥️ Sample Output
```
╔══════════════════════════════════╗
║       Java Packet Sniffer        ║
╚══════════════════════════════════╝

Available Interfaces:
  [0] eth0       - Ethernet Adapter
  [1] wlan0      - Wireless Adapter
  [2] lo         - Loopback

Select interface number [0]: 0
Enter BPF filter (or press Enter for all): tcp
Number of packets to capture [50]: 5

Starting capture on [eth0]
Filter: tcp
Capturing 5 packets...

────────────────────────────────────────────────────────────
▶ Packet #1   │ 2026-03-28 12:00:01.123 │ 74 bytes
  [ETH]  aa:bb:cc:dd:ee:ff → 11:22:33:44:55:66  (type: IPv4)
  [IPv4] 192.168.1.5 → 142.250.180.46  proto=TCP TTL=64
  [TCP]  port 52341 → 443  seq=1234567 ack=0  [SYN]
  [HEX]  45 00 00 3C 1E 4B 40 00 40 06 A1 B2 C3 D4 ...
────────────────────────────────────────────────────────────
▶ Packet #2   │ 2026-03-28 12:00:01.145 │ 60 bytes
  [ETH]  11:22:33:44:55:66 → aa:bb:cc:dd:ee:ff  (type: IPv4)
  [IPv4] 142.250.180.46 → 192.168.1.5  proto=TCP TTL=118
  [TCP]  port 443 → 52341  seq=9876543 ack=1234568  [SYN ACK]
  [HEX]  45 00 00 3C 00 00 40 00 76 06 B2 C3 ...
────────────────────────────────────────────────────────────

╔══════════════════ CAPTURE SUMMARY ══════════════════╗
  Total Packets : 5
  Total Bytes   : 330 bytes (0.32 KB)
  TCP           : 4 (80.0%)
  UDP           : 1 (20.0%)
  ICMP          : 0 (0.0%)
  Other         : 0 (0.0%)

  Top Source IPs:
    192.168.1.5        3 packets
    142.250.180.46     2 packets

  Top Destination Ports:
    Port 443       3 packets
    Port 53        1 packets
╚═════════════════════════════════════════════════════╝
```

---

## 📌 BPF Filter Examples

BPF (Berkeley Packet Filter) is a powerful filtering language used by tools like
Wireshark and tcpdump. This sniffer supports the same syntax.

| Filter | What it Captures |
|--------|-----------------|
| *(empty)* | All packets |
| `tcp` | TCP packets only |
| `udp` | UDP packets only |
| `icmp` | Ping packets only |
| `port 80` | HTTP traffic |
| `port 443` | HTTPS traffic |
| `port 53` | DNS queries |
| `port 22` | SSH traffic |
| `host 8.8.8.8` | Traffic to/from Google DNS |
| `tcp and port 80` | TCP on port 80 only |
| `not port 443` | Everything except HTTPS |
| `src host 192.168.1.1` | From a specific IP only |
| `dst port 3306` | MySQL database traffic |

---

## 📚 Network Protocols Explained

### Ethernet (Layer 2)
The lowest level captured. Every packet on a local network has an Ethernet frame
containing source and destination **MAC addresses** — unique hardware identifiers
burned into every network card.

### IPv4 / IPv6 (Layer 3)
The Internet Protocol layer. Contains source and destination **IP addresses**,
**TTL** (Time To Live — how many hops before the packet is dropped), and
the protocol number identifying what's inside (TCP=6, UDP=17, ICMP=1).

### TCP (Layer 4)
Transmission Control Protocol — reliable, ordered delivery. Contains **port numbers**
(identifying the application), **sequence and acknowledgment numbers** (for ordering),
and **flags** controlling the connection state:
- `SYN` — start connection
- `ACK` — acknowledge received data
- `FIN` — close connection
- `RST` — reset/abort connection
- `PSH` — push data immediately

### UDP (Layer 4)
User Datagram Protocol — fast, connectionless. No handshake, no guarantee of delivery.
Used for DNS, video streaming, gaming, VoIP.

### ICMP (Layer 3)
Internet Control Message Protocol — used for diagnostics. The `ping` command sends
ICMP Echo Request packets and waits for Echo Reply.

---

## 🎓 What I Learned

Building this project taught me:

- How data travels across a network in layers (OSI model in practice)
- How libpcap hooks into the OS kernel to intercept raw packets
- How TCP handshakes work (SYN → SYN-ACK → ACK)
- How BPF filters work at the kernel level for efficient filtering
- How to work with binary data and parse protocol headers in Java
- How tools like Wireshark work under the hood
- Java build tools (Maven), dependency management, fat JARs
- Running privileged operations on Linux (raw socket access requires root)

---

## ⚠️ Legal Disclaimer

> ⚠️ This tool is built for **educational and research purposes only.**
>
> - Only use this tool on networks you **own** or have **explicit permission** to monitor
> - Sniffing traffic on public or corporate networks **without permission is illegal**
> - The author takes **no responsibility** for misuse of this tool
> - Always follow your local laws regarding network monitoring and data privacy

---

## 👤 Author
**eccentricAryan404**
