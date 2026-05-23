# PacketSniffer - Network Packet Analyzer

A lightweight network packet capture and analysis tool for security monitoring and traffic analysis. Captures and dissects network packets to identify protocols, suspicious traffic, and potential security issues.

## Features

- Live packet capture on network interfaces
- Protocol identification (TCP, UDP, ICMP, HTTP, DNS, etc.)
- Packet filtering by protocol, source, destination
- Suspicious traffic pattern detection
- DNS query logging
- HTTP request extraction
- Credential detection (cleartext passwords)
- Connection tracking and statistics
- PCAP-compatible output

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/packet-sniffer.git
cd packet-sniffer
pip3 install -r requirements.txt
chmod +x packetsniffer.py
```

### System Requirements

- Linux/macOS (requires root/admin for raw sockets)
- Python 3.8+
- For full features: `scapy` library

```bash
# Install scapy for advanced packet parsing
pip3 install scapy

# On Debian/Ubuntu
sudo apt install python3-scapy
```

## Usage

### Live Capture (Basic)
```bash
sudo python3 packetsniffer.py capture
sudo python3 packetsniffer.py capture -i eth0
sudo python3 packetsniffer.py capture -i wlan0 --count 100
```

### Protocol Filter
```bash
sudo python3 packetsniffer.py capture --filter tcp
sudo python3 packetsniffer.py capture --filter udp
sudo python3 packetsniffer.py capture --filter icmp
sudo python3 packetsniffer.py capture --filter dns
sudo python3 packetsniffer.py capture --filter http
```

### DNS Monitoring
```bash
sudo python3 packetsniffer.py dns
```

### HTTP Request Logging
```bash
sudo python3 packetsniffer.py http
```

### Connection Tracking
```bash
sudo python3 packetsniffer.py connections
```

### Credential Detection
```bash
# Monitor for cleartext credentials (FTP, Telnet, HTTP Basic)
sudo python3 packetsniffer.py credentials
```

### Traffic Statistics
```bash
sudo python3 packetsniffer.py stats --duration 60
```

### Save Capture
```bash
sudo python3 packetsniffer.py capture --output capture.json
sudo python3 packetsniffer.py capture --count 1000 --output capture.json
```

## Packet Fields

| Field | Description |
|-------|-------------|
| Timestamp | Packet capture time |
| Source IP | Sender address |
| Dest IP | Receiver address |
| Source Port | Sender port |
| Dest Port | Receiver port |
| Protocol | TCP/UDP/ICMP/etc. |
| Length | Packet size in bytes |
| Info | Protocol-specific info |

## Legal Disclaimer

Packet sniffing is only legal on networks you own or have explicit authorization to monitor. Unauthorized network monitoring is illegal in most jurisdictions.

## License

MIT License
