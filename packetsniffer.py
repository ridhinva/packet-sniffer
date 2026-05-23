#!/usr/bin/env python3
"""
PacketSniffer - Network Packet Analyzer
For authorized network monitoring only.
"""

import argparse
import sys
import socket
import struct
import json
import time
import signal
from collections import Counter, defaultdict
from datetime import datetime

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError:
    class Fore:
        RED = GREEN = YELLOW = CYAN = WHITE = MAGENTA = RESET = ""
    class Style:
        RESET_ALL = ""

VERSION = "1.0.0"

# Protocol numbers
PROTOCOLS = {
    1: "ICMP", 2: "IGMP", 6: "TCP", 8: "EGP", 9: "IGP",
    17: "UDP", 27: "RDP", 41: "IPv6", 43: "IPv6-Route",
    44: "IPv6-Frag", 47: "GRE", 50: "ESP", 51: "AH",
    58: "IPv6-ICMP", 59: "IPv6-NoNxt", 60: "IPv6-Opts",
    89: "OSPF", 103: "PIM", 112: "VRRP", 132: "SCTP",
}

WELL_KNOWN_PORTS = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP-S", 68: "DHCP-C", 69: "TFTP", 80: "HTTP",
    110: "POP3", 119: "NNTP", 123: "NTP", 135: "MSRPC", 137: "NetBIOS-NS",
    138: "NetBIOS-DG", 139: "NetBIOS-SS", 143: "IMAP", 161: "SNMP",
    162: "SNMP-Trap", 389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
    514: "Syslog", 587: "SMTP-Sub", 636: "LDAPS", 993: "IMAPS",
    995: "POP3S", 1080: "SOCKS", 1433: "MSSQL", 1521: "Oracle",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 9200: "Elastic",
    27017: "MongoDB",
}

CREDENTIAL_PATTERNS = [
    b"USER ", b"PASS ", b"PASS:",
    b"Authorization: Basic ",
    b"login:", b"password:",
    b"username=", b"password=",
    b"passwd=", b"pwd=",
]


class PacketSniffer:
    def __init__(self, interface=None, count=0, timeout=0, proto_filter=None):
        self.interface = interface
        self.count = count
        self.timeout = timeout
        self.proto_filter = proto_filter
        self.packets = []
        self.running = True
        self.stats = {
            "total": 0,
            "protocols": Counter(),
            "sources": Counter(),
            "destinations": Counter(),
            "dns_queries": [],
            "http_requests": [],
            "credentials": [],
            "connections": defaultdict(int),
        }

        signal.signal(signal.SIGINT, self._signal_handler)

    def _signal_handler(self, sig, frame):
        print(f"\n{Fore.YELLOW}[*] Capture stopped by user{Style.RESET_ALL}")
        self.running = False

    def parse_ethernet(self, data):
        """Parse Ethernet frame."""
        if len(data) < 14:
            return None, None, None, data

        eth_header = struct.unpack("!6s6sH", data[:14])
        eth_type = eth_header[2]
        payload = data[14:]

        src_mac = ":".join(f"{b:02x}" for b in eth_header[0])
        dst_mac = ":".join(f"{b:02x}" for b in eth_header[1])

        return src_mac, dst_mac, eth_type, payload

    def parse_ip(self, data):
        """Parse IP packet."""
        if len(data) < 20:
            return None

        ip_header = struct.unpack("!BBHHHBBH4s4s", data[:20])
        version = (ip_header[0] >> 4)
        ihl = (ip_header[0] & 0xF) * 4
        ttl = ip_header[5]
        protocol = ip_header[6]
        src_ip = socket.inet_ntoa(ip_header[8])
        dst_ip = socket.inet_ntoa(ip_header[9])
        total_length = ip_header[2]

        return {
            "version": version,
            "ihl": ihl,
            "ttl": ttl,
            "protocol": protocol,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "total_length": total_length,
            "payload": data[ihl:],
        }

    def parse_tcp(self, data):
        """Parse TCP segment."""
        if len(data) < 20:
            return None

        tcp_header = struct.unpack("!HHLLBBHHH", data[:20])
        src_port = tcp_header[0]
        dst_port = tcp_header[1]
        seq = tcp_header[2]
        ack = tcp_header[3]
        flags = tcp_header[5]

        flag_str = []
        if flags & 0x01: flag_str.append("FIN")
        if flags & 0x02: flag_str.append("SYN")
        if flags & 0x04: flag_str.append("RST")
        if flags & 0x08: flag_str.append("PSH")
        if flags & 0x10: flag_str.append("ACK")
        if flags & 0x20: flag_str.append("URG")

        data_offset = ((tcp_header[4] >> 4) & 0xF) * 4

        return {
            "src_port": src_port,
            "dst_port": dst_port,
            "seq": seq,
            "ack": ack,
            "flags": " ".join(flag_str),
            "payload": data[data_offset:],
        }

    def parse_udp(self, data):
        """Parse UDP datagram."""
        if len(data) < 8:
            return None

        udp_header = struct.unpack("!HHHH", data[:8])
        return {
            "src_port": udp_header[0],
            "dst_port": udp_header[1],
            "length": udp_header[2],
            "payload": data[8:],
        }

    def parse_dns(self, data):
        """Parse DNS query."""
        if len(data) < 12:
            return None

        try:
            dns_header = struct.unpack("!HHHHHH", data[:12])
            flags = dns_header[1]
            qdcount = dns_header[2]
            is_response = (flags & 0x8000) != 0

            # Parse query name
            offset = 12
            name_parts = []
            while offset < len(data):
                length = data[offset]
                if length == 0:
                    offset += 1
                    break
                if length >= 192:  # Pointer
                    offset += 2
                    break
                offset += 1
                name_parts.append(data[offset:offset + length].decode('utf-8', errors='ignore'))
                offset += length

            domain = ".".join(name_parts)
            qtype = struct.unpack("!H", data[offset:offset + 2])[0] if offset + 2 <= len(data) else 0
            type_names = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 15: "MX", 16: "TXT", 28: "AAAA"}
            type_name = type_names.get(qtype, f"TYPE{qtype}")

            return {
                "domain": domain,
                "type": type_name,
                "is_response": is_response,
            }
        except:
            return None

    def check_credentials(self, data):
        """Check for cleartext credentials."""
        for pattern in CREDENTIAL_PATTERNS:
            if pattern in data:
                try:
                    text = data.decode('utf-8', errors='ignore')
                    for line in text.split('\n'):
                        if any(p.decode() in line.upper() for p in CREDENTIAL_PATTERNS):
                            return line.strip()[:100]
                except:
                    pass
        return None

    def process_packet(self, data):
        """Process a raw packet."""
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]

        # Parse Ethernet
        src_mac, dst_mac, eth_type, ip_data = self.parse_ethernet(data)

        # Parse IP
        if eth_type != 0x0800:  # Not IPv4
            return

        ip_info = self.parse_ip(ip_data)
        if not ip_info:
            return

        protocol_num = ip_info["protocol"]
        protocol_name = PROTOCOLS.get(protocol_num, str(protocol_num))

        # Apply filter
        if self.proto_filter:
            filter_lower = self.proto_filter.lower()
            if filter_lower == "tcp" and protocol_num != 6:
                return
            elif filter_lower == "udp" and protocol_num != 17:
                return
            elif filter_lower == "icmp" and protocol_num != 1:
                return
            elif filter_lower == "dns":
                if protocol_num != 17:
                    return
            elif filter_lower == "http":
                if protocol_num != 6:
                    return

        src_port = 0
        dst_port = 0
        flags = ""
        payload = ip_info["payload"]

        # Parse TCP
        if protocol_num == 6:
            tcp_info = self.parse_tcp(payload)
            if tcp_info:
                src_port = tcp_info["src_port"]
                dst_port = tcp_info["dst_port"]
                flags = tcp_info["flags"]
                payload = tcp_info["payload"]

                # Track connections
                conn_key = f"{ip_info['src_ip']}:{src_port} -> {ip_info['dst_ip']}:{dst_port}"
                self.stats["connections"][conn_key] += 1

                # HTTP detection
                if dst_port == 80 or dst_port == 8080:
                    try:
                        http_data = payload[:200].decode('utf-8', errors='ignore')
                        if http_data.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ')):
                            self.stats["http_requests"].append({
                                "time": timestamp,
                                "src": ip_info["src_ip"],
                                "request": http_data.split('\n')[0][:100],
                            })
                    except:
                        pass

        # Parse UDP
        elif protocol_num == 17:
            udp_info = self.parse_udp(payload)
            if udp_info:
                src_port = udp_info["src_port"]
                dst_port = udp_info["dst_port"]
                payload = udp_info["payload"]

                # DNS detection
                if dst_port == 53 or src_port == 53:
                    dns_info = self.parse_dns(payload)
                    if dns_info:
                        self.stats["dns_queries"].append({
                            "time": timestamp,
                            "src": ip_info["src_ip"],
                            **dns_info,
                        })
                        if self.proto_filter and self.proto_filter.lower() == "dns":
                            direction = "Response" if dns_info["is_response"] else "Query"
                            print(f"  {Fore.CYAN}[DNS {direction}]{Style.RESET_ALL} "
                                  f"{ip_info['src_ip']} => {dns_info['domain']} ({dns_info['type']})")

        # Credential detection
        cred = self.check_credentials(payload)
        if cred:
            self.stats["credentials"].append({
                "time": timestamp,
                "src": ip_info["src_ip"],
                "dst": ip_info["dst_ip"],
                "data": cred,
            })
            print(f"  {Fore.RED}[CREDENTIAL!] {ip_info['src_ip']}:{src_port} -> "
                  f"{ip_info['dst_ip']}:{dst_port} : {cred[:60]}{Style.RESET_ALL}")

        # Update stats
        self.stats["total"] += 1
        self.stats["protocols"][protocol_name] += 1
        self.stats["sources"][ip_info["src_ip"]] += 1
        self.stats["destinations"][ip_info["dst_ip"]] += 1

        # Filter display
        if self.proto_filter:
            filter_lower = self.proto_filter.lower()
            if filter_lower == "dns" and (dst_port == 53 or src_port == 53):
                return  # Already printed above
            elif filter_lower == "http" and dst_port not in (80, 8080):
                return

        # Print packet
        port_str = ""
        if src_port and dst_port:
            sport_name = WELL_KNOWN_PORTS.get(dst_port, "")
            port_str = f":{src_port} -> :{dst_port}"
            if sport_name:
                port_str += f" ({sport_name})"

        print(f"  {Fore.WHITE}{timestamp}{Style.RESET_ALL} "
              f"{Fore.GREEN}{ip_info['src_ip']}{Style.RESET_ALL}{port_str} -> "
              f"{Fore.GREEN}{ip_info['dst_ip']}{Style.RESET_ALL} "
              f"{Fore.CYAN}{protocol_name}{Style.RESET_ALL} "
              f"Len:{ip_info['total_length']} {flags}")

    def capture_live(self):
        """Capture packets on interface."""
        print(f"\n{Fore.CYAN}[*] Starting packet capture...{Style.RESET_ALL}")
        if self.interface:
            print(f"  Interface: {self.interface}")
        if self.proto_filter:
            print(f"  Filter: {self.proto_filter}")
        if self.count:
            print(f"  Count: {self.count}")
        print(f"  Press Ctrl+C to stop\n")

        try:
            # Create raw socket
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            if self.interface:
                sock.bind((self.interface, 0))
            sock.settimeout(1)

            start_time = time.time()
            captured = 0

            while self.running:
                if self.timeout and (time.time() - start_time) > self.timeout:
                    break
                if self.count and captured >= self.count:
                    break

                try:
                    data, addr = sock.recvfrom(65535)
                    self.process_packet(data)
                    captured += 1
                except socket.timeout:
                    continue
                except KeyboardInterrupt:
                    break

            sock.close()

        except PermissionError:
            print(f"  {Fore.RED}[!] Permission denied. Run with sudo:{Style.RESET_ALL}")
            print(f"  sudo python3 {' '.join(sys.argv)}")
            return
        except OSError as e:
            print(f"  {Fore.RED}[!] Socket error: {e}{Style.RESET_ALL}")
            print(f"  {Fore.YELLOW}[*] On Linux, run with: sudo python3 packetsniffer.py capture{Style.RESET_ALL}")
            return

    def print_stats(self):
        """Print capture statistics."""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"  CAPTURE STATISTICS")
        print(f"{'='*60}{Style.RESET_ALL}")
        print(f"  Total packets: {self.stats['total']}")

        if self.stats["protocols"]:
            print(f"\n  {Fore.WHITE}Protocol Distribution:{Style.RESET_ALL}")
            for proto, count in self.stats["protocols"].most_common():
                print(f"    {proto}: {count}")

        if self.stats["sources"]:
            print(f"\n  {Fore.WHITE}Top Source IPs:{Style.RESET_ALL}")
            for ip, count in self.stats["sources"].most_common(10):
                print(f"    {ip}: {count}")

        if self.stats["destinations"]:
            print(f"\n  {Fore.WHITE}Top Destination IPs:{Style.RESET_ALL}")
            for ip, count in self.stats["destinations"].most_common(10):
                print(f"    {ip}: {count}")

        if self.stats["dns_queries"]:
            print(f"\n  {Fore.WHITE}DNS Queries ({len(self.stats['dns_queries'])}):{Style.RESET_ALL}")
            for q in self.stats["dns_queries"][-10:]:
                print(f"    {q['time']} {q['src']} => {q['domain']} ({q['type']})")

        if self.stats["http_requests"]:
            print(f"\n  {Fore.WHITE}HTTP Requests ({len(self.stats['http_requests'])}):{Style.RESET_ALL}")
            for r in self.stats["http_requests"][-10:]:
                print(f"    {r['time']} {r['src']} : {r['request']}")

        if self.stats["credentials"]:
            print(f"\n  {Fore.RED}CREDENTIALS DETECTED ({len(self.stats['credentials'])}):{Style.RESET_ALL}")
            for c in self.stats["credentials"]:
                print(f"    {c['time']} {c['src']} -> {c['dst']} : {c['data'][:60]}")

    def print_connections(self):
        """Print connection tracking."""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"  CONNECTION TRACKING")
        print(f"{'='*60}{Style.RESET_ALL}")

        for conn, count in sorted(self.stats["connections"].items(), key=lambda x: x[1], reverse=True)[:30]:
            print(f"  {conn} ({count} packets)")

    def export_json(self, filename):
        report = {
            "tool": "PacketSniffer",
            "version": VERSION,
            "capture_time": datetime.now().isoformat(),
            "total_packets": self.stats["total"],
            "protocols": dict(self.stats["protocols"]),
            "dns_queries": self.stats["dns_queries"],
            "http_requests": self.stats["http_requests"],
            "credentials": self.stats["credentials"],
            "connections": dict(self.stats["connections"]),
        }
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"\n{Fore.GREEN}[+] Capture saved to {filename}{Style.RESET_ALL}")


def cmd_capture(args):
    sniffer = PacketSniffer(
        interface=args.interface,
        count=args.count,
        timeout=args.duration,
        proto_filter=args.filter,
    )
    sniffer.capture_live()
    sniffer.print_stats()

    if args.output:
        sniffer.export_json(args.output)


def cmd_dns(args):
    sniffer = PacketSniffer(interface=args.interface, count=args.count, proto_filter="dns")
    sniffer.capture_live()
    sniffer.print_stats()


def cmd_http(args):
    sniffer = PacketSniffer(interface=args.interface, count=args.count, proto_filter="http")
    sniffer.capture_live()
    sniffer.print_stats()


def cmd_connections(args):
    sniffer = PacketSniffer(interface=args.interface, count=args.count, timeout=args.duration)
    sniffer.capture_live()
    sniffer.print_connections()


def cmd_credentials(args):
    sniffer = PacketSniffer(interface=args.interface, count=args.count, timeout=args.duration)
    sniffer.capture_live()
    if sniffer.stats["credentials"]:
        print(f"\n{Fore.RED}{'='*60}")
        print(f"  CREDENTIALS FOUND")
        print(f"{'='*60}{Style.RESET_ALL}")
        for c in sniffer.stats["credentials"]:
            print(f"  {c['time']} {c['src']} -> {c['dst']}")
            print(f"    {c['data']}")
    else:
        print(f"\n  {Fore.GREEN}[+] No cleartext credentials detected{Style.RESET_ALL}")


def cmd_stats(args):
    sniffer = PacketSniffer(interface=args.interface, timeout=args.duration)
    sniffer.capture_live()
    sniffer.print_stats()


def main():
    parser = argparse.ArgumentParser(
        description="PacketSniffer - Network Packet Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo %(prog)s capture -i eth0 --count 100
  sudo %(prog)s capture --filter tcp
  sudo %(prog)s dns -i wlan0
  sudo %(prog)s http
  sudo %(prog)s connections --duration 60
  sudo %(prog)s credentials
  sudo %(prog)s stats --duration 60
        """
    )
    parser.add_argument("--version", action="version", version=f"PacketSniffer {VERSION}")

    sub = parser.add_subparsers(dest="command")

    # capture
    cap = sub.add_parser("capture", help="Live packet capture")
    cap.add_argument("-i", "--interface", help="Network interface")
    cap.add_argument("--count", type=int, default=0, help="Packet count (0=unlimited)")
    cap.add_argument("--duration", type=int, default=0, help="Duration in seconds")
    cap.add_argument("--filter", choices=["tcp", "udp", "icmp", "dns", "http"], help="Protocol filter")
    cap.add_argument("--output", help="Save capture to JSON file")

    # dns
    dns = sub.add_parser("dns", help="Monitor DNS queries")
    dns.add_argument("-i", "--interface", help="Network interface")
    dns.add_argument("--count", type=int, default=0, help="Packet count")

    # http
    http = sub.add_parser("http", help="Monitor HTTP requests")
    http.add_argument("-i", "--interface", help="Network interface")
    http.add_argument("--count", type=int, default=0, help="Packet count")

    # connections
    conn = sub.add_parser("connections", help="Track connections")
    conn.add_argument("-i", "--interface", help="Network interface")
    conn.add_argument("--duration", type=int, default=30, help="Duration in seconds")

    # credentials
    cred = sub.add_parser("credentials", help="Detect cleartext credentials")
    cred.add_argument("-i", "--interface", help="Network interface")
    cred.add_argument("--duration", type=int, default=60, help="Duration in seconds")

    # stats
    stats = sub.add_parser("stats", help="Traffic statistics")
    stats.add_argument("-i", "--interface", help="Network interface")
    stats.add_argument("--duration", type=int, default=30, help="Duration in seconds")

    args = parser.parse_args()

    print(f"\n{Fore.CYAN}╔══════════════════════════════════╗")
    print(f"║   PacketSniffer v{VERSION}          ║")
    print(f"╚══════════════════════════════════╝{Style.RESET_ALL}")

    if not args.command:
        parser.print_help()
        sys.exit(1)

    commands = {
        "capture": cmd_capture,
        "dns": cmd_dns,
        "http": cmd_http,
        "connections": cmd_connections,
        "credentials": cmd_credentials,
        "stats": cmd_stats,
    }
    commands[args.command](args)


if __name__ == "__main__":
    main()
