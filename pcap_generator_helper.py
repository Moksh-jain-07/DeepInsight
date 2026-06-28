#!/usr/bin/env python3
"""
DeepInsight PCAP Generator Helper
Generates mock PCAP files with specific application types and proportions.
"""

import sys
import struct
import random
import argparse

class PCAPWriter:
    def __init__(self, filename):
        self.file = open(filename, 'wb')
        self.write_global_header()
        self.timestamp = 1700000000
        
    def write_global_header(self):
        # Magic, version 2.4, timezone 0, sigfigs 0, snaplen 65535, linktype Ethernet
        header = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
        self.file.write(header)
        
    def write_packet(self, data):
        ts_sec = self.timestamp
        ts_usec = random.randint(0, 999999)
        self.timestamp += 1
        
        pkt_header = struct.pack('<IIII', ts_sec, ts_usec, len(data), len(data))
        self.file.write(pkt_header)
        self.file.write(data)
        
    def close(self):
        self.file.close()

def create_ethernet_header(src_mac, dst_mac, ethertype=0x0800):
    return bytes.fromhex(dst_mac.replace(':', '')) + \
           bytes.fromhex(src_mac.replace(':', '')) + \
           struct.pack('>H', ethertype)

def create_ip_header(src_ip, dst_ip, protocol, payload_len):
    version_ihl = 0x45
    tos = 0
    total_len = 20 + payload_len
    ident = random.randint(1, 65535)
    flags_frag = 0x4000  # Don't fragment
    ttl = 64
    checksum = 0
    
    header = struct.pack('>BBHHHBBH',
                         version_ihl, tos, total_len,
                         ident, flags_frag,
                         ttl, protocol, checksum)
    
    header += bytes([int(x) for x in src_ip.split('.')])
    header += bytes([int(x) for x in dst_ip.split('.')])
    return header

def create_tcp_header(src_port, dst_port, seq, ack, flags, payload_len=0):
    data_offset = 5 << 4  # 20 bytes
    window = 65535
    checksum = 0
    urgent = 0
    return struct.pack('>HHIIBBHHH',
                       src_port, dst_port,
                       seq, ack,
                       data_offset, flags,
                       window, checksum, urgent)

def create_udp_header(src_port, dst_port, payload_len):
    length = 8 + payload_len
    checksum = 0
    return struct.pack('>HHHH', src_port, dst_port, length, checksum)

def create_tls_client_hello(sni):
    # SNI extension
    sni_bytes = sni.encode('ascii')
    sni_entry = struct.pack('>BH', 0, len(sni_bytes)) + sni_bytes
    sni_list = struct.pack('>H', len(sni_entry)) + sni_entry
    sni_ext = struct.pack('>HH', 0x0000, len(sni_list)) + sni_list
    
    # Supported versions extension (TLS 1.3)
    supported_versions = struct.pack('>HHB', 0x002b, 3, 2) + struct.pack('>H', 0x0304)
    
    # All extensions
    extensions = sni_ext + supported_versions
    extensions_data = struct.pack('>H', len(extensions)) + extensions
    
    # Client Hello body
    client_version = struct.pack('>H', 0x0303)  # TLS 1.2
    random_bytes = bytes([random.randint(0, 255) for _ in range(32)])
    session_id = struct.pack('B', 0)
    cipher_suites = struct.pack('>H', 4) + struct.pack('>HH', 0x1301, 0x1302)
    compression = struct.pack('BB', 1, 0)
    
    client_hello_body = client_version + random_bytes + session_id + cipher_suites + compression + extensions_data
    
    # Handshake header
    handshake = struct.pack('B', 0x01)  # Client Hello
    handshake += struct.pack('>I', len(client_hello_body))[1:]  # 3-byte length
    handshake += client_hello_body
    
    # TLS record header
    record = struct.pack('B', 0x16)  # Handshake
    record += struct.pack('>H', 0x0301)
    record += struct.pack('>H', len(handshake))
    record += handshake
    return record

def create_http_request(host, path='/'):
    return f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: DeepInsight-Simulator/1.0\r\nAccept: */*\r\n\r\n".encode()

def create_dns_query(domain):
    txid = struct.pack('>H', random.randint(1, 65535))
    flags = struct.pack('>H', 0x0100)
    counts = struct.pack('>HHHH', 1, 0, 0, 0)
    
    question = b''
    for label in domain.split('.'):
        question += struct.pack('B', len(label)) + label.encode()
    question += struct.pack('B', 0)
    question += struct.pack('>HH', 1, 1)  # Type A, Class IN
    return txid + flags + counts + question

# TLS Application mappings with standard mock IPs
TLS_APPS = {
    "google": ("142.250.185.206", "www.google.com"),
    "youtube": ("142.250.185.110", "www.youtube.com"),
    "facebook": ("157.240.1.35", "www.facebook.com"),
    "instagram": ("157.240.1.174", "www.instagram.com"),
    "twitter": ("104.244.42.65", "twitter.com"),
    "amazon": ("52.94.236.248", "www.amazon.com"),
    "netflix": ("23.52.167.61", "www.netflix.com"),
    "github": ("140.82.114.4", "github.com"),
    "discord": ("104.16.85.20", "discord.com"),
    "zoom": ("35.186.224.25", "zoom.us"),
    "telegram": ("35.186.227.140", "web.telegram.org"),
    "tiktok": ("99.86.0.100", "www.tiktok.com"),
    "spotify": ("35.186.224.47", "open.spotify.com"),
    "cloudflare": ("192.0.78.24", "www.cloudflare.com"),
    "microsoft": ("13.107.42.14", "www.microsoft.com"),
    "apple": ("17.253.144.10", "www.apple.com"),
}

HTTP_HOSTS = [
    ("93.184.216.34", "example.com"),
    ("185.199.108.153", "httpbin.org"),
    ("192.0.78.9", "example.org"),
]

DNS_DOMAINS = [
    "www.google.com",
    "www.youtube.com",
    "www.facebook.com",
    "github.com",
    "web.telegram.org",
    "zoom.us",
    "netflix.com",
]

def main():
    parser = argparse.ArgumentParser(description="DeepInsight PCAP Generator Helper")
    parser.add_argument("--output", required=True, help="Path to write the generated PCAP file")
    parser.add_argument("--dns", type=int, default=0, help="Number of DNS query packets")
    parser.add_argument("--http", type=int, default=0, help="Number of HTTP connection flows")
    parser.add_argument("--blocked-ip-packets", type=int, default=0, help="Number of packets from blocked IP")
    
    # App-specific overrides (passed as e.g. --app-youtube 5)
    for app in TLS_APPS:
        parser.add_argument(f"--app-{app}", type=int, default=0, help=f"Number of TLS handshakes for {app}")
        
    args = parser.parse_args()

    writer = PCAPWriter(args.output)
    
    user_mac = '00:11:22:33:44:55'
    user_ip = '192.168.1.100'
    gateway_mac = 'aa:bb:cc:dd:ee:ff'
    
    seq_base = 1000
    
    # 1. Generate TLS Connections
    for app_name, info in TLS_APPS.items():
        count = getattr(args, f"app_{app_name}", 0)
        if count <= 0:
            continue
            
        dst_ip, sni = info
        for _ in range(count):
            src_port = random.randint(49152, 65535)
            dst_port = 443
            
            # TCP Handshake: SYN
            eth = create_ethernet_header(user_mac, gateway_mac)
            tcp = create_tcp_header(src_port, dst_port, seq_base, 0, 0x02)
            ip = create_ip_header(user_ip, dst_ip, 6, len(tcp))
            writer.write_packet(eth + ip + tcp)
            
            # TCP SYN-ACK
            tcp = create_tcp_header(dst_port, src_port, seq_base + 100, seq_base + 1, 0x12)
            ip = create_ip_header(dst_ip, user_ip, 6, len(tcp))
            eth = create_ethernet_header(gateway_mac, user_mac)
            writer.write_packet(eth + ip + tcp)
            
            # TCP ACK
            eth = create_ethernet_header(user_mac, gateway_mac)
            tcp = create_tcp_header(src_port, dst_port, seq_base + 1, seq_base + 101, 0x10)
            ip = create_ip_header(user_ip, dst_ip, 6, len(tcp))
            writer.write_packet(eth + ip + tcp)
            
            # TLS Client Hello
            tls_data = create_tls_client_hello(sni)
            tcp = create_tcp_header(src_port, dst_port, seq_base + 1, seq_base + 101, 0x18)
            ip = create_ip_header(user_ip, dst_ip, 6, len(tcp) + len(tls_data))
            writer.write_packet(eth + ip + tcp + tls_data)
            
            seq_base += 10000

    # 2. Generate HTTP Connections
    if args.http > 0:
        for _ in range(args.http):
            dst_ip, host = random.choice(HTTP_HOSTS)
            src_port = random.randint(49152, 65535)
            dst_port = 80
            
            # TCP SYN
            eth = create_ethernet_header(user_mac, gateway_mac)
            tcp = create_tcp_header(src_port, dst_port, seq_base, 0, 0x02)
            ip = create_ip_header(user_ip, dst_ip, 6, len(tcp))
            writer.write_packet(eth + ip + tcp)
            
            # HTTP Request
            http_data = create_http_request(host)
            tcp = create_tcp_header(src_port, dst_port, seq_base + 1, 1, 0x18)
            ip = create_ip_header(user_ip, dst_ip, 6, len(tcp) + len(http_data))
            writer.write_packet(eth + ip + tcp + http_data)
            
            seq_base += 10000

    # 3. Generate DNS Queries
    if args.dns > 0:
        dns_server = '8.8.8.8'
        for _ in range(args.dns):
            domain = random.choice(DNS_DOMAINS)
            src_port = random.randint(49152, 65535)
            
            dns_data = create_dns_query(domain)
            eth = create_ethernet_header(user_mac, gateway_mac)
            udp = create_udp_header(src_port, 53, len(dns_data))
            ip = create_ip_header(user_ip, dns_server, 17, len(udp) + len(dns_data))
            writer.write_packet(eth + ip + udp + dns_data)

    # 4. Generate Blocked IP Traffic
    if args.blocked_ip_packets > 0:
        blocked_source_ip = '192.168.1.50'
        dst_ip = '172.217.0.100'
        for _ in range(args.blocked_ip_packets):
            src_port = random.randint(49152, 65535)
            eth = create_ethernet_header('00:11:22:33:44:56', gateway_mac)
            tcp = create_tcp_header(src_port, 443, seq_base, 0, 0x02)
            ip = create_ip_header(blocked_source_ip, dst_ip, 6, len(tcp))
            writer.write_packet(eth + ip + tcp)
            seq_base += 1000

    writer.close()
    print(f"Generated customized PCAP at: {args.output}")

if __name__ == "__main__":
    main()
