#!/usr/bin/env python3
"""
DeepInsight DPI Engine
Python PCAP analyzer matching the C++ DeepInsight core logic, optimized for Windows out-of-the-box support.
"""

import sys
import os
import struct
import json
import argparse
import socket
from datetime import datetime

# App Classification Map
APP_TYPE_STRINGS = {
    "UNKNOWN": "Unknown",
    "HTTP": "HTTP",
    "HTTPS": "HTTPS",
    "DNS": "DNS",
    "TLS": "TLS",
    "QUIC": "QUIC",
    "GOOGLE": "Google",
    "FACEBOOK": "Facebook",
    "YOUTUBE": "YouTube",
    "TWITTER": "Twitter/X",
    "INSTAGRAM": "Instagram",
    "NETFLIX": "Netflix",
    "AMAZON": "Amazon",
    "MICROSOFT": "Microsoft",
    "APPLE": "Apple",
    "WHATSAPP": "WhatsApp",
    "TELEGRAM": "Telegram",
    "TIKTOK": "TikTok",
    "SPOTIFY": "Spotify",
    "ZOOM": "Zoom",
    "DISCORD": "Discord",
    "GITHUB": "GitHub",
    "CLOUDFLARE": "Cloudflare"
}

def sni_to_app_type(sni):
    if not sni:
        return "UNKNOWN"
    
    sni_lower = sni.lower()
    
    # YouTube (check first before Google)
    if any(k in sni_lower for k in ["youtube", "ytimg", "youtu.be", "yt3.ggpht"]):
        return "YOUTUBE"
        
    # Google
    if any(k in sni_lower for k in ["google", "gstatic", "googleapis", "ggpht", "gvt1"]):
        return "GOOGLE"
        
    # Facebook/Meta
    if any(k in sni_lower for k in ["facebook", "fbcdn", "fb.com", "fbsbx", "meta.com"]):
        return "FACEBOOK"
        
    # Instagram
    if any(k in sni_lower for k in ["instagram", "cdninstagram"]):
        return "INSTAGRAM"
        
    # WhatsApp
    if any(k in sni_lower for k in ["whatsapp", "wa.me"]):
        return "WHATSAPP"
        
    # Twitter/X
    if any(k in sni_lower for k in ["twitter", "twimg", "x.com", "t.co"]):
        return "TWITTER"
        
    # Netflix
    if any(k in sni_lower for k in ["netflix", "nflxvideo", "nflximg"]):
        return "NETFLIX"
        
    # Amazon
    if any(k in sni_lower for k in ["amazon", "amazonaws", "cloudfront", "aws"]):
        return "AMAZON"
        
    # Microsoft
    if any(k in sni_lower for k in ["microsoft", "msn.com", "office", "azure", "live.com", "outlook", "bing"]):
        return "MICROSOFT"
        
    # Apple
    if any(k in sni_lower for k in ["apple", "icloud", "mzstatic", "itunes"]):
        return "APPLE"
        
    # Telegram
    if any(k in sni_lower for k in ["telegram", "t.me"]):
        return "TELEGRAM"
        
    # TikTok
    if any(k in sni_lower for k in ["tiktok", "tiktokcdn", "musical.ly", "bytedance"]):
        return "TIKTOK"
        
    # Spotify
    if any(k in sni_lower for k in ["spotify", "scdn.co"]):
        return "SPOTIFY"
        
    # Zoom
    if "zoom" in sni_lower:
        return "ZOOM"
        
    # Discord
    if any(k in sni_lower for k in ["discord", "discordapp"]):
        return "DISCORD"
        
    # GitHub
    if any(k in sni_lower for k in ["github", "githubusercontent"]):
        return "GITHUB"
        
    # Cloudflare
    if any(k in sni_lower for k in ["cloudflare", "cf-"]):
        return "CLOUDFLARE"
        
    return "HTTPS"

class DPIEngine:
    def __init__(self, blocked_ips=None, blocked_apps=None, blocked_domains=None):
        self.blocked_ips = set(blocked_ips or [])
        self.blocked_apps = set(blocked_apps or [])
        self.blocked_domains = blocked_domains or []
        
        # Connection flows
        # Key: (src_ip, dst_ip, src_port, dst_port, protocol)
        self.flows = {}
        
        # Statistics
        self.total_packets = 0
        self.total_bytes = 0
        self.forwarded_packets = 0
        self.dropped_packets = 0
        self.tcp_packets = 0
        self.udp_packets = 0
        self.dns_packets = 0
        self.other_packets = 0

    def is_blocked(self, src_ip, app_type, sni):
        if src_ip in self.blocked_ips:
            return True
        if app_type in self.blocked_apps:
            return True
        for domain in self.blocked_domains:
            if sni and domain in sni:
                return True
        return False

    def parse_tls_sni(self, payload):
        """Extract Server Name Indication (SNI) from TLS Client Hello payload."""
        try:
            if len(payload) < 5:
                return None
                
            # Byte 0: Content Type = 0x16 (Handshake)
            # Byte 5: Handshake Type = 0x01 (Client Hello)
            if payload[0] != 0x16 or payload[5] != 0x01:
                return None
                
            # Skip to Session ID
            # Version (2 bytes), length (3 bytes), client version (2 bytes), random (32 bytes)
            # Offset is 43
            offset = 43
            if offset >= len(payload):
                return None
                
            session_id_len = payload[offset]
            offset += 1 + session_id_len
            
            # Cipher Suites
            if offset + 2 > len(payload):
                return None
            cipher_len = struct.unpack('>H', payload[offset:offset+2])[0]
            offset += 2 + cipher_len
            
            # Compression Methods
            if offset + 1 > len(payload):
                return None
            comp_len = payload[offset]
            offset += 1 + comp_len
            
            # Extensions
            if offset + 2 > len(payload):
                return None
            ext_len = struct.unpack('>H', payload[offset:offset+2])[0]
            offset += 2
            
            ext_end = offset + ext_len
            while offset + 4 <= ext_end and offset + 4 <= len(payload):
                ext_type = struct.unpack('>H', payload[offset:offset+2])[0]
                ext_data_len = struct.unpack('>H', payload[offset+2:offset+4])[0]
                offset += 4
                
                if ext_type == 0x0000: # SNI Extension
                    if offset + 5 > len(payload):
                        return None
                    # SNI List length (2 bytes), SNI Type (1 byte, 0 = host_name), SNI length (2 bytes)
                    sni_type = payload[offset+2]
                    if sni_type == 0x00:
                        sni_len = struct.unpack('>H', payload[offset+3:offset+5])[0]
                        if offset + 5 + sni_len <= len(payload):
                            return payload[offset+5:offset+5+sni_len].decode('ascii', errors='ignore')
                
                offset += ext_data_len
        except Exception:
            pass
        return None

    def parse_http_host(self, payload):
        """Extract Host header from HTTP plain payload."""
        try:
            if len(payload) < 10:
                return None
                
            # Check for HTTP method (GET, POST, etc.)
            methods = [b'GET ', b'POST', b'HEAD', b'PUT ', b'OPTI', b'DELE']
            if not any(payload.startswith(m) for m in methods):
                return None
                
            text = payload.decode('utf-8', errors='ignore')
            lines = text.split('\r\n')
            for line in lines:
                if line.lower().startswith('host:'):
                    parts = line.split(':', 1)
                    if len(parts) > 1:
                        host = parts[1].strip()
                        # Remove port number if exists
                        if ':' in host:
                            host = host.split(':', 1)[0]
                        return host
        except Exception:
            pass
        return None

    def process_pcap(self, input_file, output_file=None):
        try:
            infile = open(input_file, 'rb')
        except IOError as e:
            print(f"Error opening input file: {e}", file=sys.stderr)
            return False

        outfile = None
        if output_file:
            try:
                outfile = open(output_file, 'wb')
            except IOError as e:
                print(f"Error opening output file: {e}", file=sys.stderr)
                infile.close()
                return False

        # Read Global Header
        global_header = infile.read(24)
        if len(global_header) < 24:
            print("Invalid PCAP: Global header too short.", file=sys.stderr)
            infile.close()
            return False
            
        magic = struct.unpack('<I', global_header[0:4])[0]
        swap_bytes = False
        if magic == 0xd4c3b2a1:
            swap_bytes = True
        elif magic != 0xa1b2c3d4:
            print("Invalid PCAP: Magic number mismatch.", file=sys.stderr)
            infile.close()
            if outfile: outfile.close()
            return False

        if outfile:
            outfile.write(global_header)

        # Process packet by packet
        packet_idx = 0
        while True:
            pkt_hdr = infile.read(16)
            if len(pkt_hdr) < 16:
                break
                
            packet_idx += 1
            if swap_bytes:
                ts_sec, ts_usec, incl_len, orig_len = struct.unpack('>IIII', pkt_hdr)
            else:
                ts_sec, ts_usec, incl_len, orig_len = struct.unpack('<IIII', pkt_hdr)

            pkt_data = infile.read(incl_len)
            if len(pkt_data) < incl_len:
                break
                
            self.total_packets += 1
            self.total_bytes += incl_len

            # Protocol parsing
            # Ethernet header (14 bytes)
            if len(pkt_data) < 14:
                self.other_packets += 1
                if outfile:
                    outfile.write(pkt_hdr)
                    outfile.write(pkt_data)
                self.forwarded_packets += 1
                continue

            dest_mac = ":".join(f"{b:02x}" for b in pkt_data[0:6])
            src_mac = ":".join(f"{b:02x}" for b in pkt_data[6:12])
            ethertype = struct.unpack('>H', pkt_data[12:14])[0]

            if ethertype != 0x0800: # Not IPv4
                self.other_packets += 1
                if outfile:
                    outfile.write(pkt_hdr)
                    outfile.write(pkt_data)
                self.forwarded_packets += 1
                continue

            # IP header
            ip_offset = 14
            if len(pkt_data) < ip_offset + 20:
                self.other_packets += 1
                if outfile:
                    outfile.write(pkt_hdr)
                    outfile.write(pkt_data)
                self.forwarded_packets += 1
                continue

            version_ihl = pkt_data[ip_offset]
            ihl = (version_ihl & 0x0F) * 4
            protocol = pkt_data[ip_offset + 9]
            
            src_ip = socket.inet_ntoa(pkt_data[ip_offset + 12 : ip_offset + 16])
            dst_ip = socket.inet_ntoa(pkt_data[ip_offset + 16 : ip_offset + 20])

            transport_offset = ip_offset + ihl
            if len(pkt_data) < transport_offset:
                self.other_packets += 1
                if outfile:
                    outfile.write(pkt_hdr)
                    outfile.write(pkt_data)
                self.forwarded_packets += 1
                continue

            src_port = 0
            dst_port = 0
            payload_offset = transport_offset
            
            is_tcp_udp = False

            if protocol == 6: # TCP
                self.tcp_packets += 1
                is_tcp_udp = True
                if len(pkt_data) < transport_offset + 20:
                    continue
                src_port, dst_port = struct.unpack('>HH', pkt_data[transport_offset : transport_offset + 4])
                tcp_flags = pkt_data[transport_offset + 13]
                data_offset = ((pkt_data[transport_offset + 12] >> 4) & 0x0F) * 4
                payload_offset = transport_offset + data_offset
            elif protocol == 17: # UDP
                self.udp_packets += 1
                is_tcp_udp = True
                if len(pkt_data) < transport_offset + 8:
                    continue
                src_port, dst_port = struct.unpack('>HH', pkt_data[transport_offset : transport_offset + 4])
                payload_offset = transport_offset + 8

            if not is_tcp_udp:
                self.other_packets += 1
                if outfile:
                    outfile.write(pkt_hdr)
                    outfile.write(pkt_data)
                self.forwarded_packets += 1
                continue

            payload = pkt_data[payload_offset:]
            payload_len = len(payload)

            # Flow key
            flow_key = (src_ip, dst_ip, src_port, dst_port, protocol)
            
            # Flow management (check bidirectional match)
            rev_key = (dst_ip, src_ip, dst_port, src_port, protocol)
            if flow_key in self.flows:
                flow = self.flows[flow_key]
                direction = "OUT"
            elif rev_key in self.flows:
                flow = self.flows[rev_key]
                direction = "IN"
            else:
                # Create new flow
                flow = {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "protocol": "TCP" if protocol == 6 else "UDP",
                    "app_type": "UNKNOWN",
                    "sni": "",
                    "packets": 0,
                    "bytes": 0,
                    "blocked": False,
                    "first_seen": ts_sec + ts_usec / 1000000.0,
                    "last_seen": ts_sec + ts_usec / 1000000.0,
                    "packet_details": [] # Track first few packets metadata
                }
                self.flows[flow_key] = flow
                direction = "OUT"

            flow["packets"] += 1
            flow["bytes"] += incl_len
            flow["last_seen"] = ts_sec + ts_usec / 1000000.0

            # Store brief packet metadata (limit to 8 packets per connection for performance)
            if len(flow["packet_details"]) < 8:
                # Create a small hex dump representation (up to 48 bytes) of payload
                hex_dump = ""
                if payload_len > 0:
                    limit_len = min(payload_len, 48)
                    hex_dump = " ".join(f"{b:02x}" for b in payload[:limit_len])
                    if payload_len > limit_len:
                        hex_dump += " ..."
                        
                flow["packet_details"].append({
                    "time": ts_sec + ts_usec / 1000000.0,
                    "dir": direction,
                    "size": incl_len,
                    "payload_len": payload_len,
                    "hex": hex_dump
                })

            # Deep Packet Inspection (DPI)
            # Try TLS SNI
            if flow["app_type"] in ["UNKNOWN", "HTTPS"] and not flow["sni"] and dst_port == 443 and protocol == 6:
                sni = self.parse_tls_sni(payload)
                if sni:
                    flow["sni"] = sni
                    flow["app_type"] = sni_to_app_type(sni)

            # Try HTTP Host
            if flow["app_type"] in ["UNKNOWN", "HTTP"] and not flow["sni"] and dst_port == 80 and protocol == 6:
                host = self.parse_http_host(payload)
                if host:
                    flow["sni"] = host
                    flow["app_type"] = sni_to_app_type(host)

            # DNS classification
            if flow["app_type"] == "UNKNOWN" and (dst_port == 53 or src_port == 53):
                flow["app_type"] = "DNS"
                self.dns_packets += 1
                # Try simple DNS name parsing
                if payload_len > 12:
                    try:
                        # Extract query names (simple label extraction)
                        q_offset = 12
                        domains = []
                        while q_offset < payload_len:
                            label_len = payload[q_offset]
                            if label_len == 0:
                                break
                            if q_offset + 1 + label_len > payload_len:
                                break
                            label = payload[q_offset+1 : q_offset+1+label_len].decode('ascii', errors='ignore')
                            domains.append(label)
                            q_offset += 1 + label_len
                        if domains:
                            flow["sni"] = ".".join(domains)
                    except Exception:
                        pass

            # Port fallbacks
            if flow["app_type"] == "UNKNOWN":
                if dst_port == 443 or src_port == 443:
                    flow["app_type"] = "HTTPS"
                elif dst_port == 80 or src_port == 80:
                    flow["app_type"] = "HTTP"

            # Apply Rules on flow
            if not flow["blocked"]:
                flow["blocked"] = self.is_blocked(flow["src_ip"], flow["app_type"], flow["sni"])

            # Filter/forward decision
            if flow["blocked"]:
                self.dropped_packets += 1
            else:
                self.forwarded_packets += 1
                if outfile:
                    outfile.write(pkt_hdr)
                    outfile.write(pkt_data)

        infile.close()
        if outfile:
            outfile.close()
        return True

    def export_report(self, json_path=None):
        # Format flow statistics
        flow_list = []
        app_stats = {}
        
        for key, flow in self.flows.items():
            app = flow["app_type"]
            app_stats[app] = app_stats.get(app, 0) + flow["packets"]
            
            # Readable protocol name
            proto = "TCP" if key[4] == 6 else "UDP" if key[4] == 17 else str(key[4])
            
            # Format datetime
            first_seen_str = datetime.fromtimestamp(flow["first_seen"]).strftime('%H:%M:%S.%f')[:-3]
            
            flow_list.append({
                "key": f"{flow['src_ip']}:{flow['src_port']} -> {flow['dst_ip']}:{flow['dst_port']} ({proto})",
                "src_ip": flow["src_ip"],
                "dst_ip": flow["dst_ip"],
                "src_port": flow["src_port"],
                "dst_port": flow["dst_port"],
                "protocol": proto,
                "app": APP_TYPE_STRINGS.get(app, app),
                "app_raw": app,
                "sni": flow["sni"],
                "packets": flow["packets"],
                "bytes": flow["bytes"],
                "blocked": flow["blocked"],
                "time": first_seen_str,
                "packets_list": flow["packet_details"]
            })

        # Calculate percentages
        app_breakdown = []
        for app, count in app_stats.items():
            pct = (count / self.total_packets * 100.0) if self.total_packets > 0 else 0.0
            app_breakdown.append({
                "app": APP_TYPE_STRINGS.get(app, app),
                "app_raw": app,
                "count": count,
                "percentage": round(pct, 1)
            })
            
        app_breakdown.sort(key=lambda x: x["count"], reverse=True)

        report = {
            "summary": {
                "total_packets": self.total_packets,
                "total_bytes": self.total_bytes,
                "forwarded_packets": self.forwarded_packets,
                "dropped_packets": self.dropped_packets,
                "tcp_packets": self.tcp_packets,
                "udp_packets": self.udp_packets,
                "dns_packets": self.dns_packets,
                "other_packets": self.other_packets,
                "active_flows": len(self.flows)
            },
            "app_breakdown": app_breakdown,
            "flows": flow_list
        }

        if json_path:
            with open(json_path, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"Report exported to: {json_path}")
            
        return report

def main():
    parser = argparse.ArgumentParser(description="DeepInsight Packet Analysis DPI Engine")
    parser.add_argument("input_pcap", help="Input PCAP file to read")
    parser.add_argument("output_pcap", nargs="?", default=None, help="Output PCAP file to write filtered traffic")
    parser.add_argument("--json-report", help="Path to write JSON analysis report")
    parser.add_argument("--block-ip", action="append", default=[], help="Block a source IP address")
    parser.add_argument("--block-app", action="append", default=[], help="Block an app classification (e.g. YOUTUBE, FACEBOOK)")
    parser.add_argument("--block-domain", action="append", default=[], help="Block any domain containing this substring")

    args = parser.parse_args()

    # Normalize app names
    blocked_apps = [app.upper() for app in args.block_app]

    print("=========================================")
    print("      DEEPINSIGHT DPI ENGINE v1.0")
    print("=========================================")
    print(f"Input file:  {args.input_pcap}")
    if args.output_pcap:
        print(f"Output file: {args.output_pcap}")
    if args.block_ip:
        print(f"Blocked IPs: {args.block_ip}")
    if blocked_apps:
        print(f"Blocked Apps: {blocked_apps}")
    if args.block_domain:
        print(f"Blocked Domains: {args.block_domain}")
    print("-----------------------------------------")

    engine = DPIEngine(
        blocked_ips=args.block_ip,
        blocked_apps=blocked_apps,
        blocked_domains=args.block_domain
    )

    success = engine.process_pcap(args.input_pcap, args.output_pcap)
    if success:
        print("\nProcessing completed successfully.")
        report = engine.export_report(args.json_report)
        
        sum_data = report["summary"]
        print("\nSUMMARY REPORT:")
        print(f"  Total Packets:     {sum_data['total_packets']}")
        print(f"  Total Bytes:       {sum_data['total_bytes']}")
        print(f"  Forwarded Packets: {sum_data['forwarded_packets']}")
        print(f"  Dropped Packets:   {sum_data['dropped_packets']}")
        print(f"  Active Flows:      {sum_data['active_flows']}")
        
        print("\nAPPLICATION BREAKDOWN:")
        for app in report["app_breakdown"]:
            bar = "#" * int(app['percentage'] / 5)
            print(f"  {app['app']:<15} {app['count']:<8} {app['percentage']:>5}%  {bar}")
    else:
        print("\nProcessing failed.", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
