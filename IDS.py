import ipaddress
import warnings
from cryptography.utils import CryptographyDeprecationWarning
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

import argparse
import time
from scapy.all import sniff, rdpcap, IP, TCP, UDP, ICMP, DNS
from collections import defaultdict
import queue

from detection import (
    detect_icmp_data_exfiltration, detect_excessive_dns_queries,
    detect_file_transfer_protocols, detect_http_covert_channel,
    detect_syn_flood, detect_dns_exfiltration, detect_port_scan
)

# Default thresholds and configurations
small_packet_threshold = 300  # Threshold for small packets (in bytes)

# Tracking objects and flow tables
packet_queue = queue.Queue()
small_packet_tracker = defaultdict(list)  # Track small packets
flows = {}  # Store flow information

# Helper Functions
def log_to_file(log_file, message):
    """Logging utility that handles unencodable characters."""
    log_file.write(message.encode("cp1252", errors="replace").decode("cp1252") + "\n")
    log_file.flush()

# Processing functions
def process_live_interface(interface, log_file):
    sniff(iface=interface, prn=lambda pkt: process_packet(pkt, log_file))

def process_packet(packet, log_file):
    is_valid, msg = validate_ip_packet(packet)
    if not is_valid:
        log_to_file(log_file, f"Packet dropped: {msg}")
        return

    if TCP in packet:
        is_valid, msg = validate_tcp_packet(packet)
    elif UDP in packet:
        is_valid, msg = validate_udp_packet(packet)

    if not is_valid:
        log_to_file(log_file, f"Packet dropped: {msg}")
        return

    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = "TCP" if TCP in packet else "UDP" if UDP in packet else "Other"
        src_port = packet.sport if TCP in packet or UDP in packet else None
        dst_port = packet.dport if TCP in packet or UDP in packet else None
        flow_key = (src_ip, dst_ip, src_port, dst_port, protocol)

        if len(packet) < small_packet_threshold:
            small_packet_tracker[flow_key].append(time.time())

        if flow_key not in flows:
            flows[flow_key] = {"bytes": len(packet), "packets": 1, "start_time": time.time()}
        else:
            flows[flow_key]["bytes"] += len(packet)
            flows[flow_key]["packets"] += 1

        log_to_file(log_file, f"Flow: {flow_key}, Data Transferred: {flows[flow_key]['bytes']} bytes")

        # Detection calls
        detect_file_transfer_protocols(flow_key, log_file)
        if DNS in packet:
            detect_excessive_dns_queries(packet, log_file)
            detect_dns_exfiltration(packet, log_file)
        detect_port_scan(src_ip, dst_port, time.time(), log_file)
        detect_syn_flood(packet, log_file)
        detect_http_covert_channel(packet, log_file)
        detect_icmp_data_exfiltration(packet, log_file)

def process_pcap_file(pcap_file, log_file):
    packets = rdpcap(pcap_file)
    for packet in packets:
        process_packet(packet, log_file)

# Packet validation functions
def validate_ip_packet(packet):
    if IP in packet:
        ip_layer = packet[IP]
        if ip_layer.version != 4 or ip_layer.ihl < 5 or ip_layer.frag > 0 or ip_layer.ttl <= 0:
            return False, "Invalid IP packet characteristics"
        return True, "IP packet is valid"
    return False, "Not an IP packet"

def validate_tcp_packet(packet):
    if TCP in packet:
        tcp_layer = packet[TCP]
        if not (0 <= tcp_layer.sport <= 65535 and 0 <= tcp_layer.dport <= 65535 and tcp_layer.flags in (0x02, 0x10, 0x18, 0x29)):
            return False, "Invalid TCP packet characteristics"
        return True, "TCP packet is valid"
    return False, "Not a TCP packet"

def validate_udp_packet(packet):
    if UDP in packet:
        udp_layer = packet[UDP]
        if not (0 <= udp_layer.sport <= 65535 and 0 <= udp_layer.dport <= 65535):
            return False, "Invalid UDP packet characteristics"
        return True, "UDP packet is valid"
    return False, "Not a UDP packet"

# Main function
def main():
    parser = argparse.ArgumentParser(description="Intrusion Detection System")
    parser.add_argument('--pcapfile', type=str, help="PCAP file to analyze")
    parser.add_argument('--interface', type=str, help="Network interface to sniff on")
    parser.add_argument('--logfile', type=str, default="captured_packets.txt", help="Log file to store packet data")
    args = parser.parse_args()

    with open(args.logfile, "w") as log_file:
        if args.pcapfile:
            process_pcap_file(args.pcapfile, log_file)
        elif args.interface:
            process_live_interface(args.interface, log_file)
        else:
            print("You must specify either --pcapfile or --interface.")

if __name__ == "__main__":
    main()
