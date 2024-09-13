import ipaddress
import warnings
from shared import flows  # Import flows from shared.py
from cryptography.utils import CryptographyDeprecationWarning
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

import argparse
import time
from scapy.all import sniff, rdpcap, IP, TCP, UDP, DNS, raw
from collections import defaultdict
from db_utils import init_db, store_packet_data, log_attack  # Import log_attack for DB logging
import queue
import threading

from detection import (
    detect_icmp_data_exfiltration, detect_excessive_dns_queries,
    detect_file_transfer_protocols, detect_http_covert_channel,
    detect_syn_flood, detect_dns_exfiltration, detect_port_scan, detect_traffic_anomalies
)

# Default thresholds and configurations
small_packet_threshold = 300  # Threshold for small packets (in bytes)
data_exfiltration_threshold = 1000000  # Threshold for large outbound transfers (in bytes)

# Tracking objects and flow tables
packet_queue = queue.Queue()
small_packet_tracker = defaultdict(list)  # Track small packets per flow
traffic_data = []  # Placeholder to track traffic for visualization in Flask UI
log_queue = queue.Queue()  # Queue for asynchronous logging

# Helper Functions
def log_to_file(log_file, message):
    """
    Add log messages to the log queue for asynchronous logging.
    """
    log_queue.put(f"{message}")

def _write_to_file(log_file_path):
    """
    Background thread to write logs from the queue to file.
    """
    with open(log_file_path, 'a') as log_file:
        while True:
            message = log_queue.get()
            if message == "STOP":
                break
            log_file.write(message.encode("cp1252", errors="replace").decode("cp1252") + "\n")
            log_file.flush()

# Start the logging thread
def start_logging_thread(log_file_path):
    logging_thread = threading.Thread(target=_write_to_file, args=(log_file_path,))
    logging_thread.start()
    return logging_thread

# Processing functions
def process_live_interface(interface, log_file):
    """
    Sniff live packets on a given network interface and process each packet.
    """
    sniff(iface=interface, prn=lambda pkt: process_packet(pkt, log_file))

def process_packet(packet, log_file):
    """
    Process an individual packet for analysis. Validates the packet, tracks flows, 
    checks for small packets, and runs intrusion detection checks.
    """
    # Check if the packet contains an IP layer
    if not IP in packet:
        log_to_file(log_file, "Packet dropped: Not an IP packet")
        return

    # Validate the IP layer
    is_valid, msg = validate_ip_packet(packet)
    if not is_valid:
        log_to_file(log_file, f"Packet dropped: {msg}")
        return

    # Validate TCP or UDP layer (if present)
    if TCP in packet:
        is_valid, msg = validate_tcp_packet(packet)
        if not is_valid:
            log_to_file(log_file, f"Packet dropped: {msg}")  # Log reason for dropping the packet
            return
    elif UDP in packet:
        is_valid, msg = validate_udp_packet(packet)
        if not is_valid:
            log_to_file(log_file, f"Packet dropped: {msg}")  # Log reason for dropping the packet
            return

    # Extract source IP, destination IP, protocol, and port numbers
    ip_layer = packet[IP]
    src_ip = ip_layer.src
    dst_ip = ip_layer.dst
    protocol = "TCP" if TCP in packet else "UDP" if UDP in packet else "Other"
    src_port = packet.sport if TCP in packet or UDP in packet else None
    dst_port = packet.dport if TCP in packet or UDP in packet else None
    flow_key = (src_ip, dst_ip, src_port, dst_port, protocol)  # 5-tuple representing the flow

    # Track small packets for each flow
    if len(packet) < small_packet_threshold:
        small_packet_tracker[flow_key].append(time.time())

    # Initialize the flow in flows if not present
    if flow_key not in flows:
        flows[flow_key] = {
            "bytes": 0,
            "packets": 0,
            "start_time": time.time(),
            "end_time": None
        }

    # Update flow information
    flows[flow_key]["bytes"] += len(packet)
    flows[flow_key]["packets"] += 1
    flows[flow_key]["end_time"] = time.time()

    # Log the flow data
    log_to_file(log_file, f"Flow: {flow_key}, Data Transferred: {flows[flow_key]['bytes']} bytes")

    # Detection calls for intrusion detection mechanisms
    detect_file_transfer_protocols(flow_key, log_file)
    process_dns_query(packet, log_file)
    detect_port_scan(src_ip, dst_port, time.time(), log_file)
    detect_syn_flood(packet, log_file)
    detect_http_covert_channel(packet, log_file)
    detect_icmp_data_exfiltration(packet, log_file)

    # Check for large outbound data transfer (possible data exfiltration)
    if flows[flow_key]["bytes"] > data_exfiltration_threshold:
        log_to_file(log_file, f"Potential Data Exfiltration Detected: Flow {flow_key}, Bytes transferred: {flows[flow_key]['bytes']}")
        log_attack("Data Exfiltration", f"Flow {flow_key} transferred {flows[flow_key]['bytes']} bytes")

    # Detect traffic anomalies based on historical averages
    detect_traffic_anomalies(flow_key, log_file)

    # Store the packet data
    store_packet_data(packet)

def process_dns_query(packet, log_file):
    """
    Process DNS queries to detect potential DNS tunneling or other suspicious behavior.
    """
    if DNS in packet:
        dns_layer = packet[DNS]
        if dns_layer.qdcount > 0 and dns_layer.qd is not None:
            decoding_issue = False
            try:
                for i in range(dns_layer.qdcount):
                    question = dns_layer.qd[i]
                    try:
                        query_name = question.qname.decode('utf-8')
                    except UnicodeDecodeError:
                        log_to_file(log_file, "Decoding issue: Non-ASCII character found in DNS query name.")
                        decoding_issue = True
            except Exception as e:
                log_to_file(log_file, f"Error processing DNS query: {str(e)}")

            detect_excessive_dns_queries(packet, log_file)
            detect_dns_exfiltration(packet, log_file)
            if decoding_issue:
                log_to_file(log_file, "Decoding issue: DNS tunneling detection proceeded with potential partial query.")
        else:
            log_to_file(log_file, "DNS packet dropped: No valid query domain found.")

def process_pcap_file(pcap_file, log_file):
    """
    Read packets from a PCAP file and process each one.
    """
    packets = rdpcap(pcap_file)  # Read packets from PCAP file
    for packet in packets:
        process_packet(packet, log_file)  # Pass the packet to process_packet

# Packet validation functions
def validate_ip_packet(packet):
    """
    Validate IP packet characteristics, checking version, fragment, and TTL.
    """
    if IP in packet:
        ip_layer = packet[IP]
        if ip_layer.version != 4 or ip_layer.ihl is None or ip_layer.ihl < 5 or ip_layer.frag is None or ip_layer.frag > 0 or ip_layer.ttl is None or ip_layer.ttl <= 0:
            return False, "Invalid IP packet characteristics"
        return True, "IP packet is valid"
    return False, "Not an IP packet"

def validate_tcp_packet(packet, check_checksum=False):
    """
    Validate the TCP layer of the packet. Optionally, check the checksum.
    """
    if TCP in packet:
        tcp_layer = packet[TCP]
        if not (0 <= tcp_layer.sport <= 65535 and 0 <= tcp_layer.dport <= 65535 and tcp_layer.flags in (0x02, 0x10, 0x18, 0x29)):
            return False, "Invalid TCP packet characteristics"
        return True, "TCP packet is valid"
    return False, "Not a TCP packet"

def validate_udp_packet(packet):
    """
    Validate the UDP layer of the packet.
    """
    if UDP in packet:
        udp_layer = packet[UDP]
        if not (0 <= udp_layer.sport <= 65535 and 0 <= udp_layer.dport <= 65535):
            return False, "Invalid UDP packet characteristics"
        return True, "UDP packet is valid"
    return False, "Not a UDP packet"

# Main function to handle command-line arguments
def main():
    init_db()  # Initialize the database
    parser = argparse.ArgumentParser(description="Intrusion Detection System")
    parser.add_argument('--pcapfile', type=str, help="PCAP file to analyze")
    parser.add_argument('--interface', type=str, help="Network interface to sniff on")
    parser.add_argument('--logfile', type=str, default="captured_packets.txt", help="Log file to store packet data")
    args = parser.parse_args()

    logging_thread = start_logging_thread(args.logfile)

    if args.pcapfile:
        process_pcap_file(args.pcapfile, args.logfile)
    elif args.interface:
        process_live_interface(args.interface, args.logfile)
    else:
        print("You must specify either --pcapfile or --interface.")

    # Gracefully stop the logging thread
    log_queue.put("STOP")
    logging_thread.join()

if __name__ == "__main__":
    main()
