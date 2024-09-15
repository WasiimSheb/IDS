import os
import sys
import traceback
import warnings
import signal
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
    detect_syn_flood, detect_dns_exfiltration, detect_port_scan, detect_traffic_anomalies,
    detect_slowloris, detect_dns_amplification
)

# Default thresholds and configurations
small_packet_threshold = 300  # Threshold for small packets (in bytes)
data_exfiltration_threshold = 1000000  # Threshold for large outbound transfers (in bytes)

# Tracking objects and flow tables
packet_queue = queue.Queue()
small_packet_tracker = defaultdict(list)  # Track small packets per flow
traffic_data = []  # Placeholder to track traffic for visualization in Flask UI
log_queue = queue.Queue()  # Queue for asynchronous logging

# Buffer for batched log messages
log_buffer = []

# Helper Functions
def log_to_file(log_file, message, level="INFO"):
    """
    Log messages with levels (INFO, WARNING, ERROR) and batch log to file.
    """
    formatted_message = f"[{level}] {message}"
    log_buffer.append(formatted_message + "\n")
    if len(log_buffer) >= 10:  # Batch flush every 10 messages
        flush_logs(log_file)

def flush_logs(log_file):
    """
    Flush the buffered log messages to the log file.
    """
    if isinstance(log_file, str):
        with open(log_file, 'a') as f:
            f.writelines(log_buffer)
    else:
        log_file.writelines(log_buffer)
    log_file.flush()
    log_buffer.clear()

def _write_to_file(log_file_path):
    """
    Background thread to write logs from the queue to file.
    """
    with open(log_file_path, 'a') as log_file:
        while True:
            message = log_queue.get()
            if message == "STOP":
                break
            log_file.write(message + "\n")
            log_file.flush()

# Start the logging thread
def start_logging_thread(log_file_path):
    logging_thread = threading.Thread(target=_write_to_file, args=(log_file_path,))
    logging_thread.start()
    return logging_thread

# Signal handler for graceful shutdown
def handle_signal(signal_received, frame):
    print("Signal received, shutting down gracefully...")
    log_queue.put("STOP")
    sys.exit(0)

signal.signal(signal.SIGINT, handle_signal)
signal.signal(signal.SIGTERM, handle_signal)

# Processing functions
def process_live_interface(interface, log_file):
    """
    Sniff live packets on a given network interface and process each packet.
    """
    sniff(iface=interface, prn=lambda pkt: process_packet(pkt, log_file))



def process_packet(packet, log_file):
    """
    Process an individual packet for analysis, including flow tracking, detection mechanisms, and flow expiration.
    """

    try:
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

        # Extract flow information
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
        detect_slowloris(packet, log_file)
        detect_dns_amplification(packet, log_file)

        # Check for large outbound data transfer (possible data exfiltration)
        if flows[flow_key]["bytes"] > data_exfiltration_threshold:
            log_to_file(log_file, f"Potential Data Exfiltration Detected: Flow {flow_key}, Bytes transferred: {flows[flow_key]['bytes']}")
            log_attack("Data Exfiltration", f"Flow {flow_key} transferred {flows[flow_key]['bytes']} bytes")

        # Detect traffic anomalies based on historical averages
        detect_traffic_anomalies(flow_key, log_file)

        store_packet_data(packet)  # Store packet data in the database


    except Exception as e:
        # Capture any unexpected errors and log them for future analysis
        log_to_file(log_file, f"Error processing packet: {str(e)}")

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
                        log_to_file(log_file, "Decoding issue: Non-ASCII character found in DNS query name.", level="WARNING")
                        decoding_issue = True
            except Exception as e:
                log_to_file(log_file, f"Error processing DNS query: {str(e)}", level="ERROR")

            detect_excessive_dns_queries(packet, log_file)
            detect_dns_exfiltration(packet, log_file)
            if decoding_issue:
                log_to_file(log_file, "Decoding issue: DNS tunneling detection proceeded with potential partial query.", level="WARNING")
        else:
            log_to_file(log_file, "DNS packet dropped: No valid query domain found.", level="WARNING")

def process_pcap_file(pcap_file, log_file):
    """
    Read packets from a PCAP file and process each one.
    """
    try:
        packets = rdpcap(pcap_file)  # Read packets from PCAP file
        for packet in packets:
            process_packet(packet, log_file)  # Pass the packet to process_packet
    except FileNotFoundError:
        log_to_file(log_file, f"Error: PCAP file '{pcap_file}' not found.", level="ERROR")
    except Exception as e:
        log_to_file(log_file, f"Error reading PCAP file '{pcap_file}': {e}", level="ERROR")
        traceback.print_exc()

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

        # Check port validity and flags
        if not (0 <= tcp_layer.sport <= 65535 and 0 <= tcp_layer.dport <= 65535 and tcp_layer.flags in (0x02, 0x10, 0x18, 0x29)):
            return False, "Invalid TCP packet characteristics"

        if check_checksum:
            # Use Scapy's built-in function to calculate the correct checksum for TCP
            correct_checksum = packet[TCP].chksum
            packet[TCP].chksum = None  # Clear the checksum to force recalculation
            calculated_checksum = TCP(bytes(packet)).chksum

            # Now compare the manually set checksum against the recalculated one
            if correct_checksum != calculated_checksum:
                return False, "Invalid TCP checksum"

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

# Main function
def main():
    try:
        # Initialize the database with error handling
        try:
            init_db()
        except Exception as db_error:
            print(f"Error initializing the database: {db_error}")
            sys.exit(1)

        # Argument parsing with error handling
        parser = argparse.ArgumentParser(description="Intrusion Detection System")
        parser.add_argument('--pcapfile', type=str, help="PCAP file to analyze")
        parser.add_argument('--interface', type=str, help="Network interface to sniff on")
        parser.add_argument('--logfile', type=str, default="captured_packets.txt", help="Log file to store packet data")
        args = parser.parse_args()

        # Start the logging thread with error handling
        try:
            logging_thread = start_logging_thread(args.logfile)
        except Exception as log_thread_error:
            print(f"Error starting logging thread: {log_thread_error}")
            sys.exit(1)

        # Open log file in append mode
        try:
            with open(args.logfile, "a") as log_file:
                # Process the PCAP file if specified
                if args.pcapfile:
                    if not os.path.exists(args.pcapfile):
                        print(f"Error: PCAP file '{args.pcapfile}' does not exist.")
                        sys.exit(1)
                    try:
                        process_pcap_file(args.pcapfile, log_file)
                    except Exception as pcap_error:
                        print(f"Error processing PCAP file '{args.pcapfile}': {pcap_error}")
                        traceback.print_exc()
                        sys.exit(1)
                
                # Sniff live network traffic if an interface is specified
                elif args.interface:
                    try:
                        process_live_interface(args.interface, log_file)
                    except Exception as iface_error:
                        print(f"Error processing network interface '{args.interface}': {iface_error}")
                        traceback.print_exc()
                        sys.exit(1)
                
                else:
                    print("You must specify either --pcapfile or --interface.")
                    sys.exit(1)

        except OSError as file_error:
            print(f"Error opening log file '{args.logfile}': {file_error}")
            sys.exit(1)

        # Gracefully stop the logging thread
        log_queue.put("STOP")
        logging_thread.join()

    except Exception as unexpected_error:
        # Catch any unexpected exceptions and print the stack trace
        print(f"An unexpected error occurred: {unexpected_error}")
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
