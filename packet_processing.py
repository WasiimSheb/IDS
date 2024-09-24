import queue
import time
from scapy.all import IP, TCP, UDP, DNS
from collections import defaultdict
from packet_validation import validate_ip_packet, validate_tcp_packet, validate_udp_packet
from logging_utils import log_to_file
from detection import (
    detect_file_transfer_protocols, detect_port_scan, detect_syn_flood,
    detect_http_covert_channel, detect_icmp_data_exfiltration, detect_slowloris,
    detect_dns_amplification, detect_excessive_dns_queries, detect_dns_exfiltration, detect_traffic_anomalies
)
from db_utils import store_packet_data, log_attack  # Database function for storing packet data and logging attacks
from shared import flows

# Default thresholds
small_packet_threshold = 300  # Threshold for small packets (in bytes)
data_exfiltration_threshold = 1000000  # Threshold for large outbound transfers (in bytes)

# Trackers
small_packet_tracker = defaultdict(list)  # Track small packets per flow
traffic_data = []  # Placeholder to track traffic for visualization
log_queue = queue.Queue()  # Queue for asynchronous logging

# Helper Functions
def process_packet(packet, log_file):
    """
    Process an individual packet for analysis, including flow tracking, detection mechanisms, and flow expiration.
    """
    try:
        if not IP in packet:
            log_to_file(log_file, "Packet dropped: Not an IP packet")
            return

        is_valid, msg = validate_ip_packet(packet)
        if not is_valid:
            log_to_file(log_file, f"Packet dropped: {msg}")
            return

        if TCP in packet:
            is_valid, msg = validate_tcp_packet(packet)
            if not is_valid:
                log_to_file(log_file, f"Packet dropped: {msg}")
                return
        elif UDP in packet:
            is_valid, msg = validate_udp_packet(packet)
            if not is_valid:
                log_to_file(log_file, f"Packet dropped: {msg}")
                return

        # Extract flow information
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = "TCP" if TCP in packet else "UDP" if UDP in packet else "Other"
        src_port = packet.sport if TCP in packet or UDP in packet else None
        dst_port = packet.dport if TCP in packet or UDP in packet else None
        flow_key = (src_ip, dst_ip, src_port, dst_port, protocol)

        # Track small packets
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

        # Store packet data in the database
        store_packet_data(packet)

    except Exception as e:
        # Log any errors that occur during packet processing
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
