import time
import chardet
import json
from collections import defaultdict, deque  # Import deque
import ipaddress
from db_utils import log_attack
from shared import flows  # Import flows from shared.py
from scapy.all import IP, TCP, UDP, ICMP, DNS

# Trackers to hold state information for ICMP, DNS, SYN flood, and port scans
icmp_tracker = defaultdict(lambda: deque(maxlen=100))  # Track the last 100 ICMP packets
dns_tracker = defaultdict(lambda: deque(maxlen=100))   # Track the last 100 DNS queries per IP
syn_flood_tracker = defaultdict(int)
scanning_ips = {}
traffic_history = defaultdict(lambda: deque(maxlen=10))  # Track up to the last 10 traffic stats per IP
dns_amplification_tracker = defaultdict(list)
DNS_AMP_THRESHOLD = 5  # Track at least 5 DNS responses to detect amplification
slowloris_tracker = defaultdict(int)
SLOWLORIS_THRESHOLD = 50  # Customize this based on the network environment

# Time window for tracking port scan activity
port_scan_time_window = 60  # 60 seconds

# Configuration for detection thresholds
DETECTION_CONFIG = {
    "icmp_payload_threshold": 500,
    "icmp_time_window": 60,
    "icmp_packet_threshold": 100,
    "icmp_total_data_threshold": 20000,
    "syn_flood_threshold": 100,
    "dns_query_threshold": 100,
    "dns_time_window": 60,
    "user_agent_length_threshold": 30,
    "port_scan_threshold": 10,
    "port_scan_time_window": 60,
    "query_length_threshold": 50,
}

# Helper functions
def log_to_file(log_file, message, attack_type=None):
    """
    Log messages to the file, handling special encoding issues.
    Logs can be in structured JSON format to include metadata like attack types.
    """
    log_entry = {
        "message": message,
        "timestamp": time.time(),
        "attack_type": attack_type
    }
    log_file.write(json.dumps(log_entry) + "\n")
    log_file.flush()

def log_attack_and_file(log_file, message, attack_type):
    """
    Helper function to log an attack to both the log file and the database.
    """
    log_to_file(log_file, message, attack_type)
    log_attack(attack_type, message)

def is_internal_ip(ip):
    """Determine if the IP address is private (internal)."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        return False

def is_external_ip(ip):
    """Determine if the IP address is external (non-private)."""
    return not is_internal_ip(ip)

# Detection Functions
def detect_icmp_data_exfiltration(packet, log_file):
    """Detect ICMP-based data exfiltration."""
    config = DETECTION_CONFIG
    if ICMP in packet:
        payload_size = len(packet[ICMP].payload)
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        timestamp = time.time()

        if is_internal_ip(src_ip) and is_external_ip(dst_ip):
            flow_key = (src_ip, dst_ip)
            icmp_tracker[flow_key].append((payload_size, timestamp))

            # Clean up old ICMP traffic data
            icmp_tracker[flow_key] = [(size, ts) for size, ts in icmp_tracker[flow_key] if timestamp - ts < config['icmp_time_window']]

            total_data_sent = sum(size for size, _ in icmp_tracker[flow_key])
            packet_count = len(icmp_tracker[flow_key])

            if packet_count > config['icmp_packet_threshold']:
                message = f"Suspicious ICMP traffic: {packet_count} packets from {src_ip} to {dst_ip} in {config['icmp_time_window']} seconds."
                log_attack_and_file(log_file, message, "ICMP Data Exfiltration")
            if total_data_sent > config['icmp_total_data_threshold']:
                message = f"Suspicious ICMP traffic: {total_data_sent} bytes from {src_ip} to {dst_ip} in {config['icmp_time_window']} seconds."
                log_attack_and_file(log_file, message, "ICMP Data Exfiltration")
            if payload_size > config['icmp_payload_threshold']:
                message = f"Suspicious ICMP traffic: Large packet ({payload_size} bytes) from {src_ip} to {dst_ip}."
                log_attack_and_file(log_file, message, "ICMP Data Exfiltration")

def detect_excessive_dns_queries(packet, log_file):
    """Detect excessive DNS queries in a short time window."""
    config = DETECTION_CONFIG
    if DNS in packet and packet[DNS].qd:
        query_raw = packet[DNS].qd.qname
        detected_encoding = chardet.detect(query_raw)
        encoding = detected_encoding.get('encoding', 'utf-8')

        message = f"Detected DNS Query: {query_raw} with encoding {encoding}"
        log_attack_and_file(log_file, message, "DNS Query")

        try:
            # Try decoding the query name with detected encoding
            query = query_raw.decode(encoding)
            message = f"Decoded DNS Query: {query}"
            log_attack_and_file(log_file, message, "DNS Query")
        except (UnicodeDecodeError, TypeError):
            # If decoding fails, decode with 'utf-8' and log the issue
            query = query_raw.decode('utf-8', errors="replace")
            log_to_file(log_file, "Decoding issue: Non-ASCII character found in DNS query name.")
            message = f"Replaced non-ASCII DNS Query: {query}"
            log_attack_and_file(log_file, message, "DNS Query")

        src_ip = packet[IP].src
        dns_tracker[src_ip].append(time.time())

        # Clean up old DNS queries
        dns_tracker[src_ip] = [t for t in dns_tracker[src_ip] if time.time() - t < config['dns_time_window']]

        # Log excessive DNS queries if threshold is exceeded
        if len(dns_tracker[src_ip]) > config['dns_query_threshold']:
            message = f"Excessive DNS Queries Detected: {src_ip} made {len(dns_tracker[src_ip])} DNS queries in {config['dns_time_window']} seconds."
            log_attack_and_file(log_file, message, "DNS Query")

def detect_file_transfer_protocols(flow_key, log_file):
    """Detect unauthorized file transfers (e.g., FTP, SFTP)."""
    src_ip, dst_ip, src_port, dst_port, protocol = flow_key
    if protocol == "TCP" and (dst_port in [21, 22] or src_port in [21, 22]):
        message = f"Unauthorized File Transfer Detected: {src_ip} to {dst_ip}. File transfer protocol on port {dst_port if dst_port in [21, 22] else src_port}"
        log_attack_and_file(log_file, message, "File Transfer")

def detect_http_covert_channel(packet, log_file):
    """Detect covert channels through HTTP headers."""
    config = DETECTION_CONFIG
    if TCP in packet and packet[TCP].dport == 80:  # HTTP typically runs over TCP port 80
        payload = bytes(packet[TCP].payload)
        try:
            http_data = payload.decode('utf-8', errors='ignore')
        except UnicodeDecodeError:
            return  # If we can't decode the payload, skip this packet

        if "User-Agent" in http_data:
            user_agent_start = http_data.find("User-Agent:") + len("User-Agent:")
            user_agent_end = http_data.find("\r\n", user_agent_start)
            user_agent_value = http_data[user_agent_start:user_agent_end].strip()

            if len(user_agent_value) > config['user_agent_length_threshold']:
                message = f"Intrusion Detected: HTTP Covert Channel Detected in User-Agent: {user_agent_value}"
                log_attack_and_file(log_file, message, "HTTP Covert Channel")

def detect_syn_flood(packet, log_file):
    """Detect SYN flood attacks."""
    config = DETECTION_CONFIG
    if TCP in packet and (packet[TCP].flags & 0x12 == 0x02):  # SYN set, ACK not set
        src_ip = packet[IP].src
        syn_flood_tracker[src_ip] += 1

        if syn_flood_tracker[src_ip] > config['syn_flood_threshold']:
            message = f"Intrusion Detected: SYN flood detected from {src_ip}"
            log_attack_and_file(log_file, message, "SYN Flood")

def detect_dns_exfiltration(packet, log_file):
    """Detect DNS exfiltration attacks."""
    config = DETECTION_CONFIG
    if DNS in packet and packet[DNS].qd:  # DNS query
        query_raw = packet[DNS].qd.qname
        detected_encoding = chardet.detect(query_raw)
        encoding = detected_encoding.get('encoding', 'utf-8')

        try:
            query = query_raw.decode(encoding)
        except (UnicodeDecodeError, TypeError):
            query = query_raw.decode('utf-8', errors="replace")
            message = f"Decoding issue with {encoding}, replaced invalid characters in query: {query}"
            log_attack_and_file(log_file, message, "DNS Exfiltration")

        # Check for unusually long domain names
        if len(query) > config['query_length_threshold']:
            message = f"Intrusion Detected: Possible DNS exfiltration in query {query}"
            log_attack_and_file(log_file, message, "DNS Exfiltration")

def detect_port_scan(src_ip, dst_port, packet_time, log_file):
    """Detect port scanning activities."""
    config = DETECTION_CONFIG
    if src_ip not in scanning_ips:
        scanning_ips[src_ip] = {"ports": set(), "start_time": packet_time}

    # Add port to the set of accessed ports
    scanning_ips[src_ip]["ports"].add(dst_port)

    # If the time window has expired, reset the tracking for this IP
    if packet_time - scanning_ips[src_ip]["start_time"] > config['port_scan_time_window']:
        scanning_ips[src_ip] = {"ports": {dst_port}, "start_time": packet_time}

    # Check if the number of unique ports exceeds the threshold
    if len(scanning_ips[src_ip]["ports"]) > config['port_scan_threshold']:
        message = f"Intrusion Detected: Port scanning detected from {src_ip}"
        log_attack_and_file(log_file, message, "Port Scan")

def detect_traffic_anomalies(flow_key, log_file):
    """Detect traffic anomalies based on historical averages."""
    src_ip = flow_key[0]
    current_traffic = flows[flow_key]["bytes"]
    
    # Append the current traffic to the history of the source IP
    traffic_history[src_ip].append(current_traffic)
    
    # Calculate average past traffic
    if len(traffic_history[src_ip]) > 1:
        avg_traffic = sum(traffic_history[src_ip]) / len(traffic_history[src_ip])
        
        # Check if current traffic exceeds 2 times the average, indicating an anomaly
        if current_traffic > 2 * avg_traffic:
            message = f"Traffic Anomaly Detected: {src_ip} shows sudden traffic spike. Current: {current_traffic}, Avg: {avg_traffic}"
            log_attack_and_file(log_file, message, "Traffic Anomaly")


def detect_dns_amplification(packet, log_file):
    """Detect DNS amplification attacks by checking for large response sizes."""
    if DNS in packet and packet[DNS].qd and packet.haslayer(UDP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # Detect large DNS responses
        if packet[UDP].dport == 53:  # Outgoing DNS request
            dns_amplification_tracker[src_ip].append(("query", len(packet)))
        elif packet[UDP].sport == 53:  # Incoming DNS response
            dns_amplification_tracker[dst_ip].append(("response", len(packet)))

        # Check for amplification if we've seen at least 5 DNS responses
        if len(dns_amplification_tracker[dst_ip]) >= DNS_AMP_THRESHOLD:
            query_sizes = [size for typ, size in dns_amplification_tracker[dst_ip] if typ == "query"]
            response_sizes = [size for typ, size in dns_amplification_tracker[dst_ip] if typ == "response"]

            if response_sizes and query_sizes and (max(response_sizes) > 3 * max(query_sizes)):
                message = f"DNS Amplification Attack Detected: {dst_ip} received large responses."
                log_attack_and_file(log_file, message, "DNS Amplification Attack")

            # Clear the tracker after detection
            dns_amplification_tracker[dst_ip] = []


def detect_slowloris(packet, log_file):
    """Detect Slowloris DoS attack by tracking excessive half-open HTTP connections."""
    if TCP in packet and packet[TCP].dport == 80 and packet[TCP].flags == "S":  # SYN packet on port 80 (HTTP)
        src_ip = packet[IP].src
        slowloris_tracker[src_ip] += 1

        if slowloris_tracker[src_ip] > SLOWLORIS_THRESHOLD:
            message = f"Slowloris attack detected from {src_ip}: {slowloris_tracker[src_ip]} half-open connections."
            log_attack_and_file(log_file, message, "Slowloris Attack")