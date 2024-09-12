import time
import chardet
from scapy.all import IP, TCP, UDP, ICMP, DNS
from collections import defaultdict
import ipaddress

# Trackers to hold state information for ICMP, DNS, SYN flood, and port scans
icmp_tracker = defaultdict(list)
dns_tracker = defaultdict(list)
syn_flood_tracker = defaultdict(int)
scanning_ips = {}

# Time window for tracking port scan activity
port_scan_time_window = 60  # 60 seconds

# Helper functions
def log_to_file(log_file, message):
    """Logging utility that handles unencodable characters."""
    log_file.write(message.encode("cp1252", errors="replace").decode("cp1252") + "\n")
    log_file.flush()

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
def detect_icmp_data_exfiltration(packet, log_file, icmp_payload_threshold=500, icmp_time_window=60, icmp_packet_threshold=100, icmp_total_data_threshold=20000):
    """Detect ICMP-based data exfiltration."""
    if ICMP in packet:
        payload_size = len(packet[ICMP].payload)
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        timestamp = time.time()

        if is_internal_ip(src_ip) and is_external_ip(dst_ip):
            flow_key = (src_ip, dst_ip)
            icmp_tracker[flow_key].append((payload_size, timestamp))

            # Clean up old ICMP traffic data
            icmp_tracker[flow_key] = [(size, ts) for size, ts in icmp_tracker[flow_key] if timestamp - ts < icmp_time_window]

            total_data_sent = sum(size for size, _ in icmp_tracker[flow_key])
            packet_count = len(icmp_tracker[flow_key])

            if packet_count > icmp_packet_threshold:
                log_to_file(log_file, f"Suspicious ICMP traffic: {packet_count} packets from {src_ip} to {dst_ip} in {icmp_time_window} seconds.")
            if total_data_sent > icmp_total_data_threshold:
                log_to_file(log_file, f"Suspicious ICMP traffic: {total_data_sent} bytes from {src_ip} to {dst_ip} in {icmp_time_window} seconds.")
            if payload_size > icmp_payload_threshold:
                log_to_file(log_file, f"Suspicious ICMP traffic: Large packet ({payload_size} bytes) from {src_ip} to {dst_ip}.")

def detect_excessive_dns_queries(packet, log_file, dns_query_threshold=100, dns_time_window=60):
    """Detect excessive DNS queries in a short time window."""
    if DNS in packet and packet[DNS].qd:
        query_raw = packet[DNS].qd.qname
        detected_encoding = chardet.detect(query_raw)
        encoding = detected_encoding.get('encoding', 'utf-8')

        try:
            query = query_raw.decode(encoding)
        except (UnicodeDecodeError, TypeError):
            query = query_raw.decode('utf-8', errors="replace")
            log_to_file(log_file, f"Decoding issue with {encoding}, replaced invalid characters in query: {query}")

        src_ip = packet[IP].src
        dns_tracker[src_ip].append(time.time())

        # Clean up old DNS queries
        dns_tracker[src_ip] = [t for t in dns_tracker[src_ip] if time.time() - t < dns_time_window]

        if len(dns_tracker[src_ip]) > dns_query_threshold:
            log_to_file(log_file, f"Excessive DNS Queries Detected: {src_ip} made {len(dns_tracker[src_ip])} DNS queries in {dns_time_window} seconds.")

def detect_file_transfer_protocols(flow_key, log_file):
    """Detect unauthorized file transfers (e.g., FTP, SFTP)."""
    src_ip, dst_ip, src_port, dst_port, protocol = flow_key
    if protocol == "TCP" and (dst_port in [21, 22] or src_port in [21, 22]):
        log_to_file(log_file, f"Unauthorized File Transfer Detected: {src_ip} to {dst_ip}. File transfer protocol on port {dst_port if dst_port in [21, 22] else src_port}")

def detect_http_covert_channel(packet, log_file, user_agent_length_threshold=30):
    """Detect covert channels through HTTP headers."""
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

            if len(user_agent_value) > user_agent_length_threshold:
                log_to_file(log_file, f"Intrusion Detected: HTTP Covert Channel Detected in User-Agent: {user_agent_value}")

def detect_syn_flood(packet, log_file, syn_flood_threshold=100):
    """Detect SYN flood attacks."""
    if TCP in packet and (packet[TCP].flags & 0x12 == 0x02):  # SYN set, ACK not set
        src_ip = packet[IP].src
        syn_flood_tracker[src_ip] += 1

        if syn_flood_tracker[src_ip] > syn_flood_threshold:
            log_to_file(log_file, f"Intrusion Detected: SYN flood detected from {src_ip}")

def detect_dns_exfiltration(packet, log_file, query_length_threshold=50):
    """Detect DNS exfiltration attacks."""
    if DNS in packet and packet[DNS].qd:  # DNS query
        query_raw = packet[DNS].qd.qname
        detected_encoding = chardet.detect(query_raw)
        encoding = detected_encoding.get('encoding', 'utf-8')

        try:
            query = query_raw.decode(encoding)
        except (UnicodeDecodeError, TypeError):
            query = query_raw.decode('utf-8', errors="replace")
            log_to_file(log_file, f"Decoding issue with {encoding}, replaced invalid characters in query: {query}")

        # Check for unusually long domain names
        if len(query) > query_length_threshold:
            log_to_file(log_file, f"Intrusion Detected: Possible DNS exfiltration in query {query}")

def detect_port_scan(src_ip, dst_port, packet_time, log_file, port_scan_threshold=10):
    """Detect port scanning activities."""
    if src_ip not in scanning_ips:
        scanning_ips[src_ip] = {"ports": set(), "start_time": packet_time}

    # Add port to the set of accessed ports
    scanning_ips[src_ip]["ports"].add(dst_port)

    # If the time window has expired, reset the tracking for this IP
    if packet_time - scanning_ips[src_ip]["start_time"] > port_scan_time_window:
        scanning_ips[src_ip] = {"ports": {dst_port}, "start_time": packet_time}

    # Check if the number of unique ports exceeds the threshold
    if len(scanning_ips[src_ip]["ports"]) > port_scan_threshold:
        log_to_file(log_file, f"Intrusion Detected: Port scanning detected from {src_ip}")
        # Optionally, reset tracking after detection to avoid multiple detections
        scanning_ips[src_ip] = {"ports": set(), "start_time": packet_time}
