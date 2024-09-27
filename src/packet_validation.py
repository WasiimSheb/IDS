from scapy.all import IP, TCP, UDP

def validate_ip_packet(packet):
    """
    Validate IP packet characteristics, checking version, fragment, and TTL.
    """
    if IP in packet:
        ip_layer = packet[IP]
        # Check if essential fields exist and are valid
        if ip_layer.version != 4 or ip_layer.ihl is None or ip_layer.ihl < 5 or ip_layer.frag is None or ip_layer.frag > 0 or ip_layer.ttl is None or ip_layer.ttl <= 0:
            return False, "Invalid IP packet characteristics"
        return True, "IP packet is valid"
    return False, "Not an IP packet"


def validate_tcp_packet(packet, check_checksum=False):
    if TCP in packet:
        tcp_layer = packet[TCP]
        if not (0 <= tcp_layer.sport <= 65535 and 0 <= tcp_layer.dport <= 65535):
            return False, "Invalid TCP packet characteristics"

        if check_checksum:
            correct_checksum = packet[TCP].chksum
            packet[TCP].chksum = None
            calculated_checksum = TCP(bytes(packet)).chksum
            if correct_checksum != calculated_checksum:
                return False, "Invalid TCP checksum"
        return True, "TCP packet is valid"
    return False, "Not a TCP packet"

def validate_udp_packet(packet):
    if UDP in packet:
        udp_layer = packet[UDP]
        if not (0 <= udp_layer.sport <= 65535 and 0 <= udp_layer.dport <= 65535):
            return False, "Invalid UDP packet characteristics"
        return True, "UDP packet is valid"
    return False, "Not a UDP packet"
