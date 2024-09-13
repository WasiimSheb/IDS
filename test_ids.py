import unittest
from IDS import process_pcap_file, validate_ip_packet, validate_tcp_packet
from scapy.all import IP, TCP  # Import IP and TCP directly from scapy

from shared import flows

class TestIntrusionDetection(unittest.TestCase):

    def setUp(self):
        self.test_logfile = "test_log.txt"

    def test_syn_flood(self):
        with open(self.test_logfile, "w") as log_file:
            process_pcap_file("pcap/syn_flood.pcap", log_file)
        with open(self.test_logfile, "r") as log_file:
            log_content = log_file.read()
            self.assertIn("Intrusion Detected: SYN flood detected", log_content)

    def test_port_scan(self):
        with open(self.test_logfile, "w") as log_file:
            process_pcap_file("pcap/portscan.pcap", log_file)
        with open(self.test_logfile, "r") as log_file:
            log_content = log_file.read()
            self.assertIn("Intrusion Detected: Port scanning detected", log_content)

    def test_port_scan2(self):
        with open(self.test_logfile, "w") as log_file:
            process_pcap_file("pcap/portscan1.pcap", log_file)
        with open(self.test_logfile, "r") as log_file:
            log_content = log_file.read()
            self.assertIn("Intrusion Detected: Port scanning detected", log_content)

    def test_ftp_exfiltration(self):
        with open(self.test_logfile, "w") as log_file:
            process_pcap_file("pcap/ftp.pcap", log_file)
        with open(self.test_logfile, "r") as log_file:
            log_content = log_file.read()
            self.assertIn("Unauthorized File Transfer Detected", log_content)

    def test_dns_tunneling(self):
        with open(self.test_logfile, "w") as log_file:
            process_pcap_file("pcap/dns.pcap", log_file)
        with open(self.test_logfile, "r") as log_file:
            log_content = log_file.read()
            self.assertIn("Intrusion Detected: Possible DNS exfiltration", log_content)

    def test_http_covert_channel(self):
        with open(self.test_logfile, "w") as log_file:
            process_pcap_file("pcap/http_covert_channel.pcap", log_file)
        with open(self.test_logfile, "r") as log_file:
            log_content = log_file.read()
            self.assertIn("Intrusion Detected: HTTP Covert Channel Detected", log_content)

    def test_icmp_exfiltration(self):
        with open(self.test_logfile, "w") as log_file:
            process_pcap_file("pcap/icmp_large.pcap", log_file)
        
        # Read the log to ensure the detection works
        with open(self.test_logfile, "r") as log_file:
            log_content = log_file.read()
            self.assertIn("Suspicious ICMP traffic", log_content)

    def test_icmp_normal(self):
        with open(self.test_logfile, "w") as log_file:
            process_pcap_file("pcap/icmp_normal.pcap", log_file)
    
        # Read the log to ensure there's no detection of suspicious ICMP traffic
        with open(self.test_logfile, "r") as log_file:
            log_content = log_file.read()

            # Add an assertion that "Suspicious ICMP traffic" is NOT present
            self.assertNotIn("Suspicious ICMP traffic", log_content)

    
    def test_invalid_ip_packet(self):
        """Test handling of malformed IP packets."""
        # Now using the correct IP class from Scapy
        packet = IP(src="192.168.1.1")  # Incomplete IP packet
        is_valid, msg = validate_ip_packet(packet)
        self.assertFalse(is_valid)
        self.assertIn("Invalid IP packet", msg)

    def test_tcp_packet_with_invalid_checksum(self):
        """Test detection of TCP packets with invalid checksums."""
        # Construct a valid IP packet with necessary fields set
        packet = IP(src="192.168.1.1", dst="192.168.1.2", ihl=5, ttl=64) / TCP()

        # Manually set an invalid TCP checksum (0xFFFF) and prevent Scapy from recalculating it
        packet[TCP].chksum = 0xFFFF

        # Validate the IP packet first
        is_valid_ip, msg_ip = validate_ip_packet(packet)
        self.assertTrue(is_valid_ip, msg_ip)  # Ensure the IP packet is valid

        # Validate the TCP checksum (now the function actually checks it)
        is_valid_tcp, msg_tcp = validate_tcp_packet(packet, check_checksum=True)
        self.assertFalse(is_valid_tcp, msg_tcp)  # Ensure the TCP checksum is invalid
        self.assertIn("Invalid TCP checksum", msg_tcp)

    def test_flow_tracking(self):
        with open(self.test_logfile, "w") as log_file:
            process_pcap_file("pcap/flowTracking.pcap", log_file)

        # Check if at least one flow was tracked
        self.assertGreater(len(flows), 0, "No flows were tracked.")

        for flow_key, flow_info in flows.items():
            # Assert that the flow key has the correct structure (src_ip, dst_ip, src_port, dst_port, protocol)
            self.assertEqual(len(flow_key), 5, f"Flow key has an unexpected structure: {flow_key}")
            
            src_ip, dst_ip, src_port, dst_port, protocol = flow_key
            
            # Assert that the IP addresses are valid
            self.assertRegex(src_ip, r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', "Invalid source IP format")
            self.assertRegex(dst_ip, r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', "Invalid destination IP format")
            
            # Assert that the ports are valid integers within the correct range
            if src_port is not None:
                self.assertGreaterEqual(src_port, 0, "Source port is less than 0")
                self.assertLessEqual(src_port, 65535, "Source port is greater than 65535")
            
            if dst_port is not None:
                self.assertGreaterEqual(dst_port, 0, "Destination port is less than 0")
                self.assertLessEqual(dst_port, 65535, "Destination port is greater than 65535")
            
            # Assert that the protocol is either TCP or UDP
            self.assertIn(protocol, ["TCP", "UDP", "Other"], f"Unexpected protocol in flow: {protocol}")

            # Assert that the flow information includes bytes, packets, and start_time
            self.assertIn("bytes", flow_info, "Flow does not track byte count.")
            self.assertIn("packets", flow_info, "Flow does not track packet count.")
            self.assertIn("start_time", flow_info, "Flow does not track start time.")

            # Ensure the flow tracked at least one packet and non-zero bytes
            self.assertGreater(flow_info["packets"], 0, "Flow packet count is zero.")
            self.assertGreater(flow_info["bytes"], 0, "Flow byte count is zero.")
            
            # Only check end_time if it is not None
            if flow_info.get("end_time") is not None:
                self.assertGreaterEqual(flow_info["end_time"], flow_info["start_time"], "Flow end_time is not greater than or equal to start_time.")



    def test_dns_query_with_encoding_issue(self):
        # Simulate the function writing to a log file
        with open(self.test_logfile, "w") as log_file:
            process_pcap_file("pcap/dns_encoding.pcap", log_file)

        # Read the log file and check if the expected log entries are present
        with open(self.test_logfile, "r") as log_file:
            log_content = log_file.read()

        # The test should now look for successful logging of the non-ASCII DNS query
        self.assertIn("Detected DNS Query", log_content)

    def test_malformed_pcap_file(self):
        with open(self.test_logfile, "w") as log_file:
            process_pcap_file("pcap/malformed.pcap", log_file)

        with open(self.test_logfile, "r") as log_file:
            log_content = log_file.read()

        self.assertIn("Packet dropped", log_content)

    def tearDown(self):
        import os
        if os.path.exists(self.test_logfile):
            os.remove(self.test_logfile)

if __name__ == '__main__':
    unittest.main()
