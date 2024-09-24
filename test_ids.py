import logging
import time
import unittest
import os
import sqlite3
from scapy.all import IP, TCP, raw
from IDS import process_pcap_file  # Import high-level functions from IDS.py
from packet_validation import validate_ip_packet, validate_tcp_packet  # Import from packet_validation
from shared import flows
from db_utils import get_db_connection
from logging_utils import flush_logs, log_to_file  # Correct the import for logging


class TestIntrusionDetection(unittest.TestCase):

    def setUp(self):
        self.test_logfile = "test_log.txt"
        
        # Set up database connection for testing
        self.conn = get_db_connection()
        self.conn.execute('PRAGMA busy_timeout = 5000')
        self.conn.execute('PRAGMA journal_mode=WAL')
        self.conn.commit()
        self.conn.close()

    def process_pcap_and_check_log(self, pcap_file, expected_log_message, not_in_log=False):
        """Helper function to process a PCAP file and check for a specific log message."""
        with open(self.test_logfile, "w") as log_file:
            process_pcap_file(pcap_file, log_file)

        flush_logs(self.test_logfile)

        with open(self.test_logfile, "r") as log_file:
            log_content = log_file.read()

            if not_in_log:
                self.assertNotIn(expected_log_message, log_content)
            else:
                self.assertIn(expected_log_message, log_content)

    def test_syn_flood(self):
        self.process_pcap_and_check_log("pcap/syn_flood.pcap", "Intrusion Detected: SYN flood detected")

    def test_port_scan(self):
        self.process_pcap_and_check_log("pcap/portscan.pcap", "Intrusion Detected: Port scanning detected")

    def test_port_scan2(self):
        self.process_pcap_and_check_log("pcap/portscan1.pcap", "Intrusion Detected: Port scanning detected")

    def test_ftp_exfiltration(self):
        self.process_pcap_and_check_log("pcap/ftp.pcap", "Unauthorized File Transfer Detected")

    def test_dns_tunneling(self):
        self.process_pcap_and_check_log("pcap/dns.pcap", "Intrusion Detected: Possible DNS exfiltration")

    def test_http_covert_channel(self):
        self.process_pcap_and_check_log("pcap/http_covert_channel.pcap", "Intrusion Detected: HTTP Covert Channel Detected")

    def test_icmp_exfiltration(self):
        self.process_pcap_and_check_log("pcap/icmp_large.pcap", "Suspicious ICMP traffic")

    def test_icmp_normal(self):
        self.process_pcap_and_check_log("pcap/icmp_normal.pcap", "Suspicious ICMP traffic", not_in_log=True)

    def test_invalid_ip_packet(self):
        """Test handling of malformed IP packets."""
        packet = IP(src="192.168.1.1")  # Incomplete IP packet
        is_valid, msg = validate_ip_packet(packet)
        self.assertFalse(is_valid)
        self.assertIn("Invalid IP packet", msg)

    def test_tcp_packet_with_invalid_checksum(self):
        """Test detection of TCP packets with invalid checksums."""
        packet = IP(src="192.168.1.1", dst="192.168.1.2", ihl=5, ttl=64) / TCP()

        # Manually set an invalid checksum (0xFFFF) to simulate the i ?ssue
        packet[TCP].chksum = 0xFFFF
        packet = IP(raw(packet))

        # Validate the IP packet first
        is_valid_ip, msg_ip = validate_ip_packet(packet)
        self.assertTrue(is_valid_ip, msg_ip)

        # Validate the TCP checksum
        is_valid_tcp, msg_tcp = validate_tcp_packet(packet, check_checksum=True)
        self.assertFalse(is_valid_tcp, msg_tcp)
        self.assertIn("Invalid TCP checksum", msg_tcp)

    def test_flow_tracking(self):
        with open(self.test_logfile, "w") as log_file:
            process_pcap_file("pcap/flowTracking.pcap", log_file)

        self.assertGreater(len(flows), 0, "No flows were tracked.")

        for flow_key, flow_info in flows.items():
            self.assertEqual(len(flow_key), 5, f"Flow key has an unexpected structure: {flow_key}")

            src_ip, dst_ip, src_port, dst_port, protocol = flow_key
            self.assertRegex(src_ip, r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', "Invalid source IP format")
            self.assertRegex(dst_ip, r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', "Invalid destination IP format")

            if src_port is not None:
                self.assertGreaterEqual(src_port, 0)
                self.assertLessEqual(src_port, 65535)

            if dst_port is not None:
                self.assertGreaterEqual(dst_port, 0)
                self.assertLessEqual(dst_port, 65535)

            self.assertIn("bytes", flow_info, "Flow does not track byte count.")
            self.assertIn("packets", flow_info, "Flow does not track packet count.")
            self.assertIn("start_time", flow_info, "Flow does not track start time.")

            self.assertGreater(flow_info["packets"], 0, "Flow packet count is zero.")
            self.assertGreater(flow_info["bytes"], 0, "Flow byte count is zero.")

            if flow_info.get("end_time") is not None:
                self.assertGreaterEqual(flow_info["end_time"], flow_info["start_time"])

    def test_dns_query_with_encoding_issue(self):
        self.process_pcap_and_check_log("pcap/dns_encoding.pcap", "Detected DNS Query")

    def test_malformed_pcap_file(self):
        self.process_pcap_and_check_log("pcap/malformed.pcap", "Packet dropped")

    def tearDown(self):
        flush_logs(self.test_logfile)
        if os.path.exists(self.test_logfile):
            os.remove(self.test_logfile)

if __name__ == '__main__':
    unittest.main()
