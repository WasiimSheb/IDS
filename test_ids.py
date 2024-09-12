import unittest
from IDS import process_pcap_file

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

    

    def tearDown(self):
        import os
        if os.path.exists(self.test_logfile):
            os.remove(self.test_logfile)

if __name__ == '__main__':
    unittest.main()
