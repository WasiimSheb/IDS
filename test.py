import subprocess
import time
import requests
import os

def generate_normal_traffic():
    """
    Generate normal traffic (HTTP, ICMP, and DNS queries).
    Replaces 'wget' with 'requests' for HTTP traffic.
    """
    # Generate HTTP traffic using requests
    try:
        print("Generating HTTP traffic...")
        requests.get("http://example.com")
    except Exception as e:
        print(f"Error generating HTTP traffic: {e}")

    # Generate ICMP traffic using ping
    print("Generating ICMP traffic...")
    subprocess.run(['ping', '-c', '4', '8.8.8.8'])

    # Generate DNS queries using dig
    print("Generating DNS traffic...")
    subprocess.run(['dig', 'example.com'])

def generate_suspicious_traffic():
    """
    Generate suspicious traffic (to simulate attacks).
    """
    # Simulate a port scan using nmap (ensure nmap is installed)
    print("Generating Port Scan traffic...")
    subprocess.run(['nmap', '-p-', '127.0.0.1'])

def generate_flows_pcap(interface, output_file):
    """
    Generate traffic and capture it into a PCAP file.
    """
    # Start tcpdump to capture traffic in the background
    tcpdump_process = subprocess.Popen(['tcpdump', '-i', interface, '-w', output_file])

    # Wait for tcpdump to start
    time.sleep(2)

    try:
        # Generate normal and suspicious traffic
        generate_normal_traffic()
        generate_suspicious_traffic()

    finally:
        # Stop tcpdump after traffic generation
        tcpdump_process.terminate()
        tcpdump_process.wait()

    print(f"Traffic capture complete: {output_file}")

def main():
    interface = 'en0'  # Specify your network interface (e.g., eth0, en0)
    
    if not os.geteuid() == 0:
        print("This script must be run as root.")
        return

    # Generate traffic and save to PCAP
    generate_flows_pcap(interface, 'flows.pcap')

if __name__ == '__main__':
    main()
