import os
import sys
import time
import traceback
import argparse
from scapy.all import sniff, rdpcap  # Import sniff and rdpcap from scapy
from logging_utils import log_to_txt_file, start_logging_thread, log_queue
from packet_processing import process_packet  # Assuming process_packet is properly defined
from db_utils import init_db  # Import the database initialization function

def process_pcap_file(pcap_file, log_file):
    """
    Read packets from a PCAP file and process each one, simulating real-time processing.
    """
    try:
        packets = rdpcap(pcap_file)  # Read packets from the PCAP file
        if not packets:
            log_to_txt_file(log_file, "No packets to process.")
            return

        time.time()  # Get the current real time when we start processing
        first_packet_time = packets[0].time  # Timestamp of the first packet in the pcap
        previous_packet_time = first_packet_time  # Track the time of the previous packet for calculating the delay

        for packet in packets:
            # Get the timestamp from the packet
            packet_time = packet.time

            # Calculate the time difference between consecutive packets in the pcap file
            time_diff = float(packet_time - previous_packet_time) # This is the time delay in the pcap file
            previous_packet_time = packet_time
            if time_diff < 0:
                time_diff = 0

                time.sleep(time_diff)  # Sleep for the time difference between consecutive packets

            # Adjust the current real-time to simulate when the packet was processed
            simulated_time = time.time()

            # Process the packet and store it with the adjusted timestamp
            process_packet(packet, log_file, simulated_time)  # Pass the packet along with the simulated time

        log_to_txt_file(log_file, f"Finished processing PCAP file: {pcap_file}", level="INFO")

    except FileNotFoundError:
        log_to_txt_file(log_file, f"Error: PCAP file '{pcap_file}' not found.", level="ERROR")
    except Exception as e:
        log_to_txt_file(log_file, f"Error reading PCAP file '{pcap_file}': {e}", level="ERROR")
        traceback.print_exc()

    except FileNotFoundError:
        log_to_txt_file(log_file, f"Error: PCAP file '{pcap_file}' not found.", level="ERROR")
    except Exception as e:
        log_to_txt_file(log_file, f"Error reading PCAP file '{pcap_file}': {e}", level="ERROR")
        traceback.print_exc()

def main():
    try:
        # Argument parsing with error handling
        parser = argparse.ArgumentParser(description="Intrusion Detection System")
        parser.add_argument('--pcapfile', type=str, help="PCAP file to analyze")
        parser.add_argument('--interface', type=str, help="Network interface to sniff on")
        parser.add_argument('--logfile', type=str, default="captured_packets.txt", help="Log file to store packet data")
        args = parser.parse_args()

        # Initialize the database
        print("Initializing the database...")
        init_db()

        # Start the logging thread
        logging_thread = start_logging_thread(args.logfile)

        # Open log file in append mode
        with open(args.logfile, "a") as log_file:
            if args.pcapfile:
                print(f"Processing PCAP file: {args.pcapfile}")
                log_to_txt_file(log_file, f"Processing PCAP file: {args.pcapfile}", level="INFO")
                process_pcap_file(args.pcapfile, log_file)
            elif args.interface:
                print(f"Sniffing on interface: {args.interface}")
                log_to_txt_file(log_file, f"Sniffing on interface: {args.interface}", level="INFO")
                sniff(iface=args.interface, prn=lambda pkt: process_packet(pkt, log_file , time.time()))
            else:
                print("You must specify either --pcapfile or --interface.")
                sys.exit(1)

        # Gracefully stop the logging thread
        log_queue.put("STOP")
        logging_thread.join()

    except Exception as unexpected_error:
        print(f"An unexpected error occurred: {unexpected_error}")
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
