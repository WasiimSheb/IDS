#!/bin/bash

PCAP_DIR="/app/pcap"

# Loop through all PCAP files in the directory
for pcap_file in $PCAP_DIR/*.pcap; do
  echo "Replaying $pcap_file"
  
  # Replay the traffic from the PCAP file
  # Change the interface eth0 to the appropriate interface as needed
  tcpreplay --intf1=eth0 $pcap_file
  
  # Optional: add a sleep interval between replays
  sleep 8
done

# Keep the container running after replay
exec "$@"