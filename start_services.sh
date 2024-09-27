#!/bin/bash

# Start tcpreplay in the background
tcpreplay --intf1=eth0 /path/to/your/pcap/file.pcap &

# Start the IDS system in the foreground
python3 /app/src/IDS.py --interface eth0