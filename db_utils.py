import sqlite3
import time
from scapy.all import IP, TCP, UDP, raw  # Add this line to import necessary modules from scapy

# Global batch to store packets before inserting them in the database
BATCH_SIZE = 100  # Adjust the batch size as needed for performance
packet_batch = []

def init_db():
    """
    Initialize the database and create the necessary tables if they don't exist.
    """
    conn = sqlite3.connect('traffic.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS traffic_data (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    time REAL,
                    src_ip TEXT,
                    dst_ip TEXT,
                    protocol TEXT,
                    src_port INTEGER,
                    dst_port INTEGER,
                    raw_data TEXT)''')
    conn.commit()
    conn.close()

def store_packet_data(packet):
    """
    Store packet information in a batch and commit once the batch size is reached.
    """
    global packet_batch

    # Extract packet details
    ip_layer = packet[IP]
    src_ip = ip_layer.src
    dst_ip = ip_layer.dst
    protocol = "TCP" if TCP in packet else "UDP" if UDP in packet else "Other"
    src_port = packet.sport if TCP in packet or UDP in packet else None
    dst_port = packet.dport if TCP in packet or UDP in packet else None
    raw_data = raw(packet).hex()  # Store raw packet data in hex format

    # Append the packet details to the batch
    packet_batch.append((time.time(), src_ip, dst_ip, protocol, src_port, dst_port, raw_data))

    # If the batch size reaches BATCH_SIZE, commit them to the database
    if len(packet_batch) >= BATCH_SIZE:
        _commit_packet_batch()

def _commit_packet_batch():
    """
    Commit the batch of packets to the database in a single transaction.
    """
    global packet_batch

    # Skip if there's nothing to commit
    if not packet_batch:
        return

    conn = sqlite3.connect('traffic.db')
    c = conn.cursor()

    # Use a single transaction for batch insert
    c.executemany('''INSERT INTO traffic_data 
                     (time, src_ip, dst_ip, protocol, src_port, dst_port, raw_data) 
                     VALUES (?, ?, ?, ?, ?, ?, ?)''', packet_batch)
    conn.commit()
    conn.close()

    # Clear the batch after committing
    packet_batch = []

def flush_packet_batch():
    """
    Flush any remaining packets in the batch to the database.
    This should be called when the program is finished processing packets.
    """
    _commit_packet_batch()
