import sqlite3
import time
from scapy.all import IP, TCP, UDP, raw

# Global batch to store packets before inserting them in the database
BATCH_SIZE = 100
packet_batch = []
flow_table = {}  # Dictionary to store flows
time_offset = 0  # Global variable to increment time for each packet

def get_db_connection():
    """
    Establish a connection to the SQLite database with WAL mode enabled.
    """
    conn = sqlite3.connect('traffic.db', timeout=30)
    conn.execute('PRAGMA journal_mode=WAL')  # Ensure WAL mode is active
    conn.execute('PRAGMA busy_timeout = 5000')  # Wait 5000 milliseconds if the database is locked
    return conn

def init_db():
    """
    Initialize the database and create necessary tables.
    """
    conn = get_db_connection()
    try:
        c = conn.cursor()

        # Table for storing packet data
        c.execute('''CREATE TABLE IF NOT EXISTS traffic_data (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        time REAL,
                        src_ip TEXT,
                        dst_ip TEXT,
                        protocol TEXT,
                        src_port INTEGER,
                        dst_port INTEGER,
                        raw_data TEXT)''')

        # Table for storing flow data
        c.execute('''CREATE TABLE IF NOT EXISTS flow_data (
                        flow_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        src_ip TEXT,
                        dst_ip TEXT,
                        src_port INTEGER,
                        dst_port INTEGER,
                        protocol TEXT,
                        packet_count INTEGER,
                        total_bytes INTEGER,
                        start_time REAL,
                        end_time REAL)''')

        # Table for storing detected attacks
        c.execute('''CREATE TABLE IF NOT EXISTS detected_attacks (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        type TEXT,
                        description TEXT,
                        timestamp REAL)''')

        conn.commit()  # Commit changes to the database
    finally:
        conn.close()  # Ensure that the connection is always closed

def store_packet_data(packet):
    """
    Store packet information in a batch and update flow information.
    """
    global packet_batch, flow_table, time_offset

    # Extract packet details
    ip_layer = packet[IP]
    src_ip = ip_layer.src
    dst_ip = ip_layer.dst
    protocol = "TCP" if TCP in packet else "UDP" if UDP in packet else "Other"
    src_port = packet.sport if TCP in packet or UDP in packet else None
    dst_port = packet.dport if TCP in packet or UDP in packet else None
    raw_data = raw(packet).hex()  # Store raw packet data in hex format
    packet_size = len(raw(packet))  # Correctly capture packet size

    # Get the current time and add a small offset to ensure no duplicate timestamps
    current_time = time.time() + time_offset
    time_offset += 0.001  # Increment by a small value (1 ms) for each packet

    # Append the packet details to the batch
    packet_batch.append((current_time, src_ip, dst_ip, protocol, src_port, dst_port, raw_data))

    # Define the flow identifier (5-tuple: src_ip, dst_ip, src_port, dst_port, protocol)
    flow_id = (src_ip, dst_ip, src_port, dst_port, protocol)

    # Check if the flow already exists
    if flow_id not in flow_table:
        # If it's a new flow, initialize it
        flow_table[flow_id] = {
            'packet_count': 1,
            'total_bytes': packet_size,  # Store the correct size of the packet
            'start_time': current_time,
            'end_time': current_time
        }
    else:
        # Update the existing flow
        flow_table[flow_id]['packet_count'] += 1
        flow_table[flow_id]['total_bytes'] += packet_size  # Accumulate packet size correctly
        flow_table[flow_id]['end_time'] = current_time

    # If the batch size reaches BATCH_SIZE, commit them to the database
    if len(packet_batch) >= BATCH_SIZE:
        _commit_packet_batch()


def _commit_packet_batch():
    """
    Commit the batch of packets to the database and update flows.
    """
    global packet_batch, flow_table

    # Skip if there's nothing to commit
    if not packet_batch:
        return

    conn = sqlite3.connect('traffic.db')
    c = conn.cursor()

    # Insert packet data into traffic_data table
    c.executemany('''INSERT INTO traffic_data 
                     (time, src_ip, dst_ip, protocol, src_port, dst_port, raw_data) 
                     VALUES (?, ?, ?, ?, ?, ?, ?)''', packet_batch)

    # Insert or update flow data in flow_data table
    for flow_id, flow_info in flow_table.items():
        src_ip, dst_ip, src_port, dst_port, protocol = flow_id
        c.execute('''INSERT OR REPLACE INTO flow_data
                     (src_ip, dst_ip, src_port, dst_port, protocol, packet_count, total_bytes, start_time, end_time)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''', 
                     (src_ip, dst_ip, src_port, dst_port, protocol, 
                      flow_info['packet_count'], flow_info['total_bytes'],
                      flow_info['start_time'], flow_info['end_time']))

    conn.commit()
    conn.close()

    # Clear the batch after committing
    packet_batch = []
    flow_table = {}

def flush_packet_batch():
    """
    Flush any remaining packets in the batch to the database.
    """
    _commit_packet_batch()

def get_flow_statistics():
    """
    Query the database for flow statistics.
    """
    conn = get_db_connection()
    c = conn.cursor()

    # Retrieve total number of flows and total bytes transferred
    c.execute('SELECT COUNT(*), SUM(total_bytes) FROM flow_data')
    result = c.fetchone()
    total_flows = result[0] if result[0] else 0
    total_bytes = result[1] if result[1] else 0

    conn.close()
    return total_flows, total_bytes

def log_attack(attack_type, description):
    """
    Log an attack in the detected_attacks table.
    """
    conn = sqlite3.connect('traffic.db')
    c = conn.cursor()

    # Insert detected attack with correct UNIX timestamp (in seconds)
    c.execute('''INSERT INTO detected_attacks (type, description, timestamp)
                 VALUES (?, ?, ?)''', (attack_type, description, time.time()))  # time.time() returns a float (seconds)
    conn.commit()
    conn.close()

# Additional Debugging Route to Check Stored Data
def get_packet_data():
    """
    Retrieve all packet data from the traffic_data table for debugging.
    """
    conn = get_db_connection()
    c = conn.cursor()

    try:
        c.execute('SELECT * FROM traffic_data')
        return c.fetchall()  # Return all rows for debugging
    finally:
        conn.close()

if __name__ == "__main__":
    # Initialize the database and tables
    init_db()

    # Flush any pending packet data
    flush_packet_batch()

    # Print packet data for debugging
    packets = get_packet_data()
    print("Stored Packets:", packets)
