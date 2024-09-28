import os
import sqlite3
import sqlite3
import time
from scapy.all import IP, TCP, UDP, raw
from concurrent.futures import ThreadPoolExecutor
import threading
import queue

from shared import DIR

# Global batch to store packets before inserting them in the database
BATCH_SIZE = 100  # Keep batch size manageable to avoid issues
PACKET_FLUSH_INTERVAL = 50  # Flush packets to database after every 50 batches
packet_batch = []
flow_table = {}  # Dictionary to store flows
time_offset = 0  # Global variable to increment time for each packet
executor = ThreadPoolExecutor(max_workers=2)  # Use for asynchronous database writes
packet_commit_count = 0

# Attack logging queue for async processing
log_queue = queue.Queue()

# Set the absolute path to the shared database location
DB_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), DIR)
DB_PATH = os.path.join(DB_DIR, 'traffic.db')

def get_db_connection():
    """
    Establish a new connection to the SQLite database with WAL mode enabled.
    Ensure the database directory exists.
    """
    # Ensure the database directory exists
    if not os.path.exists(DB_DIR):
        os.makedirs(DB_DIR)  # Create the directory if it doesn't exist
    
    # Connect to the SQLite database
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.execute('PRAGMA journal_mode=WAL')  # Enable Write-Ahead Logging for better concurrency
    conn.execute('PRAGMA synchronous = NORMAL')  # Tuning for better performance
    conn.execute('PRAGMA temp_store = MEMORY')  # Store temporary tables in memory for faster access
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
    global packet_batch, flow_table, time_offset, packet_commit_count

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
        flow_table[flow_id] = {
            'packet_count': 1,
            'total_bytes': packet_size,
            'start_time': current_time,
            'end_time': current_time
        }
    else:
        flow_table[flow_id]['packet_count'] += 1
        flow_table[flow_id]['total_bytes'] += packet_size
        flow_table[flow_id]['end_time'] = current_time

    # Commit the data after every batch size
    if len(packet_batch) >= BATCH_SIZE:
        packet_commit_count += 1
        if packet_commit_count % PACKET_FLUSH_INTERVAL == 0:
            _commit_packet_batch_async()
        else:
            _commit_packet_batch()

def _commit_packet_batch():
    """
    Commit the batch of packets to the database and update flows.
    Each thread will open a new connection to commit the data.
    """
    global packet_batch, flow_table

    if not packet_batch:
        return

    conn = get_db_connection()
    try:
        c = conn.cursor()

        # Insert packet data into traffic_data table using bulk insert
        c.executemany('''INSERT INTO traffic_data 
                         (time, src_ip, dst_ip, protocol, src_port, dst_port, raw_data) 
                         VALUES (?, ?, ?, ?, ?, ?, ?)''', packet_batch)

        # Iterate over a copy of flow_table to avoid modification during iteration
        flow_table_copy = flow_table.copy()

        # Insert or update flow data in flow_data table using bulk insert
        for flow_id, flow_info in flow_table_copy.items():
            src_ip, dst_ip, src_port, dst_port, protocol = flow_id
            c.execute('''INSERT OR REPLACE INTO flow_data
                         (src_ip, dst_ip, src_port, dst_port, protocol, packet_count, total_bytes, start_time, end_time)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                         (src_ip, dst_ip, src_port, dst_port, protocol,
                          flow_info['packet_count'], flow_info['total_bytes'],
                          flow_info['start_time'], flow_info['end_time']))

        conn.commit()
    except Exception as e:
        print(f"Error committing batch: {e}")
    finally:
        conn.close()

    # Clear the batch after committing
    packet_batch = []
    flow_table = {}


def _commit_packet_batch_async():
    """
    Commit the packet batch asynchronously by creating a new connection in each thread.
    """
    executor.submit(_commit_packet_batch)

def flush_packet_batch():
    """
    Flush any remaining packets in the batch to the database.
    """
    print("Flushing remaining packets to the database.")
    _commit_packet_batch()

def log_attack(attack_type, description):
    """
    Log an attack in the detected_attacks table asynchronously by creating a new connection for each log.
    """
    log_queue.put((attack_type, description))

def _process_log_queue():
    """
    Continuously process log attack requests from the queue.
    Each log entry is processed using a separate database connection.
    """
    while True:
        attack_type, description = log_queue.get()  # Blocks until an item is available
        conn = get_db_connection()
        try:
            c = conn.cursor()
            c.execute('''INSERT INTO detected_attacks (type, description, timestamp)
                         VALUES (?, ?, ?)''', (attack_type, description, time.time()))
            conn.commit()
        except Exception as e:
            print(f"Error logging attack: {e}")
        finally:
            conn.close()
        log_queue.task_done()

# Start the async attack logging processor
attack_log_thread = threading.Thread(target=_process_log_queue, daemon=True)
attack_log_thread.start()