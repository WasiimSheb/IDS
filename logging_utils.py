import threading
import queue
import time
import sqlite3

# Global log queue for thread-safe logging
log_queue = queue.Queue()
log_buffer = []

# Global dictionary to keep track of recently logged attacks
recent_attacks = {}

def log_to_file(log_file, message, level="INFO"):
    """
    Log a message to the buffer and flush if necessary.
    """
    formatted_message = f"[{level}] {message} [{time.strftime('%Y-%m-%d %H:%M:%S')}]"
    log_buffer.append(formatted_message + "\n")
    
    # If the buffer reaches 10 messages, flush to the file
    if len(log_buffer) >= 10:
        flush_logs(log_file)

def flush_logs(log_file):
    """
    Flush buffered logs to the log file.
    """
    if isinstance(log_file, str):
        # If log_file is a file path, open and write
        with open(log_file, 'a') as f:
            f.writelines(log_buffer)
    else:
        # If it's a file-like object, directly write
        log_file.writelines(log_buffer)
        log_file.flush()

    # Clear the buffer
    log_buffer.clear()

def start_logging_thread(log_file_path):
    """
    Starts a background thread to log messages asynchronously.
    """
    logging_thread = threading.Thread(target=_write_to_file, args=(log_file_path,))
    logging_thread.start()
    return logging_thread

def _write_to_file(log_file_path):
    """
    Internal function that writes log messages to the file from the queue.
    """
    with open(log_file_path, 'a') as log_file:
        while True:
            message = log_queue.get()
            if message == "STOP":
                break
            log_file.write(message + "\n")
            log_file.flush()

def log_attack(attack_type, description):
    """
    Log an attack in the detected_attacks table with duplicate filtering.
    """
    global recent_attacks
    current_time = time.time()

    # Set cooldown (e.g., 10 seconds) to avoid duplicate logging
    cooldown_period = 10

    # Avoid logging the same attack within the cooldown period
    if attack_type in recent_attacks and (current_time - recent_attacks[attack_type]) < cooldown_period:
        print(f"Skipping duplicate attack log for {attack_type}")
        return

    # Log attack since it hasn't been logged recently
    recent_attacks[attack_type] = current_time

    # Perform logging to the database
    conn = sqlite3.connect('traffic.db')
    c = conn.cursor()
    c.execute('''INSERT INTO detected_attacks (type, description, timestamp)
                 VALUES (?, ?, ?)''', (attack_type, description, current_time))
    conn.commit()
    conn.close()

    print(f"Logged attack: {attack_type}")

def flush_packet_logs():
    """
    Flush any remaining logs in the queue to the log file.
    """
    log_queue.put("STOP")
