import json
import os
import threading
import queue
import time
import sqlite3

BASE_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'app/db/')
DB_PATH = os.path.join(BASE_DIR, 'traffic.db')   

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
    if len(log_buffer) >= 100:
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
    Continuously writes log messages from the queue to the log file.
    This function runs in a separate thread.
    """
    with open(log_file_path, 'a') as log_file:
        while True:
            message = log_queue.get()
            if message == "STOP":
                break
            # Write the message to the log file in JSON format
            log_file.write(json.dumps({
                "message": message["text"],
                "timestamp": time.time(),
                "attack_type": message.get("attack_type", None),
                "level": message.get("level", "INFO")
            }) + "\n")
            log_file.flush()

            log_queue.task_done()


def log_to_txt_file(log_file, message, attack_type=None, level="INFO"):
    """
    Log messages to the file, handling special encoding issues.
    Logs can be in structured JSON format to include metadata like attack types and log levels.
    """
    log_entry = {
        "message": message,
        "timestamp": time.time(),
        "attack_type": attack_type,
        "level": level
    }
    log_file.write(json.dumps(log_entry) + "\n")
    log_file.flush()


def log_attack_to_db(attack_type, description):
    """
    Log an attack in the detected_attacks table with duplicate filtering.
    """
    global recent_attacks
    current_time = time.time()

    # Set cooldown (e.g., 10 seconds) to avoid duplicate logging
    cooldown_period = 10

    # Avoid logging the same attack within the cooldown period
    if attack_type in recent_attacks and (current_time - recent_attacks[attack_type]) < cooldown_period:
        return

    # Log attack since it hasn't been logged recently
    recent_attacks[attack_type] = current_time

    # Perform logging to the database using the absolute DB_PATH
    conn = sqlite3.connect(DB_PATH)  # Use absolute path to ensure the correct database is used
    try:
        c = conn.cursor()
        c.execute('''INSERT INTO detected_attacks (type, description, timestamp)
                     VALUES (?, ?, ?)''', (attack_type, description, current_time))
        conn.commit()
    except sqlite3.Error as e:
        print(f"Error logging attack to database: {e}")
    finally:
        conn.close()


def flush_packet_logs():
    """
    Flush any remaining logs in the queue to the log file.
    """
    log_queue.put("STOP")


def write_logs(log_file, message, attack_type):
    """
    Helper function to log an attack to both the log file and the database.
    """
    log_to_txt_file(log_file, message, attack_type)
    log_attack_to_db(attack_type, message)