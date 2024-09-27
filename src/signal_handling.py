import signal
import sys
from logging_utils import log_queue

def handle_signal(signal_received, frame):
    print("Signal received, shutting down gracefully...")
    log_queue.put("STOP")
    sys.exit(0)

def setup_signal_handlers():
    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)
