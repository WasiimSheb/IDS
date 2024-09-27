from collections import defaultdict

flows = defaultdict(dict)  # The shared dictionary for tracking network flows.

DIR = '/app/db/traffic.db'  # The directory where the SQLite database is stored.