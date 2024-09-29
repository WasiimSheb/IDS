from flask import Flask, render_template, jsonify, request
import sqlite3
import time
from src.shared import DIR

app = Flask(__name__)


# Helper function to get a database connection
def get_db_connection():
    return sqlite3.connect(DIR+'traffic.db', timeout=30)

# Initialize the database
def init_db():
    conn = get_db_connection()
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
    
    # Add index for performance
    c.execute("CREATE INDEX IF NOT EXISTS idx_protocol ON flow_data (protocol)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_src_ip ON traffic_data (src_ip)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_dst_ip ON traffic_data (dst_ip)")
    
    conn.commit()
    conn.close()

# Log an attack into the detected_attacks table
def log_attack(attack_type, description):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('''INSERT INTO detected_attacks (type, description, timestamp)
                 VALUES (?, ?, ?)''', (attack_type, description, time.time()))
    conn.commit()
    conn.close()


# Route to render the main dashboard
@app.route('/')
def index():
    return render_template('index.html')

# Route to return paginated traffic data for the frontend
@app.route('/data', methods=['GET'])
def get_data():
    page = int(request.args.get('page', 1))
    page_size = int(request.args.get('page_size', 50))
    start = (page - 1) * page_size

    conn = get_db_connection()
    c = conn.cursor()

    c.execute("""
        SELECT time, src_ip, src_port, dst_ip, dst_port, protocol, raw_data
        FROM traffic_data
        LIMIT ?, ?
    """, (start, page_size))
    data = c.fetchall()

    conn.close()

    return jsonify({
        'data': [
            {
                'time': f'{row[0]:.6f}',  # Use six decimal places for microsecond precision
                'src_ip': row[1],
                'src_port': row[2],
                'dst_ip': row[3],
                'dst_port': row[4],
                'protocol': row[5],
                'raw_data': len(row[6])
            } for row in data
        ]
    })

# Route to return flow statistics for the frontend
@app.route('/flows')
def get_flows():
    conn = get_db_connection()
    c = conn.cursor()

    # Calculate total flows and total bytes transferred from the flow_data table
    c.execute("SELECT COUNT(*), SUM(total_bytes) FROM flow_data")
    total_flows, total_bytes = c.fetchone()

    conn.close()

    return jsonify({
        'total_flows': total_flows if total_flows else 0,
        'total_bytes': total_bytes if total_bytes else 0
    })


@app.route('/stats')
def get_stats():
    conn = get_db_connection()
    c = conn.cursor()

    # Get total packets and total data transferred from traffic_data
    c.execute("SELECT COUNT(*), SUM(LENGTH(raw_data)) FROM traffic_data")
    total_packets, total_data_transferred = c.fetchone()

    # Divide total_data_transferred by 2 to fix double-counting
    total_data_transferred = total_data_transferred // 2 if total_data_transferred else 0

    # Get detected attacks from detected_attacks table
    c.execute("SELECT COUNT(*) FROM detected_attacks")

    detected_attacks = c.fetchone()[0]

    # Get the number of flows from flow_data
    c.execute("SELECT COUNT(*) FROM flow_data")
    num_flows = c.fetchone()[0]

    conn.close()

    return jsonify({
        'total_packets': total_packets if total_packets else 0,
        'total_data_transferred': total_data_transferred if total_data_transferred else 0,
        'num_flows': num_flows if num_flows else 0,
        'detected_attacks': detected_attacks if detected_attacks else 0
    })



# Route to return detected attacks with pagination
@app.route('/attacks')
def get_attacks():
    try:
        conn = get_db_connection()
        conn.row_factory = sqlite3.Row
        c = conn.cursor()

        page = int(request.args.get('page', 1))
        page_size = int(request.args.get('page_size', 50))
        offset = (page - 1) * page_size

        c.execute('SELECT type, description, timestamp FROM detected_attacks ORDER BY timestamp DESC LIMIT ? OFFSET ?', (page_size, offset))
        rows = c.fetchall()

        attack_data = [{'type': row['type'], 'description': row['description'], 'timestamp': row['timestamp']} for row in rows]

    except sqlite3.OperationalError as e:
        print(f"Database error: {e}")
        return jsonify({'error': 'Database is locked or unavailable'}), 500

    finally:
        conn.close()

    return jsonify({
        'attacks': attack_data,
        'page': page,
        'page_size': page_size
    })

if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0')
