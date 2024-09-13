from flask import Flask, render_template, jsonify, request
import sqlite3
import time

app = Flask(__name__)

# Initialize the database
def init_db():
    """
    Initialize the database and create necessary tables.
    """
    conn = sqlite3.connect('traffic.db')
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
    
    conn.commit()
    conn.close()

# Log an attack into the detected_attacks table
def log_attack(attack_type, description):
    conn = sqlite3.connect('traffic.db')
    c = conn.cursor()

    # Insert detected attack into the database
    c.execute('''INSERT INTO detected_attacks (type, description, timestamp)
                 VALUES (?, ?, ?)''', (attack_type, description, time.time()))
    conn.commit()
    conn.close()

# Route to render the main dashboard
@app.route('/')
def index():
    return render_template('index.html')

# Route to return paginated traffic data for the frontend
@app.route('/data')
def get_data():
    # Get page and page_size from the query parameters, default to page 1, size 50
    page = int(request.args.get('page', 1))
    page_size = int(request.args.get('page_size', 50))

    offset = (page - 1) * page_size  # Calculate the offset

    conn = sqlite3.connect('traffic.db')
    c = conn.cursor()
    
    # Get the total number of rows
    c.execute("SELECT COUNT(*) FROM traffic_data")
    total_rows = c.fetchone()[0]
    
    # Select the most recent entries with LIMIT and OFFSET for pagination
    c.execute("SELECT time, src_ip, dst_ip, protocol, src_port, dst_port, raw_data FROM traffic_data ORDER BY time DESC LIMIT ? OFFSET ?", (page_size, offset))
    rows = c.fetchall()
    conn.close()

    # Convert the rows into a list of dictionaries
    traffic_data = [
        {
            'time': row[0],
            'src_ip': row[1],
            'dst_ip': row[2],
            'protocol': row[3],
            'src_port': row[4],
            'dst_port': row[5],
            'raw_data': len(row[6])  # Size of the raw packet data
        }
        for row in rows
    ]

    return jsonify({
        'data': traffic_data,
        'total_rows': total_rows,
        'page': page,
        'page_size': page_size
    })

# Route to return flow statistics for the frontend
@app.route('/flows')
def get_flows():
    conn = sqlite3.connect('traffic.db')
    c = conn.cursor()

    # Calculate total flows and total bytes transferred from the flow_data table
    c.execute("SELECT COUNT(*), SUM(total_bytes) FROM flow_data")
    total_flows, total_bytes = c.fetchone()

    conn.close()

    return jsonify({
        'total_flows': total_flows if total_flows else 0,
        'total_bytes': total_bytes if total_bytes else 0
    })

# Route to return general stats (Total Packets, Total Data Transferred, etc.)
@app.route('/stats')
def get_stats():
    conn = sqlite3.connect('traffic.db')
    c = conn.cursor()

    # Get total packets and total data transferred from traffic_data
    c.execute("SELECT COUNT(*), SUM(LENGTH(raw_data)) FROM traffic_data")
    total_packets, total_data_transferred = c.fetchone()

    # Get detected attacks from some hypothetical detection mechanism in the flow_data
    c.execute("SELECT COUNT(*) FROM flow_data WHERE protocol = 'TCP' AND packet_count > 1000")  # Example rule for detected attack
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

@app.route('/attacks')
def get_attacks():
    conn = sqlite3.connect('traffic.db')
    c = conn.cursor()

    # Query the detected attacks
    c.execute('SELECT type, description, timestamp FROM detected_attacks ORDER BY timestamp DESC')
    rows = c.fetchall()
    conn.close()

    # Convert the rows into a list of dictionaries
    attack_data = [{'type': row[0], 'description': row[1], 'timestamp': row[2]} for row in rows]

    return jsonify({
        'attacks': attack_data
    })

if __name__ == '__main__':
    init_db()  # Ensure tables are created before app starts
    app.run(debug=True, host='0.0.0.0')
