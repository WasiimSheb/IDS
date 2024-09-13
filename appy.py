from flask import Flask, render_template, jsonify
import sqlite3

app = Flask(__name__)

# Route to render the main dashboard
@app.route('/')
def index():
    return render_template('index.html')

# Route to return traffic data for the frontend
@app.route('/data')
def get_data():
    conn = sqlite3.connect('traffic.db')
    c = conn.cursor()
    # Select the most recent 50 entries from the database
    c.execute("SELECT time, src_ip, dst_ip, protocol, src_port, dst_port, raw_data FROM traffic_data ORDER BY time DESC LIMIT 50")
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
            'raw_data': row[6]
        }
        for row in rows
    ]

    return jsonify(traffic_data)

# Start the Flask server
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
