import sqlite3
import time
from datetime import datetime

DB_NAME = 'ids_logs.db'

def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            src_ip TEXT,
            protocol TEXT,
            status TEXT,
            type TEXT,
            info TEXT
        )
    ''')
    
    # Users Table
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT
        )
    ''')
    
    # Create default admin if not exists
    try:
        c.execute("INSERT OR IGNORE INTO users (username, password) VALUES ('admin', 'admin')")
    except:
        pass

    conn.commit()
    conn.close()

def insert_log(log_entry):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('''
        INSERT INTO logs (timestamp, src_ip, protocol, status, type, info)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (
        log_entry['timestamp'],
        log_entry['src_ip'],
        log_entry['protocol'],
        log_entry['status'],
        log_entry['type'],
        log_entry['info']
    ))
    conn.commit()
    conn.close()

def check_user(username, password):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('SELECT password FROM users WHERE username = ?', (username,))
    row = c.fetchone()
    conn.close()
    
    if row and row[0] == password:
        return True
    return False

def get_recent_logs(limit=50):
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row # Return dict-like objects
    c = conn.cursor()
    c.execute('SELECT * FROM logs ORDER BY id DESC LIMIT ?', (limit,))
    rows = c.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_stats():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    
    # Count by type (Normal vs Intrusion)
    c.execute('SELECT type, COUNT(*) FROM logs GROUP BY type')
    type_counts = dict(c.fetchall())
    
    # Count by Protocol
    c.execute('SELECT protocol, COUNT(*) FROM logs GROUP BY protocol')
    proto_counts = dict(c.fetchall())
    
    conn.close()
    
    return {
        'type_counts': type_counts,
        'proto_counts': proto_counts
    }

def get_monitor_stats(seconds=30):
    """
    Returns counts of logs per second for the last N seconds, 
    grouped by src_ip (specifically for the 192.168.1.1-10 range).
    """
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    
    # We want a time series: timestamp (seconds) -> {ip1: count, ip2: count...}
    # This query gets counts per second per IP for the simulation range
    limit_time = datetime.now().timestamp() - seconds
    
    # SQLite doesn't have easy unix epoch in all versions, so we use string comparisons if format is consistent
    # Our format is '%Y-%m-%d %H:%M:%S'
    
    c.execute('''
        SELECT timestamp, src_ip, COUNT(*) 
        FROM logs 
        WHERE src_ip LIKE '192.168.1.%' 
        AND id > (SELECT MAX(id) - 10000 FROM logs) -- optimization hint
        GROUP BY timestamp, src_ip
        ORDER BY timestamp DESC
        LIMIT 200
    ''')
    
    rows = c.fetchall()
    conn.close()
    
    # Process into standard structure
    # { '12:00:01': {'192.168.1.1': 5, ...}, ... }
    data = {}
    for r in rows:
        # r[0] is now the full timestamp "YYYY-MM-DD HH:MM:SS"
        # We need to extract just the time part for the chart labels
        t_full = r[0]
        try:
            t = t_full.split(' ')[1] # Get HH:MM:SS
        except:
            t = t_full # Fallback if format is weird
            
        ip = r[1]
        count = r[2]
        if t not in data: data[t] = {}
        data[t][ip] = count
        
    return data

def get_part_statuses(seconds=5):
    """
    Returns the status (Normal/Intrusion) for each of the 10 parts
    based on the last N seconds of data.
    """
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    
    # Calculate time threshold
    # Timestamp format in DB is: YYYY-MM-DD HH:MM:SS
    # We use SQLite's datetime function
    
    c.execute(f'''
        SELECT src_ip, COUNT(*) 
        FROM logs 
        WHERE src_ip LIKE '192.168.1.%' 
        AND type != 'Normal'
        AND timestamp >= datetime('now', 'localtime', '-{seconds} seconds')
        GROUP BY src_ip
    ''')
    
    rows = dict(c.fetchall())
    conn.close()
    
    # Construct result: { '192.168.1.1': 'Normal', ... }
    statuses = {}
    for i in range(1, 11):
        ip = f"192.168.1.{i}"
        # If any intrusion logs found for this IP, it's 'Danger'
        if ip in rows and rows[ip] > 0:
            statuses[ip] = 'Intrusion'
        else:
            statuses[ip] = 'Normal'
            
    return statuses

def get_attack_counts(seconds=5):
    """
    Returns the count of attack packets for each of the 10 parts
    based on the last N seconds of data.
    """
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    
    c.execute(f'''
        SELECT src_ip, COUNT(*) 
        FROM logs 
        WHERE src_ip LIKE '192.168.1.%' 
        AND type != 'Normal'
        AND timestamp >= datetime('now', 'localtime', '-{seconds} seconds')
        GROUP BY src_ip
    ''')
    
    rows = dict(c.fetchall())
    conn.close()
    
    # Construct result: { '192.168.1.1': 5, ... }
    counts = {}
    for i in range(1, 11):
        ip = f"192.168.1.{i}"
        counts[ip] = rows.get(ip, 0)
            
    return counts

if __name__ == "__main__":
    init_db()
    print("Database initialized.")
