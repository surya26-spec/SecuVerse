import sqlite3
import os

# Ensure we are looking for the file in the current directory
db_file = 'ids_logs.db'

if not os.path.exists(db_file):
    print(f"Error: '{db_file}' not found in the current directory.")
    print(f"Current directory: {os.getcwd()}")
    print("Please run this script from the folder containing the database.")
else:
    conn = sqlite3.connect(db_file)
    print("\n--- Recent Logs ---")
    try:
        cursor = conn.execute('SELECT * FROM logs ORDER BY id DESC LIMIT 5')
        rows = cursor.fetchall()
        if not rows:
            print("No logs found.")
        for row in rows:
            print(row)
    except sqlite3.OperationalError as e:
        print(f"Database error: {e}")
        print("The table 'logs' might not exist.")
    
    conn.close()
