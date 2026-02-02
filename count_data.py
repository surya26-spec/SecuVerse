import pandas as pd
import sqlite3
import os

def count_csv_rows(filepath):
    if os.path.exists(filepath):
        try:
            # efficient way to count lines without loading whole file if huge, but pandas is fine for 14MB
            # Just using pandas to be safe with CSV parsing nuances
            df = pd.read_csv(filepath)
            return len(df)
        except Exception as e:
            return f"Error reading {filepath}: {e}"
    return "File not found"

def count_db_rows(db_path):
    if os.path.exists(db_path):
        try:
            conn = sqlite3.connect(db_path)
            c = conn.cursor()
            c.execute("SELECT COUNT(*) FROM logs")
            count = c.fetchone()[0]
            conn.close()
            return count
        except Exception as e:
            return f"Error reading DB: {e}"
    return "Database not found"

base_dir = r"c:/Users/GAJIN S/Music/ai_2/AI_IDS/AI_IDS"
train_csv = os.path.join(base_dir, "dataset", "NSL_KDD_Train.csv")
test_csv = os.path.join(base_dir, "dataset", "NSL_KDD_Test.csv")
db_file = os.path.join(base_dir, "ids_logs.db")

print("--- Dataset Counts ---")
print(f"Train Data (NSL_KDD_Train.csv): {count_csv_rows(train_csv)}")
print(f"Test Data (NSL_KDD_Test.csv):   {count_csv_rows(test_csv)}")
print(f"Total CSV Data:                 {count_csv_rows(train_csv) + count_csv_rows(test_csv)}")

print("\n--- Database Logs ---")
print(f"Live Logs (ids_logs.db):        {count_db_rows(db_file)}")
