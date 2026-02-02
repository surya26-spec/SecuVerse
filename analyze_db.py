import sqlite3

def analyze():
    conn = sqlite3.connect('ids_logs.db')
    c = conn.cursor()
    c.execute('''
        SELECT src_ip, 
               SUM(CASE WHEN type != 'Normal' THEN 1 ELSE 0 END) as attack_count,
               COUNT(*) as total_count
        FROM logs 
        WHERE src_ip LIKE '192.168.1.%' 
        AND id > (SELECT MAX(id) - 2000 FROM logs)
        GROUP BY src_ip
    ''')
    
    print(f"{'IP':<15} | {'Attacks':<10} | {'Total':<10} | {'Ratio':<10}")
    print("-" * 50)
    for row in c.fetchall():
        ip, attacks, total = row
        ratio = attacks / total if total > 0 else 0
        print(f"{ip:<15} | {attacks:<10} | {total:<10} | {ratio:.2f}")
    
    conn.close()

if __name__ == "__main__":
    analyze()
