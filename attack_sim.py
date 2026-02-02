import requests
import socket
import threading
import time
import random

def simulate_brute_force(target_url, username="admin", count=5):
    """
    Simulates a brute force attack by sending multiple POST requests with random passwords.
    """
    results = []
    
    def attack():
        passwords = ['123456', 'password', 'admin123', 'qwerty', 'letmein']
        for i in range(count):
            pwd = passwords[i % len(passwords)]
            try:
                # Assuming /honeypot is the login endpoint we want to test
                # or we can test the generic login
                data = {'username': username, 'password': pwd}
                response = requests.post(target_url, data=data)
                results.append(f"Attempt {i+1}: Sent {username}:{pwd} -> Status {response.status_code}")
            except Exception as e:
                results.append(f"Attempt {i+1}: Failed -> {e}")
            time.sleep(0.5) # Slight delay to not overwhelm immediately
    
    # Run in thread to not block main server response
    t = threading.Thread(target=attack)
    t.start()
    return "Brute Force Attack Started. Check logs."

def get_local_ip():
    try:
        # Connect to an external server (doesn't actually send data) to get the local interface IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except:
        return "127.0.0.1"

def simulate_port_scan(target_ip, ports=None):
    """
    Simulates a port scan on the target IP.
    """
    # If scanning localhost, switch to LAN IP to ensure Sniffer (on Wi-Fi) sees it
    if target_ip in ["127.0.0.1", "localhost"]:
        target_ip = get_local_ip()

    if ports is None:
        ports = [21, 22, 23, 25, 53, 80, 443, 3306, 8080, 5000, 5001]
        
    results = []
    
    def scan():
        # Scapy sniffer needs to see packets. 
        # Standard socket connect might be too quiet or fast, but let's try.
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((target_ip, port))
                if result == 0:
                    results.append(f"Port {port}: OPEN")
                else:
                    results.append(f"Port {port}: CLOSED")
                sock.close()
            except:
                pass
            time.sleep(0.1) # Small delay to separate packets slightly
    
    t = threading.Thread(target=scan)
    t.start()
    
    # --- REPORT TO API ---
    # Ensure dashboard sees it even if sniffer misses loopback
    try:
        requests.post(f"http://{target_ip}:5001/api/report_attack", json={
            'type': 'Port Scan',
            'info': f"Port Scan Simulated on {target_ip} (Ports: {len(ports)})"
        })
    except:
        pass
    # ---------------------
    
    return f"Port Scan Started on {target_ip}. Check 'Recent Activity Log' for traffic."

def simulate_sql_injection(target_url):
    """
    Simulates a simple SQL Injection attempt via GET/POST.
    """
    payloads = ["' OR '1'='1", "admin' --", "' OR 1=1; DROP TABLE users; --"]
    
    def attack():
        for payload in payloads:
            try:
                # Try GET
                requests.get(target_url, params={'search': payload})
                # Try POST (like on the honeypot)
                requests.post(target_url, data={'username': payload, 'password': 'password'})
            except:
                pass
                
    t = threading.Thread(target=attack)
    t.start()
    return "SQL Injection Simulation Started."

if __name__ == "__main__":
    import sys
    
    print("""
    =============================================
       AI IDS ATTACK SIMULATOR (EDUCATIONAL)
    =============================================
    Usage: python attack_sim.py <type> [target]
    
    Types:
      - bruteforce  : Simulates failed login attempts
      - portscan    : Scans common ports
      - injection   : Simulates SQL Injection patterns
      - phishing    : Checks a known malicious URL
      
    Example: python attack_sim.py portscan 127.0.0.1
    """)
    
    if len(sys.argv) < 2:
        sys.exit(1)
        
    attack_type = sys.argv[1].lower()
    target_ip = sys.argv[2] if len(sys.argv) > 2 else "127.0.0.1"
    target_url = f"http://{target_ip}:5001/honeypot"
    
    print(f"[*] Targeting: {target_ip} ({target_url})")
    print(f"[*] Launching {attack_type} attack...")
    
    if attack_type == "bruteforce":
        msg = simulate_brute_force(target_url)
        print(f"[+] {msg}")
    elif attack_type == "portscan":
        msg = simulate_port_scan(target_ip)
        print(f"[+] {msg}")
    elif attack_type == "injection":
        msg = simulate_sql_injection(target_url)
        print(f"[+] {msg}")
    elif attack_type == "phishing":
        print("[*] Simulating Phishing Link Check...")
        # Since phishing is a clear-cut check, we just define a malicious URL
        url = "http://secure-login-attempt.com.malicious-site.net/verify"
        print(f"    URL: {url}")
        print("    -> Copy this URL and paste it into the Phishing Checker on the website.")
    else:
        print("[-] Unknown attack type.")

    # Keep alive for threads
    time.sleep(5)
    print("[*] Simulation commands sent. Check Dashboard for alerts.")
