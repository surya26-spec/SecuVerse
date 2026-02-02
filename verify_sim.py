import requests
import time
import sys
import threading

# Wait for server restart (assumed) or just try blindly
time.sleep(2)

print("Verifying 10-Part Simulation...")

try:
    # 1. Trigger Simulation
    print("Step 1: Triggering 10-Part Sim...")
    resp = requests.post('http://127.0.0.1:5001/api/simulate/10parts')
    if resp.status_code == 200:
        print(f"Success: {resp.json()}")
    else:
        print(f"Failed to trigger: {resp.text}")
        sys.exit(1)

    # 2. Poll for Data
    print("Step 2: Polling for data (waiting 10s for generation)...")
    time.sleep(10)
    
    resp_stats = requests.get('http://127.0.0.1:5001/api/part_stats')
    if resp_stats.status_code == 200:
        data = resp_stats.json()
        print(f"Received Stats Data Points: {len(data)}")
        if len(data) > 0:
            print("Sample Data Point:", list(data.items())[0])
            print("Verification PASSED: Live data is flowing.")
        else:
            print("Verification WARNING: No data points returned yet.")
            
    else:
        print(f"Failed to get stats: {resp_stats.status_code}")

except Exception as e:
    print(f"Verification Error: {e}")
    print("Ensure the server is running on port 5001.")
