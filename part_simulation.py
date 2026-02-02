import pandas as pd
import threading
import time
import random
import os
import database
from datetime import datetime

# Configuration
TOTAL_DURATION = 300  # 5 minutes
UPDATE_INTERVAL = 2   # seconds
PARTS_COUNT = 10

class PartSimulator:
    def __init__(self, base_dir):
        self.base_dir = base_dir
        self.is_running = False
        self.thread = None
        self.dataset_chunks = []
        
        # Load and split data on init
        self.load_data()

    def load_data(self):
        csv_path = os.path.join(self.base_dir, "dataset", "NSL_KDD_Test.csv")
        if not os.path.exists(csv_path):
            print(f"Error: Dataset not found at {csv_path}")
            return

        try:
            # Load with header=None since the file has no headers
            df = pd.read_csv(csv_path, header=None)
            
            # Mix the traffic: Shuffle the dataset so we get a mix of normal and attack
            df = df.sample(frac=1).reset_index(drop=True)
            
            # Simple chunking: Split dataframe into 10 roughly equal parts
            chunk_size = len(df) // PARTS_COUNT
            for i in range(PARTS_COUNT):
                start = i * chunk_size
                end = (i + 1) * chunk_size if i < PARTS_COUNT - 1 else len(df)
                self.dataset_chunks.append(df.iloc[start:end])
                
            print(f"Loaded {len(df)} rows, split into {PARTS_COUNT} chunks of ~{chunk_size} rows.")
            
        except Exception as e:
            print(f"Failed to load simulation data: {e}")

    def start_simulation(self):
        if self.is_running:
            return "Simulation already running."
        
        self.is_running = True
        self.thread = threading.Thread(target=self._run_sim_loop, daemon=True)
        self.thread.start()
        return "Started 10-Part Live Simulation."

    def stop_simulation(self):
        self.is_running = False
        return "Simulation stopped."

    def _run_sim_loop(self):
        start_time = time.time()
        
        # Iterators for each chunk to execute sequentially within the chunk
        # or we can pick randomly. Sequential feels more like "streaming file playback"
        iterators = [0] * PARTS_COUNT
        
        print("Starting 5-minute simulation loop...")
        
        while self.is_running and (time.time() - start_time < TOTAL_DURATION):
            
            # For each "Part" (1-10)
            for i in range(PARTS_COUNT):
                # Generate a random number of packets for this step to make the graph interesting (fluctuate)
                packets_this_tick = random.randint(1, 4) 
                
                chunk = self.dataset_chunks[i]
                current_idx = iterators[i]
                
                for _ in range(packets_this_tick):
                    if current_idx >= len(chunk):
                        current_idx = 0 # Loop back to start of chunk if we run out
                        
                    row = chunk.iloc[current_idx]
                    current_idx += 1
                    
                    # Construct Log Entry
                    # Simulated IP: 192.168.1.{i+1}
                    src_ip = f"192.168.1.{i+1}"
                    
                    # Extract info safely - Access by integer position since no headers
                    protocol = row.iloc[1] if len(row) > 1 else 'TCP'
                    service = row.iloc[2] if len(row) > 2 else 'unknown'
                    flag = row.iloc[3] if len(row) > 3 else 'SF'
                    
                    # Correct Label Extraction: Last column
                    label = row.iloc[-1] if len(row) > 0 else 'normal'
                    label_str = str(label).lower()
                    
                    # Determine Status
                    if 'normal' in label_str:
                        type_ = 'Normal'
                        status = 'success'
                    else:
                        type_ = 'Intrusion' # or label_str
                        status = 'danger'

                    log_entry = {
                        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'src_ip': src_ip,
                        'protocol': str(protocol).upper(),
                        'status': status,
                        'type': type_,
                        'info': f"Part {i+1} Stream | Svc: {service} | Flag: {flag}"
                    }
                    
                    # Insert into DB
                    try:
                        database.insert_log(log_entry)
                    except Exception as e:
                        print(f"Sim insert error: {e}")
                
                # Update iterator
                iterators[i] = current_idx

            time.sleep(UPDATE_INTERVAL)
            
        self.is_running = False
        print("Simulation loop finished.")
