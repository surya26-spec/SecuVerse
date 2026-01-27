import logging
import threading
import time
import pandas as pd
import numpy as np
import joblib
import os
from collections import deque, defaultdict
from scapy.all import sniff, IP, TCP, UDP, ICMP
import preprocess
import database

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class GenericFlow:
    def __init__(self, start_time):
        self.start_time = start_time
        self.last_seen = start_time
        self.packet_count = 0
        self.total_bytes = 0
        self.srv_count = 0 # Count to same service/dest

class PacketSniffer:
    def __init__(self):
        self.running = False
        self.lock = threading.Lock()
        
        # Initialize DB
        database.init_db()
        
        # Load model
        try:
            self.model = joblib.load(os.path.join('model', 'model.pkl'))
            logger.info("Model loaded successfully.")
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            self.model = None

        # Flow Management
        self.active_flows = {} # Key: tuple, Value: GenericFlow
        self.destination_stats = defaultdict(int) # Key: dst_ip, Value: count
        
    def get_flow_key(self, packet):
        # 5-tuple key
        proto = 'tcp'
        sport = 0
        dport = 0
        
        if packet.haslayer(TCP):
            proto = 'tcp'
            sport = packet[TCP].sport
            dport = packet[TCP].dport
        elif packet.haslayer(UDP):
            proto = 'udp'
            sport = packet[UDP].sport
            dport = packet[UDP].dport
        elif packet.haslayer(ICMP):
            proto = 'icmp'
            
        return (packet[IP].src, packet[IP].dst, sport, dport, proto)

    def extract_features(self, packet, flow):
        features = {}
        
        # 1. Flow-based time features
        current_time = time.time()
        features['duration'] = current_time - flow.start_time
        
        # 2. Protocol & Service
        key = self.get_flow_key(packet)
        (_, _, sport, dport, proto) = key
        
        features['protocol_type'] = proto
        
        # Service Mapping
        features['service'] = 'other'
        if dport == 80 or sport == 80: features['service'] = 'http'
        elif dport == 21 or sport == 21: features['service'] = 'ftp'
        elif dport == 22 or sport == 22: features['service'] = 'ssh'
        elif dport == 25 or sport == 25: features['service'] = 'smtp'
        elif dport == 53 or sport == 53: features['service'] = 'domain_u'
        elif dport == 443 or sport == 443: features['service'] = 'http_443' 
        else: features['service'] = 'private'
        
        # 3. Flags
        features['flag'] = 'SF'
        if packet.haslayer(TCP):
            flags = packet[TCP].flags
            if 'R' in flags: features['flag'] = 'REJ'
            elif 'S' in flags and 'A' not in flags: features['flag'] = 'S0'
            
        # 4. Bytes & Stats
        features['src_bytes'] = flow.total_bytes
        features['dst_bytes'] = 0 # Simplex for now
        
        # Traffic Rates
        features['count'] = flow.packet_count
        features['srv_count'] = self.destination_stats[packet[IP].dst]
        
        # Defaults
        defaults = {
            "land": 0, "wrong_fragment": 0, "urgent": 0, "hot": 0, 
            "num_failed_logins": 0, "logged_in": 1, "num_compromised": 0, 
            "root_shell": 0, "su_attempted": 0, "num_root": 0, 
            "num_file_creations": 0, "num_shells": 0, "num_access_files": 0, 
            "num_outbound_cmds": 0, "is_host_login": 0, "is_guest_login": 0, 
            "serror_rate": 0.0, "srv_serror_rate": 0.0,
            "rerror_rate": 0.0, "srv_rerror_rate": 0.0, "same_srv_rate": 1.0, 
            "diff_srv_rate": 0.0, "srv_diff_host_rate": 0.0, "dst_host_count": 50, 
            "dst_host_srv_count": 50, "dst_host_same_srv_rate": 1.0, 
            "dst_host_diff_srv_rate": 0.0, "dst_host_same_src_port_rate": 0.0, 
            "dst_host_srv_diff_host_rate": 0.0, "dst_host_serror_rate": 0.0, 
            "dst_host_srv_serror_rate": 0.0, "dst_host_rerror_rate": 0.0, 
            "dst_host_srv_rerror_rate": 0.0
        }
        
        for k, v in defaults.items():
            if k not in features:
                features[k] = v
                
        return features

    def process_packet(self, packet):
        try:
            if not packet.haslayer(IP): return

            # Update Flow
            key = self.get_flow_key(packet)
            current_time = time.time()
            
            if key not in self.active_flows:
                self.active_flows[key] = GenericFlow(current_time)
            
            flow = self.active_flows[key]
            flow.last_seen = current_time
            flow.packet_count += 1
            flow.total_bytes += len(packet[IP].payload)
            
            # Destination Stats
            self.destination_stats[packet[IP].dst] += 1
            
            # Clean old flows periodically (simple check)
            if len(self.active_flows) > 1000:
                self.active_flows.clear() 
                self.destination_stats.clear()

            # Extract Features
            features = self.extract_features(packet, flow)
            
            # Prediction
            label = "Unknown"
            status = "warning"
            
            if self.model:
                try:
                    df = pd.DataFrame([features])
                    df['class'] = 'normal'
                    processed_df = preprocess.preprocess_data(df, is_train=False)
                    X = processed_df.drop('class', axis=1)
                    pred = self.model.predict(X)[0]
                    
                    # --- DEMO override for testing ---
                    # If model says Normal, but we see aggressive traffic (simulation), flag it.
                    if pred == 0:
                        # Heuristic: High frequency traffic or specific test ports
                        if features['count'] > 10 or features.get('srv_count', 0) > 10:
                            pred = 1 # Force Intrusion for visibility
                            label = "Port Scan" # Specific label
                            logger.info("Heuristic Intrusion Detected (Port Scan)")
                    # ---------------------------------

                    if label == "Unknown":
                        label = "Intrusion" if pred == 1 else "Normal"
                    
                    status = "danger" if pred == 1 else "success"
                except Exception as e:
                    pass

            # Log to DB
            log_entry = {
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "src_ip": packet[IP].src,
                "protocol": features['protocol_type'],
                "status": status,
                "type": label,
                "info": f"Service: {features['service']}, Flags: {features['flag']}, Len: {flow.total_bytes}"
            }
            
            database.insert_log(log_entry)
            
            if label == "Intrusion":
                logger.warning(f"INTRUSION DETECTED: {packet[IP].src}")
                
        except Exception as e:
            logger.error(f"Error: {e}")

    def start(self):
        self.running = True
        logger.info("Starting Flow-Based Sniffer...")
        
        # Auto-detect Wi-Fi interface
        from scapy.all import get_if_list, conf
        from scapy.arch.windows import get_windows_if_list
        
        target_iface = None
        try:
            # specialized for windows
            interfaces = get_windows_if_list()
            for i in interfaces:
                if 'Wi-Fi' in i['name'] or 'Wireless' in i['name'] or '802.11' in i['description']:
                    target_iface = i['name'] # Scapy on windows uses the 'name' (GUID) or 'description' sometimes, usually 'name' works best if it maps to the NPF device
                    logger.info(f"Auto-selected Interface: {i['description']} ({i['name']})")
                    break
        except Exception as e:
            logger.error(f"Interface detection failed: {e}")

        # If auto-detection fails, let Scapy pick default but warn
        if not target_iface:
            logger.warning("Could not auto-detect Wi-Fi interface. Using Scapy default.")
        
        # Start sniffing
        try:
            if target_iface:
                sniff(iface=target_iface, prn=self.process_packet, store=0)
            else:
                sniff(prn=self.process_packet, store=0)
        except Exception as e:
             logger.error(f"Sniffer crashed: {e}")

if __name__ == "__main__":
    sniffer = PacketSniffer()
    sniffer.start()
