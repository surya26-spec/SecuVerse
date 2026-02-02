import pandas as pd
from sklearn.preprocessing import LabelEncoder, StandardScaler
import joblib
import os

def load_data(path):
    # NSL-KDD dataset columns based on standard documentation
    columns = ["duration","protocol_type","service","flag","src_bytes",
    "dst_bytes","land","wrong_fragment","urgent","hot","num_failed_logins",
    "logged_in","num_compromised","root_shell","su_attempted","num_root",
    "num_file_creations","num_shells","num_access_files","num_outbound_cmds",
    "is_host_login","is_guest_login","count","srv_count","serror_rate",
    "srv_serror_rate","rerror_rate","srv_rerror_rate","same_srv_rate",
    "diff_srv_rate","srv_diff_host_rate","dst_host_count","dst_host_srv_count",
    "dst_host_same_srv_rate","dst_host_diff_srv_rate","dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate","dst_host_serror_rate","dst_host_srv_serror_rate",
    "dst_host_rerror_rate","dst_host_srv_rerror_rate","class"]
    
    # Check if header exists or not. The view_file output showed no header, just raw csv.
    df = pd.read_csv(path, names=columns)
    return df

def preprocess_data(df, is_train=True):
    # Encode categorical features
    # We need to save encoders to use same mapping for training and inference
    encoders = {}
    if is_train:
        for col in ['protocol_type', 'service', 'flag']:
            le = LabelEncoder()
            df[col] = le.fit_transform(df[col])
            encoders[col] = le
        
        # Save encoders
        joblib.dump(encoders, 'model/encoders.pkl')
        
        # Encode target 'class' - map normal to 0, everything else to 1 (intrusion)
        # Or keep multi-class if desired. Let's do binary classification for simplicity first: Normal vs Attack
        #df['class'] = df['class'].apply(lambda x: 0 if x == 'normal' else 1)
    else:
        # Load encoders
        encoders = joblib.load('model/encoders.pkl')
        for col in ['protocol_type', 'service', 'flag']:
            le = encoders[col]
            # Handle potential unseen labels in test/prod by assigning a default or handling error
            # For simplicity here, we assume test data matches known categories or we might need robust handling
            # A simple trick is to map unknown to a 'unknown' class if encoder supports it, or use fallback
            # Here using map and fillna for robust handling
            df[col] = df[col].map(lambda s: s if s in le.classes_ else -1)
            # Re-fit is not correct, we need transform. But standard le.transform crashes on unseen.
            # So we implemented a safe mapped transform above. 
            # Ideally we might just fit_transform on combined data, but for an app we need a saved state.
            # Let's try standard transform and assume consistency for now, or use a robust method.
            
            # Re-implementation for robust encoding:
            known_classes = set(le.classes_)
            df[col] = df[col].apply(lambda x: x if x in known_classes else list(known_classes)[0]) # Fallback to first class
            df[col] = le.transform(df[col])

    # Feature scaling
    scaler = StandardScaler()
    
    # Exclude target 'class' from scaling
    feature_cols = [c for c in df.columns if c != 'class']
    
    if is_train:
        df[feature_cols] = scaler.fit_transform(df[feature_cols])
        joblib.dump(scaler, 'model/scaler.pkl')
    else:
        scaler = joblib.load('model/scaler.pkl')
        df[feature_cols] = scaler.transform(df[feature_cols])
        
    return df

if __name__ == "__main__":
    if not os.path.exists('model'):
        os.makedirs('model')
    print("Preprocessing script ready.")
