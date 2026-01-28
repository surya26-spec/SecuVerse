from flask import Flask, render_template, request, session, redirect, url_for
from datetime import datetime
import joblib
import pandas as pd
import preprocess
import os
import numpy as np
from functools import wraps

app = Flask(__name__)
# Secret key needed for sessions
app.secret_key = os.urandom(24)  # Random key invalidates sessions on server restart

# Disable caching for static files in development
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0

# Auth Decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login', next=request.url))
            
        # Idle Timeout Check (2 minutes = 120 seconds)
        now = datetime.now().timestamp()
        last_active = session.get('last_active')
        
        if last_active and (now - last_active > 120):
            session.clear()
            return redirect(url_for('login', error="Session expired due to inactivity."))
            
        session['last_active'] = now
        return f(*args, **kwargs)
    return decorated_function

# Basic route
import threading
from sniffer import PacketSniffer
import time

import database
import phishing
import attack_sim  # Imported the new module
import part_simulation

# Initialize Part Simulator
part_sim = part_simulation.PartSimulator(os.path.dirname(os.path.abspath(__file__)))
import part_simulation

# Initialize Part Simulator
part_sim = part_simulation.PartSimulator(os.path.dirname(os.path.abspath(__file__)))

# Initialize Sniffer Global
sniffer = PacketSniffer()

def start_sniffer():
    try:
        sniffer.start()
    except Exception as e:
        print(f"Sniffer failed to start: {e}")

# Start sniffer thread daemon
sniffer_thread = threading.Thread(target=start_sniffer, daemon=True)
sniffer_thread.start()

@app.route('/')
@login_required
def home():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if database.check_user(username, password):
            session['user'] = username
            next_page = request.args.get('next')
            return redirect(next_page or url_for('home'))
        else:
            return render_template('login.html', error="Invalid Credentials")
            
    return render_template('login.html', error=request.args.get('error'))

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

@app.route('/api/live-data')
def live_data():
    # Fetch from DB
    logs = database.get_recent_logs()
    return {'logs': logs}

@app.route('/api/stats')
def stats():
    # Fetch stats for charts
    stats = database.get_stats()
    return stats

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/honeypot', methods=['GET', 'POST'])
def honeypot():
    if request.method == 'POST':
        # Log the attempt to the database
        username = request.form.get('username')
        password = request.form.get('password')
        
        log_type = 'Brute Force'
        if "'" in username or "OR" in username.upper() or "UNION" in username.upper():
            log_type = 'SQL Injection'

        log_entry = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'src_ip': request.remote_addr,
            'protocol': 'HTTP',
            'status': 'Alert',
            'type': log_type,
            'info': f"Login Attempt - User: {username}, Pass: {password}"
        }
        
        try:
            database.insert_log(log_entry)
            print(f"Honeypot triggered and logged! User: {username}")
        except Exception as e:
            print(f"Failed to log honeypot attempt: {e}")

        return render_template('honeypot.html', message="Invalid credentials. This event has been logged.")
    return render_template('honeypot.html')

    return render_template('honeypot.html')

@app.route('/phishing', methods=['GET', 'POST'])
@login_required
def phishing_checker():
    if request.method == 'POST':
        url = request.form.get('url')
        if not url:
            return render_template('phishing.html')
            
        result, probability, details = phishing.predict_phishing(url)
        
        # Log the check
        try:
            log_entry = {
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'src_ip': request.remote_addr,
                'protocol': 'HTTP',
                'status': 'danger' if result == 'Phishing' else 'success',
                'type': 'Phishing',
                'info': f"URL Check: {url[:30]}... ({result})"
            }
            database.insert_log(log_entry)
        except Exception as e:
            print(f"Failed to log phishing check: {e}")

        return render_template('phishing.html', result=result, probability=probability, details=details, url=url)
        
    return render_template('phishing.html')

@app.route('/predict', methods=['POST'])
@login_required
def predict():
    if request.method == 'POST':
        try:
            # Load model (lazy load or global load)
            model_path = os.path.join('model', 'model.pkl')
            if not os.path.exists(model_path):
                return render_template('index.html', prediction="Error: Model not trained yet.")
            
            model = joblib.load(model_path)
            
            # Form data extraction
            # We map form fields to DataFrame columns
            # The model expects 41 features. 
            # For this demo, we will accept a few key features from the UI and defaults for others
            
            # Full column list from preprocess.py
            columns = ["duration","protocol_type","service","flag","src_bytes",
            "dst_bytes","land","wrong_fragment","urgent","hot","num_failed_logins",
            "logged_in","num_compromised","root_shell","su_attempted","num_root",
            "num_file_creations","num_shells","num_access_files","num_outbound_cmds",
            "is_host_login","is_guest_login","count","srv_count","serror_rate",
            "srv_serror_rate","rerror_rate","srv_rerror_rate","same_srv_rate",
            "diff_srv_rate","srv_diff_host_rate","dst_host_count","dst_host_srv_count",
            "dst_host_same_srv_rate","dst_host_diff_srv_rate","dst_host_same_src_port_rate",
            "dst_host_srv_diff_host_rate","dst_host_serror_rate","dst_host_srv_serror_rate",
            "dst_host_rerror_rate","dst_host_srv_rerror_rate"]
            
            input_data = {}
            
            # Get data from form or use defaults
            for col in columns:
                if col in request.form and request.form[col]:
                    # Attempt to convert to appropriate type
                    try:
                        input_data[col] = float(request.form[col])
                    except ValueError:
                         input_data[col] = request.form[col]
                else:
                    # Healthy defaults
                    if col == 'protocol_type': input_data[col] = 'tcp'
                    elif col == 'service': input_data[col] = 'http'
                    elif col == 'flag': input_data[col] = 'SF'
                    else: input_data[col] = 0
            
            # Create DataFrame
            df = pd.DataFrame([input_data])
            
            # Add dummy class column for preprocess compatibility
            df['class'] = 'normal'
            
            # Preprocess
            processed_df = preprocess.preprocess_data(df, is_train=False)
            
            # Predict
            features = processed_df.drop('class', axis=1)
            prediction = model.predict(features)[0]
            
            result = "Network Intrusion Detected!" if prediction == 1 else "Normal Traffic"
            result_class = "danger" if prediction == 1 else "success"
            
            # Log the manual analysis to the database
            try:
                log_entry = {
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'src_ip': request.remote_addr,
                    'protocol': request.form.get('protocol_type', 'tcp').upper(),
                    'status': result_class,
                    'type': 'Intrusion' if prediction == 1 else 'Normal',
                    'info': f"Manual Analysis - Service: {request.form.get('service', 'unknown')}"
                }
                database.insert_log(log_entry)
            except Exception as e:
                print(f"Failed to log analysis: {e}")
            
            return render_template('index.html', prediction=result, result_class=result_class)
            
        except Exception as e:
            return render_template('index.html', prediction=f"Error: {str(e)}", result_class="warning")

@app.route('/api/report_attack', methods=['POST'])
def report_attack():
    # Allow the attack simulator to report itself for specific educational demos
    # where network sniffing might be limited (e.g. localhost windows loopback)
    data = request.json
    try:
        log_entry = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'src_ip': request.remote_addr,
            'protocol': 'TCP',
            'status': 'danger', # Always red for attacks
            'type': data.get('type', 'Intrusion'),
            'info': data.get('info', 'Simulated Attack Detected')
        }
        database.insert_log(log_entry)
        return {'status': 'success'}
    except Exception as e:
        return {'status': 'error', 'message': str(e)}

@app.route('/api/simulate/bruteforce', methods=['POST'])
def sim_bruteforce():
    target = request.url_root + 'honeypot'
    msg = attack_sim.simulate_brute_force(target)
    return {'status': 'success', 'message': msg}

@app.route('/api/simulate/portscan', methods=['POST'])
def sim_portscan():
    # Target localhost
    msg = attack_sim.simulate_port_scan('127.0.0.1')
    return {'status': 'success', 'message': msg}

@app.route('/api/simulate/injection', methods=['POST'])
def sim_injection():
    target = request.url_root + 'honeypot'
    msg = attack_sim.simulate_sql_injection(target)
    return {'status': 'success', 'message': msg}

@app.route('/api/simulate/phishing', methods=['POST'])
def sim_phishing():
    # Log a simulated phishing event so the counter increments
    try:
        log_entry = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'src_ip': request.remote_addr,
            'protocol': 'HTTP',
            'status': 'danger', 
            'type': 'Phishing',
            'info': 'Simulated Phishing Attack Generated'
        }
        database.insert_log(log_entry)
    except Exception as e:
        print(f"Failed to log sim phishing: {e}")

    # Return the URL for the user to try manually if they want validation
    return {'status': 'success', 'url': 'http://secure-login-attempt.com.malicious-site.net/verify', 'message': 'Simulated phishing event generated and logged.'}

@app.route('/api/simulate/10parts', methods=['POST'])
def sim_10parts():
    msg = part_sim.start_simulation()
    return {'status': 'success', 'message': msg}

@app.route('/api/part_stats')
def part_stats():
    # Fetch stats for the 10-part monitor graph
    data = database.get_monitor_stats()
    return data

@app.route('/api/part_status')
def part_status():
    # Fetch current status (Normal vs Intrusion) for the 10 parts
    return database.get_part_statuses()

@app.route('/api/attack_stats')
def attack_stats():
    # Fetch attack counts for the radar chart
    return database.get_attack_counts()


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True, port=5001)
