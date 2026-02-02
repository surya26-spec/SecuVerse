
# SecuVerse (AI-IDS)

SecuVerse is an AI-Based Intrusion Detection System (AI-IDS) designed to
identify malicious and anomalous network behavior using intelligent
analysis rather than static rule-based firewalls.

## Features
- AI-driven intrusion detection
- Network traffic monitoring
- Attack and phishing simulation modules
- Dataset-driven ML training (NSL-KDD)
- Web dashboard for visualization

## Project Structure
- `app.py` – Main application
- `sniffer.py` – Network packet capture
- `model/` – Trained ML models and encoders
- `dataset/` – NSL-KDD training and test data
- `templates/` & `static/` – Web UI
- `Documentation_Site/` – Project documentation site

## Event
This project was developed and showcased at **HackXpo’26** under the name **SecuVerse**.

# AI-Based Intrusion Detection System (AI-IDS)

A Network Intrusion Detection System using Machine Learning (Random Forest) trained on the NSL-KDD dataset. This project includes a Flask web interface for real-time traffic analysis, a honeypot simulation, and a security dashboard.

## Project Structure
```
AI_IDS/
├── dataset/            # NSL-KDD dataset files
├── model/              # Trained models (ids_model.pkl, scaler.pkl)
├── templates/          # HTML Templates
│   ├── index.html      # Main generic traffic analysis
│   ├── honeypot.html   # Fake login page (Honeypot)
│   └── dashboard.html  # Security Dashboard
├── static/             # CSS and assets
├── app.py              # Flask Application
├── train.py            # Model training script
├── preprocess.py       # Data preprocessing utilities
└── requirements.txt    # Python dependencies
```

## Setup Instructions

1.  **Install Dependencies**
    Ensure you have Python installed. Install the required libraries:
    ```bash
    pip install -r requirements.txt
    ```

2.  **Train the Model**
    Before running the app, you need to train the model. This will generate `model/model.pkl` and other necessary files in the `model/` directory.
    ```bash
    python train.py
    ```
    *Note: Ensure the dataset files (`NSL_KDD_Train.csv`, `NSL_KDD_Test.csv`) are present in the `dataset/` folder.*

3.  **Run the Web Application**
    Start the Flask server:
    ```bash
    python app.py
    ```

4.  **Access the Interface**
    Open your web browser and navigate to:
    *   **Traffic Analyzer**: [http://localhost:5000/](http://localhost:5000/)
    *   **Honeypot**: [http://localhost:5000/honeypot](http://localhost:5000/honeypot)
    *   **Dashboard**: [http://localhost:5000/dashboard](http://localhost:5000/dashboard)

## Features
*   **Predictive Analysis**: Classifies network traffic as 'Normal' or 'Intrusion' based on input features.
*   **Honeypot**: A simulated login page to trap and log potential attackers.
*   **Dashboard**: A view to monitor system status and attack statistics.
 e31ccf7 (Initial commit)
