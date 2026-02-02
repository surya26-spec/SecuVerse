import pandas as pd
import phishing
import os
import time

def evaluate_all():
    data_path = 'dataset_phishing.csv'
    
    if not os.path.exists(data_path):
        print(f"Error: Dataset not found at {data_path}")
        return

    print(f"Loading dataset from {data_path}...")
    try:
        df = pd.read_csv(data_path)
    except Exception as e:
        print(f"Error reading CSV: {e}")
        return

    if 'url' not in df.columns or 'status' not in df.columns:
        print("Error: CSV must contain 'url' and 'status' columns.")
        return

    total = len(df)
    print(f"Evaluating {total} URLs against the full detection system (ML + Heuristics + Typosquatting)...")
    print("This may take a minute...\n")

    correct = 0
    false_positives = 0 # Safe marked as Phishing
    false_negatives = 0 # Phishing marked as Safe
    
    # Track some specific failures for review
    missed_phishing = []
    
    start_time = time.time()

    for i, row in df.iterrows():
        url = str(row['url'])
        true_status = str(row['status']).lower().strip()
        
        # Ground Truth
        if true_status == 'phishing':
            is_phishing_true = True
        elif true_status == 'legitimate':
            is_phishing_true = False
        else:
            continue # Skip unknown labels

        # System Prediction (The FULL pipeline)
        result, probability, details = phishing.predict_phishing(url)
        is_phishing_pred = (result == 'Phishing')

        # Comparison
        if is_phishing_pred == is_phishing_true:
            correct += 1
        else:
            if is_phishing_pred and not is_phishing_true:
                false_positives += 1
            elif not is_phishing_pred and is_phishing_true:
                false_negatives += 1
                if len(missed_phishing) < 5:
                    missed_phishing.append(url)

        # Progress bar
        if i % 500 == 0:
            print(f"Processed {i}/{total}...", end='\r')

    end_time = time.time()
    duration = end_time - start_time

    accuracy = (correct / total) * 100
    
    print("\n" + "="*40)
    print("EVALUATION RESULTS")
    print("="*40)
    print(f"Total URLs:      {total}")
    print(f"Time Taken:      {duration:.2f} seconds")
    print(f"Accuracy:        {accuracy:.2f}%")
    print("-" * 20)
    print(f"Correct:         {correct}")
    print(f"False Positives: {false_positives} (Safe sites flagged as Phishing)")
    print(f"False Negatives: {false_negatives} (Phishing sites missed)")
    print("="*40)
    
    if missed_phishing:
        print("\nSample Missed Phishing URLs (Marked Safe but were Phishing):")
        for url in missed_phishing:
            print(f" - {url}")

if __name__ == '__main__':
    evaluate_all()
