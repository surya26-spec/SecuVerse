import pandas as pd
import joblib
import os
import phishing
from sklearn.feature_extraction import DictVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report

def train_phishing_model():
    # dataset_phishing.csv is in the same directory (based on user info)
    data_path = 'dataset_phishing.csv'
    model_dir = 'model'
    
    if not os.path.exists(data_path):
        # Fallback to check dataset/ folder just in case
        data_path = os.path.join('dataset', 'dataset_phishing.csv')
        if not os.path.exists(data_path):
            print(f"Error: Dataset not found at {data_path}")
            return

    print(f"Loading dataset from {data_path}...")
    try:
        df = pd.read_csv(data_path)
    except Exception as e:
        print(f"Error reading CSV: {e}")
        return

    # Check for required columns
    # We need 'url' and 'status' (or 'label')
    if 'url' not in df.columns or 'status' not in df.columns:
        print("Error: CSV must contain 'url' and 'status' columns.")
        print(f"Found columns: {df.columns}")
        return

    print(f"Loaded {len(df)} URLs.")

    # Feature Extraction
    print("Extracting features (this may take a while)...")
    
    features_list = []
    labels = []

    # Iterate and extract features using our python logic
    # This ensures the model is trained on EXACTLY the same features it will see in production
    for i, row in df.iterrows():
        if i % 100 == 0:
            print(f"Processing row {i}/{len(df)}...", end='\r')
            
        url = str(row['url'])
        status = str(row['status']).lower().strip()
        
        # Determine label (1 = Phishing, 0 = Legitimate)
        if status == 'phishing':
            is_phishing = 1
        elif status == 'legitimate':
            is_phishing = 0
        else:
            continue # Skip unknown labels

        try:
            feat = phishing.extract_features(url)
            features_list.append(feat)
            labels.append(is_phishing)
        except Exception as e:
            print(f"Skipping URL {url} due to error: {e}")

    print(f"\nExtracted features for {len(features_list)} items.")

    # Vectorization
    print("Vectorizing features...")
    vec = DictVectorizer(sparse=False)
    X = vec.fit_transform(features_list)
    y = labels

    # Split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # Train
    print("Training Random Forest...")
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X_train, y_train)

    # Evaluate
    print("Evaluating...")
    y_pred = clf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"Accuracy: {acc:.4f}")
    print(classification_report(y_test, y_pred))

    # Save
    if not os.path.exists(model_dir):
        os.makedirs(model_dir)

    model_path = os.path.join(model_dir, 'phishing_model.pkl')
    vec_path = os.path.join(model_dir, 'phishing_vectorizer.pkl')

    joblib.dump(clf, model_path)
    joblib.dump(vec, vec_path)
    print(f"Model saved to {model_path}")
    print(f"Vectorizer saved to {vec_path}")

if __name__ == '__main__':
    train_phishing_model()
