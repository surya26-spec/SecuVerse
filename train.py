import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
import joblib
import preprocess
import os

def train():
    print("Loading data...")
    # Using absolute paths or relative to execution dir
    # Assuming execution from project root
    train_path = os.path.join('dataset', 'NSL_KDD_Train.csv')
    test_path = os.path.join('dataset', 'NSL_KDD_Test.csv')
    
    train_df = preprocess.load_data(train_path)
    test_df = preprocess.load_data(test_path)

    print("Preprocessing data...")
    # Preprocess features
    # Note: This saves encoders/scalers to 'model/' directory
    train_df = preprocess.preprocess_data(train_df, is_train=True)
    test_df = preprocess.preprocess_data(test_df, is_train=False)

    # Handle Target
    # Binary classification: normal vs attack
    # We map 'normal' to 0, and any other label to 1
    y_train = train_df['class'].apply(lambda x: 0 if x == 'normal' else 1)
    y_test = test_df['class'].apply(lambda x: 0 if x == 'normal' else 1)
    
    # Drop target column
    X_train = train_df.drop('class', axis=1)
    X_test = test_df.drop('class', axis=1)

    print("Training Random Forest model...")
    # Using a small number of estimators for speed in this demo, can be increased
    clf = RandomForestClassifier(n_estimators=50, random_state=42)
    clf.fit(X_train, y_train)

    print("Evaluating model...")
    y_pred = clf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"Accuracy: {acc:.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred))

    print("Saving model...")
    model_path = os.path.join('model', 'model.pkl')
    joblib.dump(clf, model_path)
    print(f"Model saved to {model_path}")

if __name__ == "__main__":
    train()
