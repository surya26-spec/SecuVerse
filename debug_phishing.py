import phishing
import sys

def test_url(url):
    print(f"\n--- Testing URL: {url} ---")
    
    # Run the prediction
    result, probability, details = phishing.predict_phishing(url)
    features = phishing.extract_features(url)
    
    print(f"Prediction: {result}")
    print(f"Probability (Phishing): {probability:.2f}%")
    print("Risk Factors / Details:")
    for d in details:
        print(f" - {d}")
        
    print("\nExtracted Features:")
    for k, v in features.items():
        print(f"  {k}: {v}")
    print("------------------------------------------------")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        # Command line arg support
        url = sys.argv[1]
        test_url(url)
    else:
        # Interactive mode
        print("Phishing Detection Test Tool")
        print("Type a URL to test, or 'q' to quit.")
        
        while True:
            try:
                user_input = input("\nEnter URL: ").strip()
                if user_input.lower() in ['q', 'quit', 'exit']:
                    break
                if not user_input:
                    continue
                    
                test_url(user_input)
            except KeyboardInterrupt:
                break
        print("Bye.")
