import phishing
import urllib.parse

url = "gOOgle.com"
print(f"Testing URL: {url}")

# Check what urlparse does
parsed = urllib.parse.urlparse(url)
print(f"urlparse.netloc: '{parsed.netloc}' (Note: if this is lowercase, that's the bug)")

# Run the actual prediction
result, probability, details = phishing.predict_phishing(url)
features = phishing.extract_features(url)

print(f"Result: {result}")
print(f"Probability: {probability}")
print(f"Details: {details}")
print(f"Features: {features}")
