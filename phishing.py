import re
from urllib.parse import urlparse
import joblib
import os

# Globals for caching the model
MODEL = None
VECTORIZER = None
MODEL_PATH = os.path.join(os.path.dirname(__file__), 'model', 'phishing_model.pkl')
VEC_PATH = os.path.join(os.path.dirname(__file__), 'model', 'phishing_vectorizer.pkl')

def load_model():
    global MODEL, VECTORIZER
    if MODEL is None:
        if os.path.exists(MODEL_PATH) and os.path.exists(VEC_PATH):
            try:
                MODEL = joblib.load(MODEL_PATH)
                VECTORIZER = joblib.load(VEC_PATH)
            except Exception as e:
                print(f"Failed to load phishing model: {e}")

def extract_features(url):
    features = {}
    
    # 1. Length of URL
    features['url_length'] = len(url)
    
    # 2. IP Address in URL
    # IPv4 regex
    ip_pattern = re.compile(r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\/)|'  # IPv4
                            r'((0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\/)'  # Hexadecimal
                            r'(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}')
    match = ip_pattern.search(url)
    features['has_ip'] = 1 if match else 0
    
    # 3. Presence of @ symbol
    features['has_at_symbol'] = 1 if '@' in url else 0
    
    # 4. Number of dots (subdomains)
    # Ignore "www." and the TLD dot
    parsed = urlparse(url)
    domain = parsed.netloc
    features['num_dots'] = domain.count('.')
    
    # 5. Using a shortening service (tinyurl, bit.ly, etc.)
    shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                          r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                          r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                          r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                          r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                          r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                          r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                          r"tr\.im|link\.zip\.net"
    features['is_shortened'] = 1 if re.search(shortening_services, url, flags=re.IGNORECASE) else 0
    
    # 6. Presence of hyphen in domain
    features['has_hyphen'] = 1 if '-' in domain else 0
    
    # 7. Non-standard port
    features['has_port'] = 1 if re.search(r':[0-9]{2,5}', domain) else 0

    # 8. Suspicious keywords
    keywords = ['confirm', 'account', 'banking', 'secure', 'ebayisapi', 'webscr', 'login', 'signin']
    features['has_suspicious_keyword'] = 1 if any(word in url.lower() for word in keywords) else 0
    
    # 9. Mixed Case Domain (e.g. gOOgle.com)
    if domain:
        features['has_mixed_case'] = 1 if any(c.isupper() for c in domain) and any(c.islower() for c in domain) else 0
    else:
        features['has_mixed_case'] = 0

    # 10. Typosquatting Check (New)
    features['is_typosquat'] = 0
    if domain:
        # Simple common substitution check for popular domains
        # We manually check if "g00gle" or similar patterns exist
        
        # Normalize: replace 0 with o, 1 with l, etc. to see if it matches a big brand
        normalized = domain.lower().replace('0', 'o').replace('1', 'l').replace('3', 'e').replace('@', 'a')
        
        # Add more brands here to protect them
        targets = [
            'google', 'facebook', 'amazon', 'apple', 'microsoft', 'paypal', 'netflix', 'instagram',
            'zomato', 'swiggy', 'bms', 'paytm', 'flipkart', 'twitter', 'linkedin', 'whatsapp'
        ]
        
        for t in targets:
            if t in normalized and t not in domain.lower():
                # If the "corrected" version contains the brand, but the original didn't
                # It means they used subsitutions like 0 for o.
                # Exception: legitimate subdomains or weird coincidences, but usually high risk.
                features['is_typosquat'] = 1
                break
                
    return features

def predict_phishing(url):
    """
    Returns a tuple: (prediction_label, probability_score, details_list)
    prediction_label: 1 (Phishing) or 0 (Safe)
    """
    # Fix malformed URLs (e.g., http:www.google.com -> http://www.google.com)
    if url.startswith("http:") and not url.startswith("http://"):
        url = url.replace("http:", "http://")
    elif url.startswith("https:") and not url.startswith("https://"):
         url = url.replace("https:", "https://")
    elif not url.startswith("http://") and not url.startswith("https://"):
        # If user typed 'google.com', assume http for parsing purposes
        url = "http://" + url
         
    features = extract_features(url)
    
    score = 0
    details = []
    
    # Heuristic Scoring Logic
    
    if features['has_ip']:
        score += 30
        details.append("URL contains IP address (High Risk)")
    
    if features.get('has_mixed_case'):
        score += 60 # Critical indicator
        details.append("Domain contains mixed usage of Upper/Lower case (Suspicious)")
        
    if features['has_at_symbol']:
        score += 20
        details.append("URL contains '@' symbol (Medium Risk)")
        
    if features['is_shortened']:
        score += 20
        details.append("URL uses a shortening service (Medium Risk)")
        
    if features['has_hyphen']:
        score += 15
        details.append("Domain name contains hyphens (Low/Medium Risk)")

    if features['num_dots'] > 3:
        score += 20
        details.append("Suspiciously high number of subdomains")
        
    if features['has_port']:
        score += 10
        details.append("Uses non-standard port")
        
    if features['url_length'] > 75:
        score += 20
        details.append("URL is abnormally long")
    elif features['url_length'] < 54:
        pass # Normal length
    else:
        score += 10 # Slightly long
        
    if features['has_suspicious_keyword']:
        score += 25
        details.append("Contains suspicious security/banking keywords")
        
    # Calculate probability
    # Determine threshold
    # If score > 50 -> Phishing
    
    # --- ML OVERRIDE ---
    # If a trained model exists, we use it to refine the prediction.
    load_model()
    if MODEL and VECTORIZER:
        try:
            # Prepare features for model
            vec_features = VECTORIZER.transform([features])
            prediction = MODEL.predict(vec_features)[0] # 0 or 1
            
            # Get probability. 
            # Note: predict_proba returns [prob_class_0, prob_class_1]
            probs = MODEL.predict_proba(vec_features)[0]
            ml_prob = probs[1] * 100 # Probability of being phishing
            
            if prediction == 1:
                return "Phishing", ml_prob, details + ["ML Model detected phishing patterns."]
            else:
                 # If ML says safe but heuristics match, we might want to warn. 
                 # But generally ML on this dataset is strong.
                 
                 # --- CRITICAL OVERRIDE: Typosquatting ---
                 # The ML model might miss "g00gle" if it wasn't in the training set features.
                 if features.get('is_typosquat') == 1:
                     return "Phishing", 95.0, details + ["Critical: Typosquatting detected (Brand Impersonation)"]
                 
                 return "Safe", ml_prob, details + ["ML Model verified as safe."]
                 
        except Exception as e:
            print(f"ML Prediction Error: {e}")
            # Fallback to heuristic if ML fails
    
    # --- HEURISTIC FALLBACK ---
    probability = min(score, 100)
    
    if score >= 50:
        return "Phishing", probability, details
    else:
        if score == 0:
            details.append("No suspicious indicators found.")
        return "Safe", probability, details
