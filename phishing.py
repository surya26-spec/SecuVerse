import re
from urllib.parse import urlparse

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
    # Validate only if there is a domain found
    if domain:
        # Check if domain has uppercase characters (legit domains are usually strictly lowercase in display)
        # We ignore typically capitalized first letters if it's just one, but "gOOgle" is suspicious.
        features['has_mixed_case'] = 1 if any(c.isupper() for c in domain) and any(c.islower() for c in domain) else 0
    else:
        features['has_mixed_case'] = 0

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
    
    probability = min(score, 100)
    
    if score >= 50:
        return "Phishing", probability, details
    else:
        if score == 0:
            details.append("No suspicious indicators found.")
        return "Safe", probability, details
