import requests
import sys

BASE_URL = "http://127.0.0.1:5001"
LOGIN_URL = f"{BASE_URL}/login"
HOME_URL = f"{BASE_URL}/"
DASHBOARD_URL = f"{BASE_URL}/dashboard"

def run_test():
    s = requests.Session()
    
    print(f"--- Testing Access Protection ---")
    # 1. Try to access Home without login
    try:
        r = s.get(HOME_URL, allow_redirects=False)
        if r.status_code == 302 and '/login' in r.headers.get('Location', ''):
            print(f"[PASS] Home page redirected to login. Location: {r.headers['Location']}")
        else:
            print(f"[FAIL] Home page did NOT redirect to login correctly. Status: {r.status_code}")
            return False
    except Exception as e:
        print(f"[ERROR] server might not be running? {e}")
        return False

    # 2. Login
    print(f"\n--- Testing Login Flow ---")
    credentials = {'username': 'admin', 'password': 'admin'}
    # First get the page to get any potential CSRF token if implemented (flask default doesn't enforce without extra lib, but good practice)
    s.get(LOGIN_URL) 
    
    # Post login
    r = s.post(LOGIN_URL, data=credentials, allow_redirects=False, params={'next': HOME_URL})
    
    if r.status_code == 302:
        print(f"[PASS] Login POST returned redirect. Location: {r.headers.get('Location')}")
        if r.headers.get('Location') == '/' or r.headers.get('Location') == HOME_URL:
             print("[PASS] Redirected to Home as expected.")
        else:
             print(f"[WARN] Redirected to {r.headers.get('Location')} instead of Home.")
    else:
        print(f"[FAIL] Login failed or didn't redirect. Status: {r.status_code}")
        return False
        
    # 3. Access Protected Page with Session
    print(f"\n--- Testing Authenticated Access ---")
    r = s.get(DASHBOARD_URL)
    if r.status_code == 200:
        print(f"[PASS] Accessed Dashboard successfully after login.")
    else:
        print(f"[FAIL] Could not access Dashboard after login. Status: {r.status_code}")
        return False
        
    return True

if __name__ == "__main__":
    if run_test():
        print("\nAll authentication tests PASSED.")
    else:
        print("\nSome tests FAILED.")
        sys.exit(1)
