import requests
import json
from datetime import datetime

# --- Configuration ---
# Use the Gitpod external URL for your Flask app
FLASK_APP_URL = "https://5000-bigmanii-aihoney-u1fiukvcxsf.ws-eu120.gitpod.io"
LOG_ATTACK_ENDPOINT = "/log_attack"
LOGIN_ENDPOINT = "/login" # Assuming your login endpoint is /login

# --- Your admin credentials ---
# Use the email and password you set up via 'flask shell'
ADMIN_EMAIL = "new_admin@example.com" # Or whatever email you set
ADMIN_PASSWORD = "A_VERY_MEMORABLE_PASSWORD" # Your actual password

# --- Function to send test attack ---
def send_test_attack(session, ip_address, attack_type, payload_content, honeypot_name="honeypot1", honeypot_type="Test"):
    url = f"{FLASK_APP_URL}{LOG_ATTACK_ENDPOINT}"
    
    # Use 'source_ip' and 'attack_type' as expected by your Flask app
    # Also include 'honeypot_id' (assuming 3 for testing as before)
    # And 'timestamp' as a string
    data = {
        "honeypot_id": 3,
        "source_ip": ip_address,
        "attack_type": attack_type,
        "payload": payload_content,
        "honeypot_name": honeypot_name,
        "honeypot_type": honeypot_type,
        "timestamp": datetime.now().isoformat() + "Z" # ISO 8601 format with Z for UTC
    }

    print(f"Sending test attack to {url}")
    print("Payload:", json.dumps(data, indent=2))

    try:
        # Use the session for the request
        response = session.post(url, json=data, headers={"Content-Type": "application/json"})
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)

        print("Test attack sent successfully!")
        print("Response Status:", response.status_code)
        print("Response Body:", response.json())

    except requests.exceptions.HTTPError as e:
        print(f"ERROR: Could not send test attack: {e}")
        print(f"Error Response Status: {e.response.status_code}")
        print(f"Error Response Body: {e.response.text}")
    except requests.exceptions.ConnectionError as e:
        print(f"ERROR: Could not send test attack: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

# --- Main execution ---
if __name__ == "__main__":
    # Create a session to handle cookies (for authentication)
    session = requests.Session()

    # 1. Attempt to log in
    login_url = f"{FLASK_APP_URL}{LOGIN_ENDPOINT}"
    login_payload = {
        "email": ADMIN_EMAIL,
        "password": ADMIN_PASSWORD
    }
    print(f"\nAttempting to log in to {login_url}...")
    try:
        login_response = session.post(login_url, data=login_payload) # Use data= for form-encoded login, or json= if your /login expects json
        login_response.raise_for_status()
        print("Login successful!")
    except requests.exceptions.HTTPError as e:
        print(f"ERROR: Login failed: {e}")
        print(f"Login Response Status: {e.response.status_code}")
        print(f"Login Response Body: {e.response.text}")
        print("Please ensure your admin credentials are correct and the login endpoint is configured to accept them via POST.")
        exit() # Exit if login fails
    except Exception as e:
        print(f"An unexpected error occurred during login: {e}")
        exit()

    # 2. If login is successful, send the test attack
    send_test_attack(session, "192.168.1.78", "Test Ping", "simple test payload for ping")
    print("-" * 30)
    send_test_attack(session, "192.168.1.218", "Test Scan", "simple test payload for scan")
    print("-" * 30)
    send_test_attack(session, "192.168.1.241", "Test Exploit", "simple test payload for exploit")