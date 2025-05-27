import requests
import json
from datetime import datetime, timezone
import random

# Replace this with your actual URL where the Flask app is running
# IMPORTANT: Use your Codespaces URL, e.g., "https://stunning-space-sniffle-x5vp4w59r45vc9x67-5001.app.github.dev/log_attack"
DASHBOARD_API_URL = "http://127.0.0.1:5001/log_attack"  # Change to your server URL if needed

# Replace with your actual API key and honeypot name
API_KEY = "default-key-1"  # Use the correct API key for your honeypot
HONEYPOT_NAME = "honeypot1"  # Use the correct honeypot name

def send_test_attack():
    attack_data = {
        "ip_address": f"192.168.1.{random.randint(1, 254)}",
        "type": random.choice(["Test Scan", "Test Login", "Test Ping"]),
        "payload": "simple test payload",
        "honeypot_name": HONEYPOT_NAME,
        "honeypot_type": "Test",
"timestamp": datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')    }

    headers = {
        "Content-Type": "application/json",
        "X-API-KEY": API_KEY  # Include the API key in the headers
    }

    print(f"Sending test attack to {DASHBOARD_API_URL}")
    print(f"Payload: {json.dumps(attack_data, indent=2)}")

    try:
        response = requests.post(DASHBOARD_API_URL, json=attack_data, headers=headers)
        response.raise_for_status()  # Raise an exception for HTTP errors (4xx or 5xx)
        print(f"\nSUCCESS! Dashboard Response Status: {response.status_code}")
        print(f"Dashboard Response Body: {response.json()}")
    except requests.exceptions.RequestException as e:
        print(f"\nERROR: Could not send test attack: {e}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"Error Response Status: {e.response.status_code}")
            print(f"Error Response Body: {e.response.text}")
    except Exception as e:
        print(f"\nAN UNEXPECTED ERROR OCCURRED: {e}")

if __name__ == "__main__":
    send_test_attack()