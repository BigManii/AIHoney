# --- API Authentication ---
API_KEY = "default-key-1"  # Must match your Flask app's HONEYPOT_API_KEYS
HEADERS = {
    "X-API-KEY": API_KEY,
    "Content-Type": "application/json"
}


# honeypot_simulator.py
from datetime import datetime, timezone # Correct import for timezone
from flask import Flask, request, jsonify, render_template
import requests
import random
import time
import threading
import os # For environment variables, though not strictly used in current example

# Optional: If you want to use faker for more realistic data
# from faker import Faker
# fake = Faker()

app = Flask(__name__)

# --- Configuration for your main dashboard API ---
# IMPORTANT: Replace 'http://localhost:5001' with your actual dashboard URL
# If running in Codespaces, it will be the URL of your forwarded port 5001
# Use your actual Codespace URL for app.py
# Paste your ACTUAL Codespaces URL for port 5001 here:
DASHBOARD_API_URL = "https://stunning-space-sniffle-x5vp4w59r45vc9x67-5001.app.github.dev/log_attack"

# --- Default Honeypot Identity for this simulator instance ---
DEFAULT_HONEYPOT_NAME = "Simulated HoneyPot-001"
DEFAULT_HONEYPOT_TYPE = "Generic" # Will be updated by specific attack types if needed

# --- Simulated Attack Scenarios ---
ATTACK_SCENARIOS = [
    {
        "type": "SSH Brute-Force",
        "payloads": [
            "username: root, password: password",
            "username: admin, password: 123456",
            "username: test, password: test",
            "username: user, password: user"
        ],
        "ip_prefixes": ["192.168.1.", "10.0.0.", "172.16.0.", "8.8.8."], # Add some public-like IPs
        "user_agents": ["SSHClient/1.0", "Masscan/1.0", "Nmap Scripting Engine", "Hydra/8.6"]
    },
    {
        "type": "Web Scan",
        "payloads": [
            "/admin", "/.env", "/wp-admin/setup-config.php", "/config.php.bak", "/test.php"
        ],
        "ip_prefixes": ["185.199.108.", "104.28.14.", "172.67.135.", "51.15.100."],
        "user_agents": [
            "Mozilla/5.0 (compatible; Nmap/7.90; https://nmap.org/book/nse.html)",
            "Python-urllib/3.8",
            "Go-http-client/1.1",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        ]
    },
    {
        "type": "SQL Injection",
        "payloads": [
            "username=' OR '1'='1 --",
            "user=admin' -- ",
            "id=1 UNION SELECT 1,database(),user()",
            "id=1; EXEC xp_cmdshell('dir')"
        ],
        "ip_prefixes": ["203.0.113.", "198.51.100.", "192.0.2.", "94.102.61."],
        "user_agents": ["SQLMap/1.4.10#stable", "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0)"]
    },
    {
        "type": "XSS",
        "payloads": [
            "<script>alert('XSS')</script>",
            "<h1>Hello</h1>",
            "<img src=x onerror=alert(document.cookie)>",
            "<svg onload=alert(1)>"
        ],
        "ip_prefixes": ["203.0.113.", "198.51.100.", "192.0.2.", "173.255.200."],
        "user_agents": ["Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0", "XSS-Scanner/1.0", "OWASP ZAP"]
    },
    {
        "type": "Port Scan",
        "payloads": ["Port 22 Open", "Port 80 Open", "Port 443 Open", "Port 23 Open", "Port 3389 Open"],
        "ip_prefixes": ["45.32.22.", "139.162.20.", "10.10.10."],
        "user_agents": ["Nmap/7.90", "ZMap/1.2.1", "Rustscan/1.0"]
    },
    {
        "type": "Malware Download Attempt",
        "payloads": ["GET /malware.exe", "GET /shell.sh", "POST /upload_backdoor.php"],
        "ip_prefixes": ["1.2.3.", "4.5.6."],
        "user_agents": ["Wget/1.20.3 (linux-gnu)", "curl/7.68.0"]
    }
]

def generate_random_ip(ip_prefix):
    """Generates a random IP address based on a given prefix."""
    return f"{ip_prefix}{random.randint(1, 254)}"

#def send_attack_to_dashboard(attack_data):
  #  """Sends simulated attack data to the main dashboard API."""
    #try:
       # response = requests.post(DASHBOARD_API_URL, json=attack_data, timeout=10) # Added timeout
        #response.raise_for_status() # Raise an exception for bad status codes (4xx or 5xx)
        #print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Sent attack to dashboard: {attack_data.get('type', 'N/A')} from {attack_data.get('ip_address', 'N/A')}")
        #print(f"Dashboard response ({response.status_code}): {response.text}")
    #except requests.exceptions.Timeout:
        #print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Timeout sending attack to dashboard.")
   # except requests.exceptions.RequestException as e:
      #  print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Error sending attack to dashboard: {e}")
   # except Exception as e:
       # print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Unexpected error during attack send: {e}")

# Define this constant somewhere at the top
HEADERS = {
    "X-API-KEY": "default-key-1"  # This must match what your app.py is expecting
}

def send_attack_to_dashboard(attack_data):
    """Sends simulated attack data to the main dashboard API."""
    try:
        response = requests.post(
            DASHBOARD_API_URL,
            json=attack_data,
            headers=HEADERS,  # Ensure API key is sent here
            timeout=10
        )
        response.raise_for_status()
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] ✅ Sent attack to dashboard: {attack_data.get('type', 'N/A')}")
        print(f"📡 Response: {response.status_code} - {response.text}")
    except requests.exceptions.Timeout:
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] ⏳ Timeout while sending attack.")
    except requests.exceptions.HTTPError as e:
        print(f"[ERROR] HTTP error: {e.response.status_code} - {e.response.text}")
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Failed to send attack: {str(e)}")


def simulate_attack_event(
    honeypot_name=DEFAULT_HONEYPOT_NAME,
    honeypot_type=DEFAULT_HONEYPOT_TYPE,
    attack_type=None,
    ip_address=None,
    payload=None,
    user_agent=None
):
    """
    Generates and sends a single simulated attack event to the dashboard.
    Can be called with specific parameters or will generate random ones.
    """
    scenario = random.choice(ATTACK_SCENARIOS)

    # Use provided values or generate random ones
    chosen_attack_type = attack_type if attack_type else scenario["type"]
    chosen_ip_address = ip_address if ip_address else generate_random_ip(random.choice(scenario["ip_prefixes"]))
    chosen_payload = payload if payload else random.choice(scenario["payloads"])
    chosen_user_agent = user_agent if user_agent else random.choice(scenario["user_agents"])

    # Ensure honeypot_type is more specific if it's currently 'Generic'
    if honeypot_type == "Generic" and chosen_attack_type == "SSH Brute-Force":
        honeypot_type = "SSH"
    elif honeypot_type == "Generic" and "Web" in chosen_attack_type:
        honeypot_type = "HTTP"
    elif honeypot_type == "Generic" and "SQL" in chosen_attack_type:
        honeypot_type = "SQL"

    attack_data = {
        "ip_address": chosen_ip_address,
        "type": chosen_attack_type,
        "payload": chosen_payload,
        "honeypot_name": honeypot_name, # Required by app.py
        "honeypot_type": honeypot_type, # Required by app.py
        "user_agent": chosen_user_agent,
        "timestamp": datetime.now(timezone.utc).isoformat(timespec='seconds') + "Z" # ISO 8601 with Z for UTC
    }

    send_attack_to_dashboard(attack_data)

# --- Routes for the simulated honeypot (for direct interaction) ---
@app.route('/')
def home():
    # Trigger a random attack when someone visits the home page
    threading.Thread(target=simulate_attack_event).start()
    return render_template('honeypot_index.html', honeypot_name=DEFAULT_HONEYPOT_NAME)

@app.route('/login', methods=['GET', 'POST'])
def login():
    client_ip = request.remote_addr # Get the client's IP from the request
    user_agent = request.headers.get('User-Agent', 'Unknown')
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        payload_details = f"username: {username}, password: {password}"

        # Simulate a specific attack based on interaction
        threading.Thread(target=simulate_attack_event, kwargs={
            'ip_address': client_ip,
            'attack_type': "Login Attempt (Failed)",
            'payload': payload_details,
            'honeypot_type': "HTTP", # This route implies HTTP honeypot
            'user_agent': user_agent
        }).start()
        return "Login Failed! (Honeypot logged this attempt)"
    return "Login page. Try submitting credentials."

@app.route('/admin_panel')
def admin_panel():
    client_ip = request.remote_addr
    user_agent = request.headers.get('User-Agent', 'Unknown')

    threading.Thread(target=simulate_attack_event, kwargs={
        'ip_address': client_ip,
        'attack_type': "Web Scan (Admin Panel Access)",
        'payload': f"Attempt to access {request.path}",
        'honeypot_type': "HTTP",
        'user_agent': user_agent
    }).start()
    return "Access Denied. (Honeypot logged this attempt)"

@app.route('/execute', methods=['POST'])
def execute_command():
    command = request.json.get('command') if request.is_json else request.form.get('command')
    client_ip = request.remote_addr
    user_agent = request.headers.get('User-Agent', 'Unknown')

    threading.Thread(target=simulate_attack_event, kwargs={
        'ip_address': client_ip,
        'attack_type': "Command Injection (Simulated)",
        'payload': f"Attempted command: {command}",
        'honeypot_type': "Generic-Shell", # Example specific type
        'user_agent': user_agent
    }).start()
    return f"Command '{command}' not found. (Honeypot logged this attempt)"


# --- Automated attack simulation ---
def start_automated_simulation_loop():
    """Starts a thread to send automated attacks at intervals."""
    print("Automated attack simulation loop started.")
    while True:
        simulate_attack_event() # Call the unified function
        time.sleep(random.randint(5, 15)) # Send an attack every 5-15 seconds

# ==============================================================================
# MAIN APPLICATION RUN
# ==============================================================================
if __name__ == '__main__':
    # Start the automated simulation in a separate thread
    print("Starting automated attack simulation in background...")
    simulation_thread = threading.Thread(target=start_automated_simulation_loop, daemon=True)
    simulation_thread.start()

    print(f"Honeypot Simulator running on http://127.0.0.1:5002")
    print(f"Sending attacks to: {DASHBOARD_API_URL}")
    print("Access http://127.0.0.1:5002/, /login, /admin_panel, or /execute (POST) to trigger attacks from your browser.")
    app.run(debug=True, port=5002) # Run on a different port than your dashboard (e.g., 5002)