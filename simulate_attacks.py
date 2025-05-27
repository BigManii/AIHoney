# honeypot_simulator.py
from datetime import datetime, timezone
from flask import Flask, request, jsonify, render_template
import requests
import random
import time
import threading
import os # Import os for environment variables


app = Flask(__name__)

# --- Configuration for your main dashboard API ---
# IMPORTANT: Update this to your actual dashboard URL on port 5001
# Replace 'stunning-space-sniffle-x5vp4w59r45vc9x67' with your Codespaces unique identifier
DASHBOARD_API_URL = "https://stunning-space-sniffle-x5vp4w59r45vc9x67-5001.app.github.dev/log_attack"
# If running locally and app.py is on 5001: DASHBOARD_API_URL = "http://127.0.0.1:5001/log_attack"

# Honeypot Configuration for sending data to the dashboard
# These should match entries in app.config['HONEYPOT_API_KEYS'] in your main app.py
HONEYPOT_NAME = "honeypot1" # Example: 'honeypot1' or 'honeypot2'
HONEYPOT_API_KEY = "default-key-1" # Example: 'default-key-1' or 'default-key-2' (matching app.py config)
HONEYPOT_TYPE = "Web" # The type of this simulated honeypot (e.g., 'Web', 'SSH', 'FTP')

# --- Simulation Settings ---
AUTOMATED_SIMULATION_INTERVAL_SECONDS = 30 # How often automated attacks are sent

# Example attack types
ATTACK_SCENARIOS = [
    {
        "type": "SSH Brute-Force",
        "payloads": [
            "username: root, password: password",
            "username: admin, password: 123456",
            "username: test, password: test",
            "username: user, password: user"
        ],
        "ip_prefixes": ["192.168.1.", "10.0.0.", "172.16.0.", "8.8.8."], # Added a public-ish one
        "user_agents": ["SSHClient/1.0", "Masscan/1.0", "Nmap Scripting Engine"]
    },
    {
        "type": "Web Scan",
        "payloads": [
            "/admin", "/.env", "/wp-admin/setup-config.php", "/config.php.bak", "/test.php"
        ],
        "ip_prefixes": ["185.199.108.", "104.28.14.", "172.67.135."],
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
        "ip_prefixes": ["203.0.113.", "198.51.100.", "192.0.2."],
        "user_agents": ["SQLMap/1.4.10#stable", "Mozilla/5.0"]
    },
    {
        "type": "XSS",
        "payloads": [
            "<script>alert('XSS')</script>",
            "<h1>Hello</h1>",
            "<img src=x onerror=alert(document.cookie)>",
            "<svg onload=alert(1)>"
        ],
        "ip_prefixes": ["203.0.113.", "198.51.100.", "192.0.2."],
        "user_agents": ["Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0", "XSS-Scanner/1.0"]
    },
    {
        "type": "Port Scan",
        "payloads": ["Port 22", "Port 80", "Port 443", "Port 23", "Port 3389"],
        "ip_prefixes": ["45.32.22.", "139.162.20."],
        "user_agents": ["Nmap/7.90", "ZMap/1.2.1"]
    }
]

def send_attack_to_dashboard(attack_data):
    """Sends simulated attack data to the main dashboard API."""
    try:
        # Add API key and honeypot name to the JSON payload as required by app.py
        attack_data['api_key'] = HONEYPOT_API_KEY
        attack_data['honeypot_name'] = HONEYPOT_NAME
        attack_data['honeypot_type'] = HONEYPOT_TYPE

        response = requests.post(DASHBOARD_API_URL, json=attack_data)
        response.raise_for_status() # Raise an exception for bad status codes (4xx or 5xx)
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Sent attack to dashboard: {attack_data['type']} from {attack_data['ip']} on {attack_data['honeypot_name']}")
        print(f"Dashboard response: {response.status_code} - {response.json()}")
    except requests.exceptions.RequestException as e:
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Error sending attack to dashboard: {e}")
    except Exception as e:
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Unexpected error: {e}")

def generate_random_ip(ip_prefix):
    """Generates a random IP address based on a given prefix."""
    return f"{ip_prefix}{random.randint(1, 254)}"

def simulate_automated_attack():
    """Generates and sends a random simulated attack for automated background process."""
    scenario = random.choice(ATTACK_SCENARIOS)
    attack_type = scenario["type"]
    simulated_ip = generate_random_ip(random.choice(scenario["ip_prefixes"]))
    simulated_user_agent = random.choice(scenario["user_agents"])
    simulated_payload = random.choice(scenario["payloads"])

    attack_data = {
        "ip": simulated_ip,
        "attack_type": attack_type,
        "details": simulated_payload,
        "user_agent": simulated_user_agent,
        "timestamp": datetime.now(timezone.utc).isoformat(timespec='seconds') + "Z" # ISO 8601 format with Z for UTC
    }
    send_attack_to_dashboard(attack_data)

def start_automated_simulation():
    """Starts a loop to send automated attacks."""
    while True:
        simulate_automated_attack()
        time.sleep(AUTOMATED_SIMULATION_INTERVAL_SECONDS) # Wait before sending next attack

def simulate_attack_on_request():
    """Generates and sends a random simulated attack triggered by a web request."""
    # This function uses request context to get client IP and user agent
    client_ip = request.remote_addr
    user_agent = request.headers.get('User-Agent')

    scenario = random.choice(ATTACK_SCENARIOS)
    attack_type = scenario["type"]
    simulated_payload = random.choice(scenario["payloads"])

    attack_data = {
        "ip": client_ip, # Use the actual client IP for browser-based attacks
        "attack_type": attack_type,
        "details": f"Web-triggered attack: {simulated_payload}",
        "user_agent": user_agent,
        "timestamp": datetime.now(timezone.utc).isoformat(timespec='seconds') + "Z"
    }
    send_attack_to_dashboard(attack_data)

# --- Routes for the simulated honeypot ---

@app.route('/')
def home():
    # Trigger an attack simulation when the home page is accessed
    simulate_attack_on_request()
    return render_template('honeypot_index.html', honeypot_name=HONEYPOT_NAME)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        client_ip = request.remote_addr # Get the client's IP from the request
        user_agent = request.headers.get('User-Agent')

        # Simulate a failed login attempt (always fails for a honeypot)
        payload_details = f"username: {username}, password: {password}"
        attack_data = {
            "ip": client_ip,
            "attack_type": "Login Attempt (Failed)",
            "details": payload_details,
            "user_agent": user_agent,
            "timestamp": datetime.now(timezone.utc).isoformat(timespec='seconds') + "Z"
        }
        send_attack_to_dashboard(attack_data)
        # Honeypots typically always show a failed login
        return "Login Failed! (Honeypot logged this attempt)"
    # For GET requests, show the login page
    return "Login page. Try submitting credentials."

@app.route('/admin_panel')
def admin_panel():
    # Simulate a web scan or attempt to access admin panel
    client_ip = request.remote_addr
    user_agent = request.headers.get('User-Agent')
    attack_data = {
        "ip": client_ip,
        "attack_type": "Web Scan (Admin Panel Access)",
        "details": f"Attempt to access {request.path}",
        "user_agent": user_agent,
        "timestamp": datetime.now(timezone.utc).isoformat(timespec='seconds') + "Z"
    }
    send_attack_to_dashboard(attack_data)
    return "Access Denied. (Honeypot logged this attempt)"

@app.route('/execute', methods=['POST'])
def execute_command():
    # Simulate a command injection attempt
    command = request.json.get('command') if request.is_json else request.form.get('command')
    client_ip = request.remote_addr
    user_agent = request.headers.get('User-Agent')

    attack_data = {
        "ip": client_ip,
        "attack_type": "Command Injection (Simulated)",
        "details": f"Attempted command: {command}",
        "user_agent": user_agent,
        "timestamp": datetime.now(timezone.utc).isoformat(timespec='seconds') + "Z"
    }
    send_attack_to_dashboard(attack_data)
    return jsonify({"status": "Command execution simulated, logged by honeypot."})

if __name__ == '__main__':
    # Start the automated simulation in a separate thread
    print("Starting automated attack simulation in background...")
    simulation_thread = threading.Thread(target=start_automated_simulation, daemon=True)
    simulation_thread.start()

    # Run the Flask app for the simulator
    SIMULATOR_PORT = int(os.environ.get('SIMULATOR_PORT', 5003)) # Default to 5003
    print(f"Honeypot Simulator running on http://127.0.0.1:{SIMULATOR_PORT}")
    print(f"Sending attacks to: {DASHBOARD_API_URL}")
    print(f"This simulator sends attacks as honeypot: {HONEYPOT_NAME} with API Key: {HONEYPOT_API_KEY}")
    print("Access /login, /admin_panel, / to trigger web-based attacks.")
    app.run(host="0.0.0.0", port=SIMULATOR_PORT, debug=True, use_reloader=False) # Changed port to SIMULATOR_PORT (default 5003)