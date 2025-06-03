# app.py
# ==============================================================================
# IMPORTS
# ==============================================================================

# --- Python Standard Library ---
import os
import re
import traceback
import json
from dotenv import load_dotenv
import random
import time
import uuid
from datetime import datetime, timedelta, timezone
from threading import Timer
from functools import wraps
import logging
from collections import deque # Used for RL agent's memory
from utils import get_geolocation_data, check_ip_reputation, is_ip_blocked, block_ip
from anomaly_detection import AnomalyDetector
from rl_agent import DQLAgent


# --- GEVENT MONKEY PATCH - MUST BE AT THE VERY TOP, after basic imports
from gevent import monkey
monkey.patch_all()

# --- Flask & Flask Extensions ---
from flask import Flask, render_template, redirect, url_for, flash, request, jsonify, abort, current_app
from flask_login import UserMixin, login_user, login_required, logout_user, current_user
from flask_socketio import SocketIO, emit
from flask_migrate import Migrate
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from itsdangerous import SignatureExpired, BadSignature
from sqlalchemy import func, text
import requests # For geolocation lookup

# --- Data Processing & Machine Learning ---
import numpy as np
import joblib # For loading/saving scikit-learn models
from sklearn.ensemble import IsolationForest
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense
from tensorflow.keras.optimizers import Adam

from models import User, Attack, Honeypot

# Load environment variables
load_dotenv()

# --- Import extensions from extensions.py (CORRECT WAY) ---
from extensions import init_extensions, db, login_manager, mail, get_serializer
from flask_mail import Message # Keep Message import if you use it directly


# ==============================================================================
# FLASK APPLICATION SETUP
# ==============================================================================

app = Flask(__name__)

# --- Start of Database Configuration Update ---

# Ensure the instance directory exists using Flask's built-in app.instance_path.
# For a Flask app created at the root of your project, app.instance_path will
# automatically resolve to a subdirectory named 'instance' next to your app.py.
os.makedirs(app.instance_path, mode=0o755, exist_ok=True)
print(f"DEBUG: Created database directory: {app.instance_path}")

# Construct the absolute path to your database file within the instance directory.
db_path = os.path.join(app.instance_path, 'honeypot.db')

# App Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', '@EmmanuelogboguKey64')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', f'sqlite:///{db_path}')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_HTTPONLY'] = True
# Add to your config section (near other configs)
app.config['HONEYPOT_API_KEYS'] = {
    'honeypot1': 'default-key-1', # Your API key for honeypot1 is now fixed as 'default-key-1'
    'honeypot2': os.environ.get('HONEYPOT2_API_KEY', 'default-key-2')
}
# Mail Configuration
app.config["MAIL_SERVER"] = os.environ.get("MAIL_SERVER", "smtp.gmail.com")
app.config["MAIL_PORT"] = int(os.environ.get("MAIL_PORT", 587))
app.config["MAIL_USE_TLS"] = os.environ.get("MAIL_USE_TLS", True)
app.config["MAIL_USERNAME"] = os.environ.get("MAIL_USERNAME", "your-email@gmail.com")
app.config["MAIL_PASSWORD"] = os.environ.get("MAIL_PASSWORD", "your-email-password")

# Initialize Flask-SocketIO and Flask-Limiter with the 'app' instance
socketio = SocketIO(app, cors_allowed_origins="*", engineio_logger=True, logger=True, async_mode='gevent')
limiter = Limiter(key_func=get_remote_address)
limiter.init_app(app)

# Initialize custom extensions (SQLAlchemy, Flask-Login, Flask-Mail, Serializer)
# This connects the imported 'db', 'login_manager', 'mail' instances to this 'app'
init_extensions(app)

# Flask-Migrate must be initialized AFTER db has been initialized with 'app'
migrate = Migrate(app, db)

# ==============================================================================
# REINFORCEMENT LEARNING AGENT (AI)
# ==============================================================================
class HoneypotRLAgent:
    def __init__(self, state_size, action_size):
        self.state_size = state_size
        self.action_size = action_size
        self.memory = deque(maxlen=2000)
        self.gamma = 0.95
        self.epsilon = 1.0
        self.epsilon_decay = 0.995
        self.epsilon_min = 0.01
        self.learning_rate = 0.001
        self.model = self._build_model()

    def _build_model(self):
        model = Sequential()
        model.add(Dense(24, input_dim=self.state_size, activation='relu'))
        model.add(Dense(24, activation='relu'))
        model.add(Dense(self.action_size, activation='linear'))
        model.compile(loss='mse', optimizer=Adam(learning_rate=self.learning_rate))
        return model

    def remember(self, state, action, reward, next_state, done):
        self.memory.append((state, action, reward, next_state, done))

    def act(self, state):
        if np.random.rand() <= self.epsilon:
            return random.randrange(self.action_size)
        act_values = self.model.predict(state, verbose=0)
        return np.argmax(act_values[0])

    def replay(self, batch_size):
        if len(self.memory) < batch_size:
            return
        minibatch = random.sample(self.memory, batch_size)
        for state, action, reward, next_state, done in minibatch:
            target = reward
            if not done:
                target = (reward + self.gamma * np.amax(self.model.predict(next_state, verbose=0)[0]))
            target_f = self.model.predict(state, verbose=0)
            target_f[0][action] = target
            self.model.fit(state, target_f, epochs=1, verbose=0)
        if self.epsilon > self.epsilon_min:
            self.epsilon *= self.epsilon_decay

    def save_model(self, path):
        self.model.save(path)

    def load_model(self, path):
        self.model = tf.keras.models.load_model(path)

# ==============================================================================
# ANOMALY DETECTION (AI)
# ==============================================================================
class AnomalyDetector:
    def __init__(self):
        self.model = None
        self.threshold = 0.5
        self.is_initialized = False # <--- ADD THIS LINE

    def train(self, data):
        if data.shape[0] < 2: # Ensure at least 2 samples for IsolationForest
            print("WARNING: Not enough data to train Anomaly Detector. Need at least 2 samples.")
            self.is_initialized = False
            return
        self.model = IsolationForest(random_state=42)
        self.model.fit(data)
        self.is_initialized = True # <--- SET TO TRUE ON SUCCESSFUL TRAINING
        print("Anomaly Detector trained successfully.")

    def predict(self, data):
        if self.model and self.is_initialized:
            scores = self.model.decision_function(data)
            return scores < self.threshold # Returns True for anomaly, False for normal
        print("WARNING: Anomaly Detector not trained. Returning False for all predictions.")
        return np.array([False] * len(data))

    def save_model(self, path):
        if self.model: # Only save if a model exists
            joblib.dump(self.model, path)
            print(f"Anomaly Detector model saved to {path}")

    def load_model(self, path):
        try:
            self.model = joblib.load(path)
            self.is_initialized = True # Set to True if successfully loaded
            print(f"Anomaly Detector model loaded from {path}")
        except FileNotFoundError:
            print(f"Anomaly Detector model not found at {path}. Will train on startup.")
            self.is_initialized = False
        except Exception as e:
            print(f"Error loading Anomaly Detector model from {path}: {e}")
            self.is_initialized = False

# Global instances for AI models (initialized lazily)
rl_agent = DQLAgent(state_size=9, action_size=3) #
anomaly_detector = AnomalyDetector() # This line should be present

# ==============================================================================
# ML FEATURE EXTRACTION HELPERS
# ==============================================================================

def extract_features(attack_data):
    """
    Extracts defined features from attack data.
    """
    payload = attack_data.get('payload', '')
    scanned_path = attack_data.get('scanned_path', '')
    timestamp_input = attack_data.get('timestamp') # Get the timestamp input, can be None or string
    
    dt_object = None
    if isinstance(timestamp_input, str):
        try:
            # Try to parse the string timestamp
            dt_object = datetime.fromisoformat(timestamp_input.replace('Z', '+00:00')) # Handle 'Z' for UTC
        except ValueError:
            # Fallback to current UTC time if string is invalid ISO format
            dt_object = datetime.utcnow()
    elif timestamp_input is None:
        # If timestamp is not provided, use current UTC time
        dt_object = datetime.utcnow()
    else:
        # If it's not a string and not None, assume it's already a datetime object or fall back
        # For simplicity, we'll just use current UTC time as a fallback for unexpected types
        dt_object = datetime.utcnow()

    # Ensure dt_object is not None before proceeding
    if dt_object is None:
        # This case should ideally not happen with the above logic, but as a safeguard
        dt_object = datetime.utcnow()

    # Feature 1: request_path_length
    full_request_content = f"{scanned_path} {payload}"
    request_path_length = len(full_request_content.strip()) if full_request_content.strip() else 0

    # Feature 2: http_method_encoded
    http_method_map = {'GET': 0, 'POST': 1, 'PUT': 2, 'DELETE': 3, 'HEAD': 4, 'OPTIONS': 5, 'UNKNOWN': -1}
    http_method_encoded = http_method_map.get(attack_data.get('method', 'UNKNOWN').upper(), -1)

    # Feature 3, 4, 5: Pattern matching for common attack types
    content_to_scan = (payload if isinstance(payload, str) else json.dumps(payload) if payload else "") + " " + (scanned_path if scanned_path else "")
    content_to_scan = content_to_scan.lower()

    is_sql_injection_pattern = bool(
        re.search(r"select.*from|union.*select|' or '1'='1|--|#|cast\(|convert\(", content_to_scan)
    )
    is_xss_pattern = bool(
        re.search(r"<script>|alert\(|onerror|onload|javascript:|eval\(", content_to_scan)
    )
    is_dir_trav_pattern = bool(
        re.search(r"\.\./|\.\.\\|%2e%2e%2f|%2e%2e%5c", content_to_scan)
    )

    # Feature 6: hour_of_day
    hour_of_day = dt_object.hour

    # Feature 7: day_of_week (Monday=0, Sunday=6)
    day_of_week = dt_object.weekday()

    return {
        'request_path_length': request_path_length,
        'http_method_encoded': http_method_encoded,
        'is_sql_injection_pattern': is_sql_injection_pattern,
        'is_xss_pattern': is_xss_pattern,
        'is_dir_trav_pattern': is_dir_trav_pattern,
        'hour_of_day': hour_of_day,
        'day_of_week': day_of_week,
    }

#====APPLICATION CONTEXT BLOCK======
with app.app_context():
    # db.create_all() # Commented out, migrations will handle schema creation
    print(f"DEBUG: Flask app is connecting to database: {app.config['SQLALCHEMY_DATABASE_URI']}")

    # --- Anomaly Detector Initialization & Training ---
    # Store anomaly_detector instance on app.extensions for access later
    if 'anomaly_detector' not in app.extensions:
        app.extensions['anomaly_detector'] = anomaly_detector # Use the global instance
        app.extensions['anomaly_detector'].is_initialized = False # Initial state

    print("Attempting to load or train Anomaly Detector model...")
    MODEL_PATH = os.path.join(app.instance_path, 'anomaly_detector_model.joblib')

    # Try to load existing model
    app.extensions['anomaly_detector'].load_model(MODEL_PATH)

    if not app.extensions['anomaly_detector'].is_initialized:
        # If model not loaded, train it
        all_attacks = Attack.query.all()
        
        # Prepare features for training
        if all_attacks:
            features_list = []
            for attack in all_attacks:
                # Re-extract features using your extract_features function
                # Ensure the data passed to extract_features matches its expected input structure
                extracted = extract_features({
                    'payload': attack.payload,
                    'scanned_path': attack.scanned_path,
                    'timestamp': attack.timestamp.isoformat() if attack.timestamp else None,
                    'type': attack.type,
                    'method': 'UNKNOWN' # Assuming method might not be directly in Attack model yet
                })
                # Order of features MUST match what you expect in the model
                features_vector = [
                    extracted['request_path_length'],
                    extracted['http_method_encoded'],
                    1 if extracted['is_sql_injection_pattern'] else 0,
                    1 if extracted['is_xss_pattern'] else 0,
                    1 if extracted['is_dir_trav_pattern'] else 0,
                    extracted['hour_of_day'],
                    extracted['day_of_week']
                ]
                features_list.append(features_vector)
            
            if features_list:
                training_data = np.array(features_list)
                app.extensions['anomaly_detector'].train(training_data)
                
                # Save the model after training
                if app.extensions['anomaly_detector'].is_initialized:
                    app.extensions['anomaly_detector'].save_model(MODEL_PATH)
            else:
                print("No historical attack data available to train Anomaly Detector.")
        else:
            print("No historical attack data available to train Anomaly Detector.")

    # --- RL Agent Initialization ---
    # This will be for a later step, but ensuring the global instance is accessible.
    if 'rl_agent' not in app.extensions:
        app.extensions['rl_agent'] = rl_agent # Use the global instance

# ==============================================================================
# DATABASE MODELS & USER LOADER
# ==============================================================================
# Import models *after* the db object has been initialized with the app


# This function tells Flask-Login how to load a user from the user_id stored in the session
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ==============================================================================
# GEO-LOCATION & THREAT INTELLIGENCE FUNCTIONS
# ==============================================================================

IPINFO_API_KEY = os.environ.get('IPINFO_API_KEY')
IPINFO_API_KEY = os.environ.get('IPINFO_API_KEY')

# Ensure logging is imported if not already

# Assuming IPINFO_API_KEY is defined globally or loaded from environment variables
# For example:
# from dotenv import load_dotenv
# load_dotenv()
# IPINFO_API_KEY = os.getenv("IPINFO_API_KEY")


# ==============================================================================
# THREAT INTELLIGENCE INTEGRATION (e.g., AbuseIPDB, VirusTotal, etc.)
# ==============================================================================

# IMPORTANT: Replace with your actual Threat Intelligence API Key and URL
# Load these from your .env file or environment variables for security
THREAT_INTEL_API_KEY = os.getenv("THREAT_INTEL_API_KEY") # Define this in your .env
THREAT_INTEL_API_URL = "https://api.abuseipdb.com/api/v2/check" # Example URL for AbuseIPDB

def check_ip_reputation(ip_address):
    """
    Checks the reputation of an IP address using a threat intelligence service.
    Returns a dictionary with reputation data, or None if an error occurs.
    """
    if not THREAT_INTEL_API_KEY:
        app.logger.warning("THREAT_INTEL_API_KEY not set. Cannot check IP reputation.")
        return None

    # Skip checking private or local IPs
    if ip_address == "127.0.0.1" or ip_address.startswith("192.168.") or \
       ip_address.startswith("10.") or ip_address.startswith("172.16."):
        app.logger.info(f"Skipping threat intel check for private/local IP: {ip_address}")
        return {"reputation": "private_ip", "confidence": 0, "is_whitelisted": False}

    headers = {
        'Key': THREAT_INTEL_API_KEY,
        'Accept': 'application/json',
    }
    params = {
        'ipAddress': ip_address,
        'maxAgeInDays': '90', # Check reports from the last 90 days
        'verbose': '' # Include all available data
    }

    try:
        app.logger.info(f"Checking IP reputation for {ip_address} using {THREAT_INTEL_API_URL}")
        response = requests.get(THREAT_INTEL_API_URL, headers=headers, params=params, timeout=10)
        response.raise_for_status() # Raise an exception for HTTP errors
        data = response.json()

        # Parse relevant data from the response (this part depends on the API's structure)
        if 'data' in data and data['data']:
            report = data['data']
            reputation = {
                "ipAddress": report.get('ipAddress'),
                "abuseConfidenceScore": report.get('abuseConfidenceScore', 0),
                "isPublic": report.get('isPublic'),
                "isWhitelisted": report.get('isWhitelisted', False),
                "totalReports": report.get('totalReports', 0),
                "numDistinctUsers": report.get('numDistinctUsers', 0),
                "lastReportedAt": report.get('lastReportedAt')
            }
            app.logger.info(f"IP {ip_address} reputation: Confidence {reputation['abuseConfidenceScore']}")
            return reputation
        else:
            app.logger.info(f"No reputation data found for {ip_address}.")
            return {"reputation": "clean", "confidence": 0} # Assume clean if no data

    except requests.exceptions.RequestException as e:
        app.logger.error(f"Error checking IP reputation for {ip_address}: {e}")
        # If response exists, log its content for more details
        if e.response is not None:
            app.logger.error(f"Threat Intel API Error Response: {e.response.text}")
        return None
    except Exception as e:
        app.logger.error(f"An unexpected error occurred during IP reputation check: {e}")
        return None

# Assuming 'app' exists and has a logger, e.g., app.logger
# For a standalone function, you might use Python's default logging:
# logging.basicConfig(level=logging.INFO)
# logger = logging.getLogger(__name__)


def get_geolocation_data(ip_address):
    # Ensure IPINFO_API_KEY is accessible, e.g., as a global variable or passed in
    # This check needs to reference the actual variable where the key is stored
    # Assuming IPINFO_API_KEY is a global variable from app.py context
    # If not, you might need to pass it as an argument or ensure it's accessible.
    try:
        # Access the current_app context for logger if running within a Flask app
        # If not, use the standard logging module
        current_logger = logging.getLogger(__name__) # Fallback logger
        if 'app' in globals() and hasattr(app, 'logger'): # Check if Flask app exists
            current_logger = app.logger
    except NameError:
        current_logger = logging.getLogger(__name__)
        logging.basicConfig(level=logging.INFO) # Ensure basic config if app.logger not available

    if not IPINFO_API_KEY: # This IPINFO_API_KEY needs to be defined somewhere in your app.py
        current_logger.warning("IPINFO_API_KEY not set. Cannot perform geo-location lookup.")
        return None, None, None, None

    if ip_address == "127.0.0.1" or \
       ip_address.startswith("192.168.") or \
       ip_address.startswith("10.") or \
       ip_address.startswith("172.16."): # Corrected indentation for continuity
        return None, None, None, None

    try:
        url = f"https://ipinfo.io/{ip_address}/json?token={IPINFO_API_KEY}"
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        data = response.json()

        country = data.get('country')
        city = data.get('city')
        loc = data.get('loc')

        latitude, longitude = None, None
        if loc:
            try:
                latitude, longitude = map(float, loc.split(','))
            except ValueError:
                current_logger.error(f"Could not parse 'loc' data '{loc}' for IP {ip_address}.")


        return country, city, latitude, longitude

    except requests.exceptions.RequestException as e:
        current_logger.error(f"Error fetching geo-location for {ip_address}: {e}")
        return None, None, None, None
    except ValueError as e:
        current_logger.error(f"Error parsing geo-location data for {ip_address}: {e}")
        return None, None, None, None
    except Exception as e:
        current_logger.error(f"An unexpected error occurred during geo-location lookup for {ip_address}: {e}")
        return None, None, None, None

# app.py

# ... (existing imports, app setup, db setup, etc.) ...




        

# ==============================================================================
# IP BLOCKING MECHANISM
# ==============================================================================
blocked_ips = {} # This seems to be a global variable, keep it outside functions

def block_ip(ip_address, duration_minutes=60):
    block_until = datetime.utcnow() + timedelta(minutes=duration_minutes)
    blocked_ips[ip_address] = block_until
    print(f"IP {ip_address} blocked until {block_until.isoformat()}")

def is_ip_blocked(ip_address):
    if ip_address in blocked_ips:
        if datetime.utcnow() < blocked_ips[ip_address]:
            return True
        else:
            del blocked_ips[ip_address]
    return False

# ==============================================================================
# UTILITY FUNCTIONS (for dashboard data)
# ==============================================================================
def get_recent_attack_data(days=7):
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=days)
    attacks = Attack.query.filter(Attack.timestamp >= start_date).all()

    date_counts = {}
    for i in range(days):
        date = (start_date + timedelta(days=i)).strftime('%Y-%m-%d')
        date_counts[date] = 0

    for attack in attacks:
        date = attack.timestamp.strftime('%Y-%m-%d')
        if date in date_counts:
            date_counts[date] += 1
    return list(date_counts.keys()), list(date_counts.values())

def get_top_attackers(limit=5):
    top_attackers_query = db.session.query(
        Attack.ip,
        func.count(Attack.id).label('attack_count'),
        func.group_concat(func.distinct(Attack.type)).label('attack_types')
    ).group_by(Attack.ip).order_by(func.count(Attack.id).desc()).limit(limit).all()

    formatted_attackers = []
    for attacker in top_attackers_query:
        formatted_attackers.append({
            'ip': attacker.ip,
            'attack_count': attacker.attack_count,
            'attack_types': attacker.attack_types.split(',') if attacker.attack_types else []
        })
    return formatted_attackers

def get_honeypot_stats():
    honeypots = Honeypot.query.all()
    return honeypots

# ADD THIS NEW DECORATOR
def api_key_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Get API key from headers or JSON payload
        api_key = request.headers.get('X-API-KEY') or (request.json and request.json.get('api_key'))
        honeypot_name = request.json and request.json.get('honeypot_name')
        
        if not api_key or not honeypot_name:
            print(f"DEBUG: API key or honeypot name missing. API Key: {api_key}, Honeypot Name: {honeypot_name}")
            return jsonify({"error": "API key and honeypot name required"}), 401
            
        # Verify the API key matches the honeypot's registered key
        configured_key = app.config['HONEYPOT_API_KEYS'].get(honeypot_name)
        if api_key != configured_key:
            print(f"DEBUG: Invalid API key for {honeypot_name}. Received: {api_key}, Expected: {configured_key}")
            return jsonify({"error": "Invalid API key for this honeypot"}), 401
          
        print(f"DEBUG: API key validated for {honeypot_name}")
        return f(*args, **kwargs)
    return decorated_function


# ==============================================================================
# HONEYPOT CONFIGURATION (Example)
# ==============================================================================
HONEYPOT_TYPES = {
    "ssh": {"port": 22, "banner": "SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3", "description": "Simulated SSH server"},
    "http": {"port": 80, "banner": "Apache/2.4.29 (Ubuntu)", "description": "Simulated HTTP server"},
    "ftp": {"port": 21, "banner": "220 ProFTPD 1.3.5d Server (Debian)", "description": "Simulated FTP server"}
}



# ==============================================================================
# SOCKETIO EVENT HANDLERS
# ==============================================================================
@socketio.on('connect')
def test_connect():
    print('Client connected')
    emit('my response', {'data': 'Connected'})

@socketio.on('disconnect')
def test_disconnect():
    print('Client disconnected')

@socketio.on('request_dashboard_data')
def handle_request_dashboard_data():
    with app.app_context():
        date_labels, attack_data = get_recent_attack_data()
        top_attackers = get_top_attackers()
        total_events = Attack.query.count()
        unique_ips = db.session.query(func.count(func.distinct(Attack.ip))).scalar()
        threats = Attack.query.filter_by(is_threat=True).count()
        honeypots = get_honeypot_stats()

        emit('dashboard_update', {
            'date_labels': date_labels,
            'attack_data': attack_data,
            'top_attackers': top_attackers,
            'total_events': total_events,
            'unique_ips': unique_ips,
            'threats': threats,
           'honeypots': [{'id': h.id, 'name': h.name, 'type': h.type, 'status': h.status, 'attack_count': h.attack_count} for h in honeypots]
        })


# ==============================================================================
# ROUTES
# ==================================================.============================

@app.route("/")
@login_required
def dashboard():
    honeypots = get_honeypot_stats()
    total_events = Attack.query.count()
    unique_ips = db.session.query(func.count(func.distinct(Attack.ip))).scalar()
    threats = Attack.query.filter_by(is_threat=True).count()

    date_labels, attack_data = get_recent_attack_data()
    top_attackers = get_top_attackers()

    return render_template(
        "dashboard.html",
        honeypots=honeypots,
        total_events=total_events,
        unique_ips=unique_ips,
        threats=threats,
        date_labels=date_labels,
        attack_data=attack_data,
        top_attackers=top_attackers
    )

@app.route('/honeypots', methods=['POST'])
def create_honeypot():
    data = request.json
    new_hp = Honeypot(
        name=data['name'],
        type=data['type'],
        api_key=data['api_key'],
        ip_address=data.get('ip_address')
    )
    db.session.add(new_hp)
    db.session.commit()
    return jsonify({'message': 'Honeypot created', 'id': new_hp.id}), 201

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5/minute")
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        password = request.form.get('password')

        if user and user.check_password(password):
            login_user(user)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html')

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role', 'slave')

        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already registered. Please login.', 'warning')
            return redirect(url_for('signup'))

        new_user = User(username=name, email=email, role=role)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created successfully! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('signup.html')


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route("/forgot_password", methods=["GET", "POST"])
@limiter.limit("2/minute")
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if user:
            # Use the imported get_serializer()
            token = get_serializer().dumps(email, salt='password-reset-salt')
            msg = Message('Password Reset Request',
                          sender=app.config['MAIL_USERNAME'],
                          recipients=[email])
            link = url_for('reset_password', token=token, _external=True)
            msg.body = f'Your password reset link is: {link}\n\nThis link is valid for 1 hour.'
            try:
                mail.send(msg)
                flash('A password reset link has been sent to your email.', 'info')
            except Exception as e:
                flash(f'Error sending email: {e}. Please check your mail configuration.', 'danger')
        else:
            flash('Email not found.', 'danger')
        return redirect(url_for('forgot_password'))
    return render_template('forgot_password.html')

@app.route("/reset_password/<token>", methods=["GET", "POST"])
def reset_password(token):
    try:
        # Use the imported get_serializer()
        email = get_serializer().loads(token, salt='password-reset-salt', max_age=3600)
    except SignatureExpired:
        flash('The password reset link has expired.', 'danger')
        return redirect(url_for('forgot_password'))
    except BadSignature:
        flash('The password reset link is invalid.', 'danger')
        return redirect(url_for('forgot_password'))

    user = User.query.filter_by(email=email).first()
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        if not new_password or new_password != confirm_password:
            flash('Passwords do not match or are empty.', 'danger')
            return render_template('reset_password.html', token=token)
        user.set_password(new_password)
        db.session.commit()
        flash('Your password has been reset!', 'success')
        return redirect(url_for('login'))
    return render_template('reset_password.html', token=token)

@app.route("/admin_panel")
@login_required
def admin_panel():
    if current_user.role != 'master':
        flash('Access denied. You must be a master user to access the admin panel.', 'danger')
        return redirect(url_for('dashboard'))
    users = User.query.all()
    honeypots = Honeypot.query.all()
    return render_template('admin_panel.html', users=users, honeypots=honeypots)

# app.py

# ... (your existing imports, make sure 'db' and 'AttackLog' are imported) ...
from sqlalchemy import func # Add this import at the top with other imports

# ... (your existing app setup and other routes) ...

@app.route('/ai_panel')
@login_required
def ai_panel():
    attack_logs = Attack.query.all()

    # ... (your existing code to calculate attack_type_counts, sorted_attack_types, top_attack_types) ...
    attack_type_counts = {}
    for log in attack_logs:
        attack_type_counts[log.type] = attack_type_counts.get(log.type, 0) + 1
    
    sorted_attack_types = sorted(attack_type_counts.items(), key=lambda item: item[1], reverse=True)
    top_attack_types = sorted_attack_types[:5] 

    unique_ips = len(set(log.ip for log in attack_logs))
    total_attacks = len(attack_logs)

    # --- NEW: Prepare data for Chart.js ---
    top_attack_labels = [item[0] for item in top_attack_types] # e.g., ['SQL Injection', 'Port Scan']
    top_attack_data = [item[1] for item in top_attack_types]   # e.g., [15, 10]


    # Pass the insights (including chart data) to the template
    return render_template(
        'ai_panel.html',
        top_attack_types=top_attack_types, # Keep this for the list if you want both
        unique_ips=unique_ips,
        total_attacks=total_attacks,
        top_attack_labels=json.dumps(top_attack_labels), # Pass as JSON string
        top_attack_data=json.dumps(top_attack_data)     # Pass as JSON string
    )
# ... (rest of your app.py) ...


@app.route('/confirm/<token>')
def confirm_email(token):
    s = get_serializer()
    try:
        email = s.loads(token, max_age=3600)
    except:
        return jsonify({'error': 'Unauthorized'}), 401
    return jsonify({'message': f'{email} confirmed'})

# ==============================================================================
# ATTACK LOGGING ROUTE (Honeypot Interaction Point)
# ==============================================================================
# Add this anywhere in your app.py, outside of any existing functions/routes
@app.route('/test_post', methods=['POST'])
def test_post_route():
    try:
        test_data = request.get_json()
        print(f"DEBUG: Successfully received data on /test_post: {test_data}")
        return jsonify({"status": "success", "message": "Test POST received!"}), 200
    except Exception as e:
        print(f"ERROR: Exception on /test_post: {e}")
        return jsonify({"error": str(e)}), 400


# ==============================================================================
# ATTACK LOGGING ROUTE (Honeypot Interaction Point)
# ==============================================================================

@app.route('/log_attack', methods=['POST'])
@limiter.limit("100 per minute") # Rate limit this endpoint
# You need to uncomment or re-add the @api_key_required decorator if you want auth
# @api_key_required
def log_attack():
    app.logger.info("Received attack log request.")
    data = request.get_json()

    # --- START OF CRITICAL CHECKS ---
    if not isinstance(data, dict):
        print(f"DEBUG: log_attack received data of unexpected type: {type(data)}. Full data: {data}")
        return jsonify({"error": "Invalid JSON payload or unexpected data type. Expected a dictionary."}), 400
    
    if not data:
        app.logger.error("No JSON data received in log_attack request.")
        return jsonify({"error": "Empty JSON payload provided"}), 400
    # --- END OF CRITICAL CHECKS ---
    
    # Required fields for Attack model (and optional ones, using .get() with defaults)
    ip_address = data.get('ip_address') or request.remote_addr # Use provided or remote IP
    attack_type = data.get('type')
    payload = data.get('payload')
    honeypot_name = data.get('honeypot_name')
    honeypot_type = data.get('honeypot_type')
    api_key = data.get('api_key')
    timestamp_str = data.get('timestamp') # Renamed to avoid conflict with datetime object
    user_agent = data.get('user_agent')
    scanned_path = data.get('scanned_path', '/')
    method = data.get('method', 'UNKNOWN')

    # Convert timestamp string to datetime object
    timestamp_obj = datetime.utcnow()
    if isinstance(timestamp_str, str):
        try:
            timestamp_obj = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        except ValueError:
            app.logger.warning(f"Invalid timestamp format received: {timestamp_str}. Using current UTC time.")

    if not all([attack_type, payload, honeypot_name, honeypot_type, api_key]):
        app.logger.error(f"Missing required fields: type={attack_type}, payload={payload}, honeypot_name={honeypot_name}, honeypot_type={honeypot_type}, api_key={api_key}")
        return jsonify({"error": "Missing required attack data fields"}), 400

    # --- API Key Authentication ---
    # Moved to an earlier, dedicated decorator @api_key_required (if you uncomment it above)
    # If not using the decorator, keep this block here:
    expected_api_key = current_app.config['HONEYPOT_API_KEYS'].get(honeypot_name)
    if not expected_api_key or expected_api_key != api_key:
        app.logger.warning(f"Unauthorized access attempt to {honeypot_name} with key {api_key}. Expected: {expected_api_key}")
        return jsonify({"error": "Unauthorized honeypot access"}), 401

    # --- Geolocation and IP Reputation ---
    country, city, latitude, longitude = get_geolocation_data(ip_address)
    ip_reputation_data = check_ip_reputation(ip_address) # This returns a dict or None

    # --- Honeypot Instance Management ---
    honeypot_instance = Honeypot.query.filter_by(name=honeypot_name).first()
    honeypot_id = None
    if honeypot_instance:
        honeypot_id = honeypot_instance.id
    else:
        new_honeypot = Honeypot(name=honeypot_name, honeypot_type=honeypot_type, api_key=api_key)
        db.session.add(new_honeypot)
        db.session.commit() # Commit new honeypot immediately to get its ID
        honeypot_id = new_honeypot.id
        app.logger.info(f"Created new honeypot instance: {honeypot_name}")

    # --- ML Feature Extraction ---
    features = extract_features({
        'payload': payload,
        'scanned_path': scanned_path,
        'timestamp': timestamp_obj.isoformat(), # Pass datetime obj as ISO string
        'type': attack_type,
        'method': method
    })

    # Convert features dictionary to a list/array in the correct order for prediction
    # This order MUST match the order used during training in app.app_context()
    feature_vector_for_prediction = np.array([[
        features['request_path_length'],
        features['http_method_encoded'],
        1 if features['is_sql_injection_pattern'] else 0,
        1 if features['is_xss_pattern'] else 0,
        1 if features['is_dir_trav_pattern'] else 0,
        features['hour_of_day'],
        features['day_of_week']
    ]])
    
    # --- Anomaly Detection and Threat Level Assignment ---
    action_taken = "log_only"
    threat_level = "low" # Default threat level
    is_anomaly = False # Default to False
    is_threat = False # Default to False (for known signature threats)

    # 1. Check for known signature-based threats
    if attack_type in ["SQL Injection", "XSS Attack", "Directory Traversal", "Malware Upload", "Port Scan", "SSH Brute Force"]:
        is_threat = True
        threat_level = "high" # Initial high based on type

    # 2. Anomaly Detection
    anomaly_detector_instance = current_app.extensions.get('anomaly_detector')
    if anomaly_detector_instance and anomaly_detector_instance.is_initialized:
        try:
            # IsolationForest's decision_function returns positive for normal, negative for anomalous
            prediction_scores = anomaly_detector_instance.model.decision_function(feature_vector_for_prediction)
            anomaly_score = prediction_scores[0]
            # is_anomaly is True if score is below the threshold (more negative)
            is_anomaly = anomaly_score < anomaly_detector_instance.threshold 

            app.logger.info(f"Anomaly detection for IP {ip_address} (Type: {attack_type}): "
                            f"Score: {anomaly_score:.4f}, Is Anomaly: {is_anomaly}")

            if is_anomaly:
                # If it's an anomaly, escalate threat level if not already critical
                if threat_level != "critical": # Prevent downgrading from manual block etc.
                    threat_level = "critical"
                action_taken = "trigger_alert" # Default action for anomaly
                app.logger.warning(f"ANOMALY ALERT: {attack_type} from {ip_address} detected as anomalous.")

        except Exception as e:
            app.logger.error(f"Error during anomaly detection prediction for {ip_address}: {e}")
            # If anomaly detection fails, threat_level remains based on type or "medium"
            is_anomaly = False # Assume not anomaly if error
    else:
        app.logger.warning("Anomaly Detector not initialized or not found. Skipping prediction for this attack.")
        # threat_level remains based on 'is_threat' or "low" if not already set.

    # 3. IP Blocking Logic (This should potentially override other actions)
    if is_ip_blocked(ip_address):
        app.logger.info(f"Attack from known blocked IP: {ip_address}. Setting action to 'block_ip'.")
        action_taken = "block_ip"
        threat_level = "critical" # Blocked IPs are always critical threats

    # --- Create new Attack entry with all new features ---
    new_attack = Attack(
        ip=ip_address,
        type=attack_type,
        payload=payload,
        user_agent=user_agent,
        scanned_path=scanned_path,
        timestamp=timestamp_obj, # Use the datetime object
        latitude=latitude,
        longitude=longitude,
        country=country,
        city=city,
        honeypot_id=honeypot_id,
        is_threat=is_threat,       # Based on attack_type signature
        is_anomaly=is_anomaly,     # Based on ML model prediction
        threat_intel=json.dumps(ip_reputation_data) if ip_reputation_data else None, # Store as JSON string
        request_path_length=features['request_path_length'],
        http_method_encoded=features['http_method_encoded'],
        is_sql_injection_pattern=features['is_sql_injection_pattern'],
        is_xss_pattern=features['is_xss_pattern'],
        is_dir_trav_pattern=features['is_dir_trav_pattern'],
        hour_of_day=features['hour_of_day'],
        day_of_week=features['day_of_week'],
        # threat_level is determined by logic above
        threat_level=threat_level
    )
    
    db.session.add(new_attack)
    try:
        db.session.commit()
        app.logger.info(f"Attack from {ip_address} (Type: {attack_type}, Anomaly: {is_anomaly}, Threat Level: {threat_level}) logged successfully.")
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Failed to log attack for {ip_address}: {e}")
        return jsonify({"status": "error", "message": "Failed to log attack"}), 500

    # Emit real-time update
    attack_data_for_feed = {
        "id": new_attack.id, # Include ID for dashboard
        "ip_address": ip_address,
        "type": attack_type,
        "timestamp": new_attack.timestamp.isoformat(),
        "honeypot_name": honeypot_name,
        "threat_level": threat_level,
        "action_taken": action_taken,
        "city": city,
        "country": country,
        "is_anomaly": is_anomaly,
        "payload": payload # Include payload for more context in dashboard feed if desired
    }
    socketio.emit('new_attack', attack_data_for_feed)

    # Final response to the honeypot
    message = "Attack logged." # Default message

    if action_taken == "block_ip":
        message = "Attack source blocked due to AI analysis."
    elif action_taken == "trigger_alert":
        message = "Alert triggered for suspicious activity."
    elif action_taken == "redirect_attacker":
        message = "Attack source flagged for redirection (not implemented)."
    elif action_taken == "log_only":
        message = "Attack logged only."
    else:
        message = "No specific action taken."

    return jsonify({
        "status": "logged",
        "message": message,
        "action_taken": action_taken,
        "is_anomaly": is_anomaly, # Include anomaly status in API response
        "threat_level": threat_level # Include threat level in API response
    }), 200

# ==============================================================================
# MAIN APPLICATION RUN
# ==============================================================================

if __name__ == "__main__":
    print("Starting AI Honey Pot Dashboard...")

    with app.app_context():
        # Optional: Create a default admin user if one doesn't exist
        if not User.query.filter_by(email='admin@example.com').first():
            print("Creating default admin user...")
            admin_user = User(username='Admin', email='admin@example.com', role='master')
            admin_user.set_password('adminpassword') # PLEASE CHANGE THIS PASSWORD IMMEDIATELY IN PRODUCTION!
            db.session.add(admin_user)
            db.session.commit()
            print("Default admin user created: email=admin@example.com, password=adminpassword")

    socketio.run(app, host="0.0.0.0", port=5001, allow_unsafe_werkzeug=True) # Port back to 5001