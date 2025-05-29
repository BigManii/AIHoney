# app.py
# ==============================================================================
# IMPORTS
# ==============================================================================

# --- Python Standard Library ---
import os
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

# Load environment variables
load_dotenv()

# --- Import extensions from extensions.py (CORRECT WAY) ---
from extensions import init_extensions, db, login_manager, mail, get_serializer
from flask_mail import Message # Keep Message import if you use it directly


# ==============================================================================
# FLASK APPLICATION SETUP
# ==============================================================================

app = Flask(__name__)

# App Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', '@EmmanuelogboguKey64')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///new_honeypot.db')
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
# DATABASE MODELS & USER LOADER
# ==============================================================================
# Import models *after* the db object has been initialized with the app
from models import User, Attack, Honeypot

# This function tells Flask-Login how to load a user from the user_id stored in the session
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Create database tables within an application context (for initial setup)
with app.app_context():
    db.create_all() # Temporarily add this back to ensure tables exist
    print(f"DEBUG: Flask app is connecting to database: {app.config['SQLALCHEMY_DATABASE_URI']}")
    pass

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

    def train(self, data):
        self.model = IsolationForest(random_state=42)
        self.model.fit(data)

    def predict(self, data):
        if self.model:
            scores = self.model.decision_function(data)
            return scores < self.threshold
        return np.array([False] * len(data))

    def save_model(self, path):
        joblib.dump(self.model, path)

    def load_model(self, path):
        self.model = joblib.load(path)

# Global instances for AI models (initialized lazily)
rl_agent = DQLAgent(state_size=9, action_size=3) #
anomaly_detector = AnomalyDetector()

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
# @api_key_required # <--- KEEP THIS COMMENTED OUT for now if not implemented
# @limiter.exempt   # <--- THIS IS NOW COMMENTED OUT
def log_attack():
    print("DEBUG: Entered log_attack function.")
    global anomaly_detector, rl_agent
    data = request.get_json()
    print(f"DEBUG: RAW Received attack data in log_attack: {data}")
    if not data:
        print("DEBUG: No JSON data received.")
        return jsonify({"error": "No JSON data received"}), 400

    source_ip = data.get('ip_address') or data.get('ip')
    attack_type = data.get('type') or data.get('attack_type')
    payload = data.get('payload') or data.get('details')
    honeypot_name = data.get('honeypot_name')
    honeypot_type = data.get('honeypot_type', 'Unknown')
    user_agent = request.headers.get('User-Agent', 'Unknown')
    timestamp_str = data.get('timestamp')

    print(f"DEBUG: Parsed data - IP: {source_ip}, Type: {attack_type}, Honeypot: {honeypot_name}")

    if not source_ip or not attack_type:
        print(f"DEBUG: Missing critical data. IP: {source_ip}, Type: {attack_type}")
        return jsonify({"error": "Missing IP address or attack type"}), 400

    timestamp = datetime.now(timezone.utc) # Default timestamp if none provided or parsing fails
    if timestamp_str:
        try:
            # datetime.fromisoformat handles 'Z' and standard timezone offsets directly.
            timestamp = datetime.fromisoformat(timestamp_str)

            # Ensure the timestamp is timezone-aware and converted to UTC
            if timestamp.tzinfo is None:
                # If naive, assume it's UTC if it came with 'Z' (which fromisoformat would handle)
                # or treat it as local time and convert to UTC.
                # For consistency with Z suffix, we assume it's UTC if naive at this point.
                timestamp = timestamp.replace(tzinfo=timezone.utc)
            else:
                # If already timezone-aware, convert to UTC
                timestamp = timestamp.astimezone(timezone.utc)

        except ValueError as e:
            print(f"DEBUG: Invalid timestamp format: {timestamp_str} - Error: {e}")
            return jsonify({"error": "Invalid timestamp format. Use ISO format (YYYY-MM-DDTHH:MM:SSZ)"}), 400

    if is_ip_blocked(source_ip):
        print(f"Blocked attack from {source_ip} (already blocked).")
        return jsonify({"status": "blocked", "message": "IP is currently blocked."}), 403

    country, city, latitude, longitude = get_geolocation_data(source_ip)
    threat_intel_result = check_ip_reputation(source_ip)
    is_threat = threat_intel_result.get('is_malicious', False)

    # Ensure payload is a string for len()
    payload_len = len(str(payload)) if payload is not None else 0

    anomaly_input_features = np.array([
        payload_len,
        1 if 'login' in attack_type.lower() else 0,
        1 if 'sql' in attack_type.lower() else 0,
        threat_intel_result.get('score', 0),
        1 if country == 'China' else 0, # Example feature
        random.random(), # Placeholder features
        random.random(),
        random.random(),
        random.random()
    ]).reshape(1, -1)

    is_anomaly = False
    if anomaly_detector.model:
        is_anomaly = bool(anomaly_detector.predict(anomaly_input_features)[0])

    # Get the API key for the honeypot
    honeypot_api_key = current_app.config['HONEYPOT_API_KEYS'].get(honeypot_name)
    if not honeypot_api_key:
        return jsonify({"error": f"API key not configured for honeypot: {honeypot_name}"}), 400

    honeypot = Honeypot.query.filter_by(name=honeypot_name).first()
    if not honeypot:
        # Create new honeypot if it doesn't exist
        honeypot = Honeypot(
            name=honeypot_name,
            type=honeypot_type,
            status="Active",
            last_seen=timestamp, # Corrected from last_activity
            api_key=honeypot_api_key # Added for NOT NULL constraint
        )
        db.session.add(honeypot)
        print(f"Created new honeypot: {honeypot.name} with type {honeypot.type}")
    else:
        # Update existing honeypot
        # Removed honeypot.events += 1 as 'events' column is not used; attack_count property tracks attacks
        honeypot.status = "Active"
        honeypot.last_seen = timestamp # Corrected from last_activity
        if honeypot.type == 'Unknown' and honeypot_type != 'Unknown':
            honeypot.type = honeypot_type
    db.session.commit() # Commit the new/updated honeypot

    new_attack = Attack(
    ip=source_ip,
    timestamp=timestamp,
    type=attack_type, # <--- CORRECTED!
    payload=str(payload),
    honeypot_id=honeypot.id,
    is_threat=is_threat,
    is_anomaly=is_anomaly,
    user_agent=user_agent,
    country=country,
    city=city,
    latitude=latitude,
    longitude=longitude,
    threat_intel=threat_intel_result
)
    db.session.add(new_attack)
    db.session.commit() # Commit the new attack record

    # Now that the attack is committed, honeypot.attack_count will reflect it
    print(f"Logged attack: {attack_type} on {honeypot_name} (Attacks: {honeypot.attack_count}) from {source_ip}") # Used attack_count

    # Emit new attack data via SocketIO
    socketio.emit('new_attack', {
        'id': new_attack.id,
        'ip': source_ip,
        'type': attack_type,
        'timestamp': new_attack.timestamp.isoformat(),
        'user_agent': user_agent,
        'payload': str(payload),
        'country': country,
        'city': city,
        'latitude': latitude,
        'longitude': longitude,
        'is_threat': is_threat,
        'is_anomaly': is_anomaly,
        'honeypot_id': honeypot.id
    }, namespace='/')

    # RL Agent state update and action decision (conceptual, adjust as needed)
    current_state_rl = np.array([
        1 if is_ip_blocked(source_ip) else 0,
        is_threat,
        is_anomaly,
        honeypot.attack_count, # Used attack_count
        len(Attack.query.filter_by(ip=source_ip).all()), # Total attacks from this specific IP
        1 if 'login' in attack_type.lower() else 0, # Simplified feature example
        1 if 'sql' in attack_type.lower() else 0,   # Simplified feature example
        random.random(), # More placeholder features
        random.random()
    ]).reshape(1, -1)

    # Simplified reward based on detection/threat (adjust logic as needed)
    reward = 10 if is_threat or is_anomaly else 1
    action = rl_agent.act(current_state_rl)
    next_state_rl = current_state_rl # For simplicity, next state could be derived from new attack data
    rl_agent.remember(current_state_rl, action, reward, next_state_rl, False) # 'done' usually means episode end
    rl_agent.replay(batch_size=32)

    action_taken = "log_only" # Default action
    if action == 0:
        action_taken = "block_ip"
        block_ip(source_ip)
    elif action == 1:
        action_taken = "trigger_alert"
        # TODO: Implement alert triggering mechanism
    elif action == 2:
        action_taken = "redirect_attacker"
        # TODO: Implement attacker redirection mechanism
    # Additional actions can be defined

    print(f"DEBUG: RL agent took action: {action_taken}") # Debugging print

    message = ""
    if action_taken == "block_ip":
        message = "Attack source blocked due to AI analysis."
    elif action_taken == "trigger_alert":
        message = "Alert triggered for suspicious activity."
    elif action_taken == "redirect_attacker":
        message = "Attack source flagged for redirection (not implemented)."
    elif action_taken == "log_only":
        message = "Attack logged only."
    else:
        message = "No action taken."

    return jsonify({
        "status": "logged",
        "message": message,
        "action_taken": action_taken
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