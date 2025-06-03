# models.py (Consolidated and Corrected)

# Make sure this import is correct based on your project's structure (e.g., extensions.py)
from extensions import db
from flask_login import UserMixin
from sqlalchemy import UniqueConstraint
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timezone # Ensure timezone is imported if using datetime.utcnow with replace(tzinfo=timezone.utc)

# --- User Model (Your existing User model) ---
class User(db.Model, UserMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    role = db.Column(db.String(20), default='user') # 'user', 'admin', 'master'

    def __repr__(self):
        return f'<User {self.username}>'

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# --- Consolidated Honeypot Model ---
# This version includes fields necessary for app.py's status updates (ip_address, status, last_seen)
# and also includes the relationship for attack_count.

class Honeypot(db.Model):
    __tablename__ = 'honeypots'

    __table_args__ = (
        UniqueConstraint('api_key', name='uq_honeypots_api_key'),
    )

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    type = db.Column(db.String(50), nullable=False)
    ip_address = db.Column(db.String(45), nullable=True)
    status = db.Column(db.String(20), default='active', nullable=False)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    api_key = db.Column(db.String(128), unique=True, nullable=False)

    attacks = db.relationship('Attack', back_populates='honeypot', lazy=True)

    def __repr__(self):
        return f'<Honeypot {self.name} ({self.ip_address}) - {self.status}>'

    @property
    def attack_count(self):
        return len(self.attacks) if self.attacks else 0


# --- Attack Model (with geo-location fields and honeypot relationship) ---
class Attack(db.Model):
    __tablename__ = 'attacks'

    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(45), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    type = db.Column(db.String(100), nullable=False)
    payload = db.Column(db.Text)
    user_agent = db.Column(db.String(255))
    scanned_path = db.Column(db.String(255))
    honeypot_name = db.Column(db.String(100)) # Consider making this nullable=False if always required
    honeypot_type = db.Column(db.String(50)) # Consider making this nullable=False if always required

    # Geo-location fields
    latitude = db.Column(db.Float, nullable=True)
    longitude = db.Column(db.Float, nullable=True)
    country = db.Column(db.String(100), nullable=True)
    city = db.Column(db.String(100), nullable=True)

    # Foreign Key to link to the Honeypot model
    honeypot_id = db.Column(db.Integer, db.ForeignKey('honeypots.id'), nullable=True) # Keep this one
    # Define the relationship to the Honeypot model (use back_populates for consistency)
    honeypot = db.relationship('Honeypot', back_populates='attacks') # Keep this one

    # Threat Intelligence & ML derived fields
    is_threat = db.Column(db.Boolean, nullable=False, server_default='0')
    is_anomaly = db.Column(db.Boolean, nullable=False, server_default='0')
    threat_level = db.Column(db.String(50), default="low")
    threat_intel = db.Column(db.JSON, nullable=True) # Store reputation data as JSON (or Text for SQLite)

    # ML Feature Extraction fields
    request_path_length = db.Column(db.Integer, nullable=True)
    http_method_encoded = db.Column(db.Integer, nullable=True)
    is_sql_injection_pattern = db.Column(db.Boolean, default=False, nullable=True)
    is_xss_pattern = db.Column(db.Boolean, default=False, nullable=True)
    is_dir_trav_pattern = db.Column(db.Boolean, default=False, nullable=True)
    hour_of_day = db.Column(db.Integer, nullable=True)
    day_of_week = db.Column(db.Integer, nullable=True)

    def __repr__(self):
        return f'<Attack from {self.ip} at {self.timestamp}>'