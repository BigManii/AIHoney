from extensions import db
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

class User(db.Model, UserMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), default='slave')  # 'master' or 'slave'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Honeypot(db.Model):
    __tablename__ = 'honeypots'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    type = db.Column(db.String(50), nullable=False)
    active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Added relationship (from the suggested version)
    attacks = db.relationship('Attack', backref='honeypot', lazy=True)
    
    # Added property (from the suggested version)
    @property
    def attack_count(self):
        return len(self.attacks)

class Attack(db.Model):
    __tablename__ = 'attacks'

    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), nullable=False)
    attack_type = db.Column(db.String(100), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    details = db.Column(db.Text)
    honeypot_id = db.Column(db.Integer, db.ForeignKey('honeypots.id'))
    is_threat = db.Column(db.Boolean, default=False)
    
    # Relationship already exists in your original version
    # honeypot = db.relationship('Honeypot', backref='attacks')
    
    # Removed the duplicate relationship since you already have it