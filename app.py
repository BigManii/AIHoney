from datetime import datetime, timedelta
from sqlalchemy import func
from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from flask_login import (
    LoginManager,
    login_user,
    logout_user,
    login_required,
    current_user,
)
from itsdangerous import SignatureExpired, BadSignature
from flask_mail import Message
from flask_socketio import SocketIO, emit
from extensions import db, mail, serializer, init_extensions
from models import User, Honeypot, Attack
import uuid, requests

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'
socketio = SocketIO(app, 
                   cors_allowed_origins="*",
                   engineio_logger=True,  # Better logging
                   logger=True)           # See debug info

attacks = []

# Common vulnerable endpoints
VULNERABLE_ROUTES = [
    '/admin', 
    '/wp-login.php',
    '/.env',
    '/phpmyadmin',
    '/db_backup.sql'
]

# Configuration
app.config["SECRET_KEY"] = "your-secret-key"  # Replace with a secure key
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///honeypot.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Mail config example (adjust accordingly)
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = "your-email@gmail.com"  # Replace
app.config["MAIL_PASSWORD"] = "your-email-password"  # Replace

# Initialize extensions
init_extensions(app)

login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)


def get_ip_geo(ip):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}?fields=status,message,country,lat,lon,isp")
        data = response.json()
        if data['status'] == 'success':
            return {
                'lat': data['lat'],
                'lon': data['lon'],
                'country': data['country'],
                'isp': data['isp']
            }
        return None
    except:
        return None


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Helper functions (replace with real queries)
def get_events_chart_data():
    # Query attacks from the last 7 days and group by date
    attacks_by_date = db.session.query(
        func.date(Attack.timestamp).label('date'),
        func.count(Attack.id).label('count')
    ).filter(
        Attack.timestamp >= datetime.now() - timedelta(days=7)
    ).group_by(
        func.date(Attack.timestamp)
    ).all()

    # Format data for Chart.js
    labels = [str(record.date) for record in attacks_by_date]
    values = [record.count for record in attacks_by_date]

    return {"labels": labels, "values": values}


def get_top_attackers():
    return [
        {"ip_address": "192.168.1.1", "count": 25},
        {"ip_address": "10.0.0.2", "count": 15},
    ]


def get_top_services():
    return [
        {"name": "SSH", "count": 40},
        {"name": "HTTP", "count": 20},
    ]


# Routes


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").lower()
        password = request.form.get("password", "")

        if User.query.filter_by(email=email).first():
            flash("Email address already exists", "danger")
            return redirect(url_for("signup"))

        new_user = User(name=name, email=email)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        login_user(new_user)
        flash("Signup successful! Welcome.", "success")
        return redirect(url_for("dashboard"))

    return render_template("signup.html")


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            login_user(user)
            # Only flash ONCE
            flash("Logged in successfully.", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid email or password.", "danger")

    return render_template("login.html")



from flask import Flask, render_template
from flask_login import login_required, current_user
from models import Honeypot, Attack  # Your SQLAlchemy models
from datetime import datetime, timedelta
from sqlalchemy import func




@socketio.on('connect')
def handle_connect():
    print('Client connected')

# Replace with this updated version to avoid conflicts
def log_and_broadcast_attack(attack_data):
    # 1. Save to database
    new_attack = Attack(
        ip_address=attack_data['ip'],
        timestamp=datetime.fromisoformat(attack_data['timestamp']),
        # ... other fields ...
    )
    db.session.add(new_attack)
    db.session.commit()
    
    # 2. Broadcast via Socket.IO
    socketio.emit('new_attack', {
        **attack_data,
        'db_id': new_attack.id  # Include DB record ID
    })

@app.route("/dashboard")
@login_required
def dashboard():
    # Honeypot data with attack counts
    honeypots = Honeypot.query.options(db.joinedload(Honeypot.attacks)).all()
    
    # Attack statistics
    total_events = Attack.query.count()
    unique_ips = db.session.query(Attack.ip_address).distinct().count()
    threats = Attack.query.filter_by(is_threat=True).count()
    
    # Last 7 days attack data
    date_counts = db.session.query(
        func.date(Attack.timestamp).label('date'),
        func.count(Attack.id).label('count')
    ).filter(
        Attack.timestamp >= datetime.now() - timedelta(days=6)
    ).group_by(func.date(Attack.timestamp)).all()

    # Prepare chart data (fill missing days)
    date_labels = []
    attack_data = []
    
    for i in range(7):
        day = datetime.now().date() - timedelta(days=6-i)
        date_labels.append(day.strftime('%Y-%m-%d'))
        count = next((x.count for x in date_counts if x.date == day), 0)
        attack_data.append(count)
    
    # Top attackers with services
    top_attackers = db.session.query(
        Attack.ip_address,
        Honeypot.type.label('service'),
        func.count(Attack.id).label('count')
    ).join(Honeypot).group_by(
        Attack.ip_address,
        Honeypot.type
    ).order_by(
        func.count(Attack.id).desc()
    ).limit(5).all()

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
    return render_template(
        "dashboard.html",
        honeypots=honeypots,
        total_events=total_events,
        unique_ips=unique_ips,
        threats=threats,
        attack_data=attack_data,
        top_attackers=top_attackers,
        datetime=datetime,
        timedelta=timedelta
    )

@app.route("/attacks")
@login_required
def attacks():
    recent_attacks = Attack.query.order_by(Attack.timestamp.desc()).limit(50).all()
    return render_template("attacks.html", attacks=recent_attacks)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("index"))


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").lower()
        user = User.query.filter_by(email=email).first()
        if user:
            token = serializer.dumps(email, salt="password-reset-salt")
            reset_url = url_for("reset_password", token=token, _external=True)

            msg = Message(subject="Password Reset Request", recipients=[email])
            msg.body = f"To reset your password, click the following link:\n{reset_url}\n\nIf you did not request this, please ignore this email."
            mail.send(msg)

        flash(
            "If an account with that email exists, a reset link has been sent.", "info"
        )
        return redirect(url_for("login"))

    return render_template("forgot_password.html")


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    try:
        email = serializer.loads(token, salt="password-reset-salt", max_age=3600)
    except SignatureExpired:
        flash("The password reset link has expired.", "danger")
        return redirect(url_for("forgot_password"))
    except BadSignature:
        flash("Invalid password reset token.", "danger")
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        password = request.form.get("password")
        password_confirm = request.form.get("password_confirm")
        if password != password_confirm:
            flash("Passwords do not match.", "danger")
            return redirect(url_for("reset_password", token=token))

        user = User.query.filter_by(email=email).first()
        if user:
            user.set_password(password)
            db.session.commit()
            flash("Your password has been updated! You can now login.", "success")
            return redirect(url_for("login"))
        else:
            flash("User not found.", "danger")
            return redirect(url_for("forgot_password"))

    return render_template("reset_password.html")


@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    if getattr(current_user, "role", "slave") != "master":
        flash("Access denied.", "danger")
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        some_setting = request.form.get("some_setting")
        # Save to database or config here
        flash("Settings updated successfully!", "success")
        return redirect(url_for("settings"))

    current_settings = {"some_setting": "example_value"}

    return render_template("settings.html", settings=current_settings)

@app.route('/')
def home():
    return render_template('fake_login.html')

@app.route('/login', methods=['POST'])
def fake_login():
    # Log all login attempts
    attack_data = {
        'id': str(uuid.uuid4()),
        'type': 'login_attempt',
        'ip': request.remote_addr,
        'timestamp': datetime.now().isoformat(),
        'payload': {
            'username': request.form.get('username'),
            'password': request.form.get('password')
        },
        'user_agent': request.headers.get('User-Agent'),
        'headers': dict(request.headers)
    }
    
    attacks.append(attack_data)
    socketio.emit('new_attack', attack_data)  # Real-time update
    
    # Always return invalid credentials
    return "Invalid username or password", 401


    # Initialize with your existing app
socketio = SocketIO(app)

# Keep only ONE version of this route in your entire app.py
@app.route('/log_attack', methods=['POST'])
def log_attack():
    attack_data = {
        'ip': request.remote_addr,
        'timestamp': datetime.now().isoformat(),
        'user_agent': request.headers.get('User-Agent'),
        'geo': get_ip_geo(request.remote_addr)  # From previous implementation
    }
    
    # Add payload if it's a login attempt
    if request.is_json:
        attack_data.update(request.json)
    elif request.form:
        attack_data['payload'] = dict(request.form)
    
    attacks.append(attack_data)
    socketio.emit('new_attack', attack_data)
    
    return jsonify({"status": "logged"})

@app.route('/<path:path>')
def catch_all(path):
    if path in VULNERABLE_ROUTES:
        attack_data = {
            'id': str(uuid.uuid4()),
            'type': 'vulnerability_scan',
            'ip': request.remote_addr,
            'timestamp': datetime.now().isoformat(),
            'scanned_path': path,
            'user_agent': request.headers.get('User-Agent')
        }
        
        attacks.append(attack_data)
        socketio.emit('new_attack', attack_data)
        
        # Return fake responses for common vulnerabilities
        if path == '/.env':
            return "DB_PASSWORD=supersecret\nDB_USER=admin", 200
        elif path == '/wp-login.php':
            return render_template('fake_wordpress_login.html')
    
    return "Not Found", 404

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0", port=5001, debug=True)
