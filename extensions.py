# extensions.py
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_mail import Mail
from itsdangerous import URLSafeTimedSerializer
from flask import current_app # Import current_app here for get_serializer

db = SQLAlchemy()
login_manager = LoginManager()
mail = Mail()
serializer_instance = None # Will hold the serializer instance initialized by init_extensions

def init_extensions(app):
    global serializer_instance
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'login' # Set the login view here
    mail.init_app(app)
    serializer_instance = URLSafeTimedSerializer(app.config['SECRET_KEY']) # Initialize serializer

def get_serializer():
    """Returns the URLSafeTimedSerializer instance."""
    # This should correctly return the instance initialized by init_extensions
    # within the application context.
    if serializer_instance is None:
        # Fallback/error case if called before init_extensions or outside app context
        # This part should ideally not be hit if init_extensions is always called on app startup
        if current_app:
            return URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
        else:
            raise RuntimeError("Serializer not initialized and no current_app available.")
    return serializer_instance