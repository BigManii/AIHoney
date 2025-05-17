from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail
from itsdangerous import URLSafeTimedSerializer

db = SQLAlchemy()
mail = Mail()
serializer = None  # Will initialize after app creation


def init_extensions(app):
    global serializer
    db.init_app(app)
    mail.init_app(app)
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
