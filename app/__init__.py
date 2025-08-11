# app/__init__.py

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_wtf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import os

db = SQLAlchemy()
login_manager = LoginManager()
login_manager.login_view = 'main.login'

csrf = CSRFProtect()  # ✅ Define csrf
limiter = Limiter(key_func=get_remote_address)

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'your-secret-key'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'

    # Optional security configs
    app.config.update({
        'SESSION_COOKIE_HTTPONLY': True,
        'SESSION_COOKIE_SAMESITE': 'Lax',
        'REMEMBER_COOKIE_HTTPONLY': True,
        'PERMANENT_SESSION_LIFETIME': 900  # 15 minutes
    })

    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)       # ✅ This now works
    limiter.init_app(app)    # ✅ Apply request limiting

    from app.models import User

    @login_manager.user_loader
    def load_user(user_id):
        user = User.query.get(int(user_id))
        return user if user and user.is_active else None

    with app.app_context():
        from app import models
        instance_dir = app.instance_path
        os.makedirs(instance_dir, exist_ok=True)
        db_path = os.path.join(instance_dir, 'site.db')

        if not os.path.exists(db_path):
            print("Creating database and tables...")
            db.create_all()
            print("Database created successfully.")
        else:
            print("Database already exists.")

    from app.routes import main
    app.register_blueprint(main)

    return app