from flask import Flask, request
from flask_wtf.csrf import CSRFProtect
from flask_login import LoginManager, current_user
from .config import Config
from .models import db, User, AuditEvent
from .auth import auth_bp
from .main import main_bp
import os

csrf = CSRFProtect()
login_manager = LoginManager()
login_manager.login_view = "auth.login"

@login_manager.user_loader
def load_user(user_id):
    try:
        return db.session.get(User, int(user_id))
    except Exception:
        return None

def _gen_csrf():
    from flask_wtf.csrf import generate_csrf
    return generate_csrf()

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    os.makedirs("data", exist_ok=True)
    os.makedirs("data/runs", exist_ok=True)

    csrf.init_app(app)
    db.init_app(app)
    login_manager.init_app(app)

    app.jinja_env.globals['csrf_token'] = _gen_csrf
    @app.context_processor
    def inject_app_config():
        return {
            "app_config": app.config,
            "real_scans": app.config.get("REAL_SCANS"),
            "fast_demo": app.config.get("FAST_DEMO"),
        }

    @app.after_request
    def _audit_login(resp):
        try:
            if request.endpoint == "auth.login" and current_user.is_authenticated:
                ev = AuditEvent(event_type="login", message="User logged in", user_id=current_user.id)
                db.session.add(ev); db.session.commit()
        except Exception: db.session.rollback()
        return resp

    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    return app

def init_db_and_seed(app):
    with app.app_context():
        db.create_all()
        if not User.query.first():
            admin = User(email="admin@example.com", role="Admin"); admin.set_password("change-me-now")
            db.session.add(admin); db.session.commit()
