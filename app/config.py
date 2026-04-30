import os
_APP_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
_DATA_DIR = os.path.join(_APP_ROOT, "data")
os.makedirs(_DATA_DIR, exist_ok=True)
_DEFAULT_SQLITE = "sqlite:///" + os.path.join(_DATA_DIR, "app.db")

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-change-me")
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL", _DEFAULT_SQLITE)
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    REAL_SCANS = os.environ.get("REAL_SCANS", "false").lower() == "true"
    FAST_DEMO = os.environ.get("FAST_DEMO", "false").lower() == "true"
    MC_TRIALS = int(os.environ.get("MC_TRIALS", "10000"))
