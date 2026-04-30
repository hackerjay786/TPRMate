from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from datetime import datetime
from sqlalchemy.types import JSON

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(32), default="Viewer", nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    def set_password(self, password): self.password_hash = generate_password_hash(password)
    def check_password(self, password): return check_password_hash(self.password_hash, password)

class Vendor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), unique=True, nullable=False)
    domain = db.Column(db.String(255))
    consent = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class ScanRun(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    vendor_id = db.Column(db.Integer, db.ForeignKey("vendor.id"), nullable=False)
    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)
    status = db.Column(db.String(32), default="running")
    run_path = db.Column(db.String(512))

    passive_status = db.Column(db.String(16), default="pending")
    passive_pct = db.Column(db.Integer, default=0)
    passive_log = db.Column(db.Text, default="")
    passive_pid = db.Column(db.Integer)
    passive_path = db.Column(db.String(512))

    active_status = db.Column(db.String(16), default="pending")
    active_pct = db.Column(db.Integer, default=0)
    active_log = db.Column(db.Text, default="")
    active_pid = db.Column(db.Integer)
    active_path = db.Column(db.String(512))

    p10 = db.Column(db.Float)
    p50 = db.Column(db.Float)
    p90 = db.Column(db.Float)

    vendor = db.relationship("Vendor", backref="runs")

class Finding(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    run_id = db.Column(db.Integer, db.ForeignKey("scan_run.id"), nullable=False)
    severity = db.Column(db.String(16), default="low")
    category = db.Column(db.String(64), default="info")
    description = db.Column(db.Text, default="")
    run = db.relationship("ScanRun", backref="findings")

class AuditEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    event_type = db.Column(db.String(64), nullable=False)
    message = db.Column(db.String(512))
    user_id = db.Column(db.Integer)
    vendor_id = db.Column(db.Integer)
    run_id = db.Column(db.Integer)
    details = db.Column(JSON)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
