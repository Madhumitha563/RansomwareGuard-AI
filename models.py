from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()

# ================= USER =================

class User(UserMixin, db.Model):

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    username = db.Column(
        db.String(80)
    )

    email = db.Column(
        db.String(120),
        unique=True
    )

    password_hash = db.Column(
        db.String(255)
    )

    last_login = db.Column(
        db.DateTime
    )


# ================= LOG =================

class Log(db.Model):

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    timestamp = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )

    event_type = db.Column(
        db.String(100)
    )

    description = db.Column(
        db.String(255)
    )

    risk_level = db.Column(
        db.String(20)
    )


# ================= QUARANTINE =================

class QuarantineFile(db.Model):

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    filename = db.Column(
        db.String(255)
    )

    original_path = db.Column(
        db.String(500)
    )

    risk_level = db.Column(
        db.String(20),
        default="High"
    )

    threat_type = db.Column(
        db.String(100),
        default="Suspicious File"
    )

    quarantined_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )

    def __repr__(self):

        return f"<QuarantineFile {self.filename}>"


# ================= RISK HISTORY =================

class RiskHistory(db.Model):

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    timestamp = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )

    risk_score = db.Column(
        db.Integer
    )

    risk_level = db.Column(
        db.String(20)
    )


# ================= NETWORK TRAFFIC =================

class NetworkTraffic(db.Model):

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    timestamp = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )

    connections = db.Column(
        db.Integer
    )


# ================= PROCESS LOG =================

class ProcessLog(db.Model):

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    timestamp = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )

    process_name = db.Column(
        db.String(255)
    )

    pid = db.Column(
        db.Integer
    )

    cpu_usage = db.Column(
        db.Float
    )


# ================= NETWORK LOG =================

class NetworkLog(db.Model):

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    timestamp = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )

    ip_address = db.Column(
        db.String(100)
    )

    port = db.Column(
        db.Integer
    )

    status = db.Column(
        db.String(50)
    )