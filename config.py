import os
from datetime import timedelta

# ================= BASE PATH =================

BASE_DIR = os.path.abspath(
    os.path.dirname(__file__)
)

# ================= MAIN CONFIG =================

class Config:

    SECRET_KEY = os.getenv(
        "SECRET_KEY",
        "ransomwareguard-secret-2026"
    )

    SQLALCHEMY_DATABASE_URI = (

        "sqlite:///"

        + os.path.join(
            BASE_DIR,
            "data",
            "ransomwareguard.db"
        )

    )

    SQLALCHEMY_TRACK_MODIFICATIONS = False

    PERMANENT_SESSION_LIFETIME = timedelta(
        minutes=15
    )

    # EMAIL

    MAIL_SERVER = "smtp.gmail.com"

    MAIL_PORT = 587

    MAIL_USE_TLS = True

    MAIL_USERNAME = os.getenv(
        "MAIL_USERNAME"
    )

    MAIL_PASSWORD = os.getenv(
        "MAIL_PASSWORD"
    )

    MAIL_DEFAULT_SENDER = os.getenv(
        "MAIL_USERNAME"
    )


# ================= GLOBAL EMAIL VARIABLE (FIX) =================

ALERT_EMAIL = os.getenv(
    "ALERT_EMAIL",
    os.getenv("MAIL_USERNAME")
)

# ================= PATHS =================

DATA_FOLDER = os.path.join(
    BASE_DIR,
    "data"
)

HONEYPOT_FOLDER = os.path.join(
    BASE_DIR,
    "honeypot"
)

QUARANTINE_FOLDER = os.path.join(
    BASE_DIR,
    "quarantine"
)

BACKUP_FOLDER = os.path.join(
    BASE_DIR,
    "backup"
)

# ================= CREATE FOLDERS =================

os.makedirs(DATA_FOLDER, exist_ok=True)
os.makedirs(HONEYPOT_FOLDER, exist_ok=True)
os.makedirs(QUARANTINE_FOLDER, exist_ok=True)
os.makedirs(BACKUP_FOLDER, exist_ok=True)

# ================= RISK THRESHOLDS =================

LOW_RISK = 30
MEDIUM_RISK = 60
HIGH_RISK = 85