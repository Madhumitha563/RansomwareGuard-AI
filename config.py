
import os
import tempfile
from datetime import timedelta

# ================= BASE PATH =================

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# Vercel deployment filesystem is read-only.
# Use /tmp on Vercel; local development uses project folders.
IS_VERCEL = os.getenv("VERCEL") == "1"

if IS_VERCEL:
    STORAGE_ROOT = os.path.join(tempfile.gettempdir(), "ransomwareguard")
else:
    STORAGE_ROOT = BASE_DIR

# ================= PATHS =================

DATA_FOLDER = os.path.join(STORAGE_ROOT, "data")
HONEYPOT_FOLDER = os.path.join(STORAGE_ROOT, "honeypot")
QUARANTINE_FOLDER = os.path.join(STORAGE_ROOT, "quarantine")
BACKUP_FOLDER = os.path.join(STORAGE_ROOT, "backup")

# Create folders in writable storage
for folder in (
    DATA_FOLDER,
    HONEYPOT_FOLDER,
    QUARANTINE_FOLDER,
    BACKUP_FOLDER,
):
    os.makedirs(folder, exist_ok=True)

# ================= MAIN CONFIG =================

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY")

    if not SECRET_KEY:
        SECRET_KEY = "local-development-only-change-me"

    SQLALCHEMY_DATABASE_URI = (
        "sqlite:///"
        + os.path.join(DATA_FOLDER, "ransomwareguard.db")
    )

    SQLALCHEMY_TRACK_MODIFICATIONS = False

    PERMANENT_SESSION_LIFETIME = timedelta(minutes=15)

    # EMAIL
    MAIL_SERVER = "smtp.gmail.com"
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.getenv("MAIL_USERNAME")
    MAIL_PASSWORD = os.getenv("MAIL_PASSWORD")
    MAIL_DEFAULT_SENDER = os.getenv("MAIL_USERNAME")


# ================= ALERT EMAIL =================

ALERT_EMAIL = os.getenv(
    "ALERT_EMAIL",
    os.getenv("MAIL_USERNAME")
)

# ================= RISK THRESHOLDS =================

LOW_RISK = 30
MEDIUM_RISK = 60
HIGH_RISK = 85
