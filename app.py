from dotenv import load_dotenv
load_dotenv()
from flask_login import current_user
import os
import threading
import time
import random

from datetime import datetime

import psutil


from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session,
    jsonify
)

from flask_login import (
    LoginManager,
    login_user,
    login_required,
    logout_user
)

from response.email_service import send_security_alert

from flask_mail import Mail, Message
from flask_socketio import SocketIO

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

from sqlalchemy import func

from config import Config, QUARANTINE_FOLDER

from models import (
    db,
    User,
    Log,
    QuarantineFile,
    RiskHistory,
    NetworkTraffic
)

from monitor.file_monitor import start_file_monitor
from monitor.process_monitor import start_process_monitor
from monitor.network_monitor import start_network_monitor

from scheduler.cleanup import cleanup_old_files


# ================= INIT =================

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)

socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode="threading"
)

mail = Mail(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


# ================= USER =================

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


# ================= OTP =================

def generate_otp():

    otp = str(
        random.randint(
            100000,
            999999
        )
    )

    print("Generated OTP:", otp)

    return otp


def send_otp_email(recipient, otp):

    try:

        msg = Message(
            subject="OTP Verification",
            recipients=[recipient]
        )

        msg.body = f"""

Your OTP Code:

{otp}

"""

        mail.send(msg)

        print("OTP sent")

    except Exception as e:

        print("Email error:", e)


# ================= ROUTES =================

@app.route("/")
def index():
    return redirect(url_for("login"))


# ================= REGISTER =================

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")

        if User.query.filter_by(email=email).first():

            flash("Email already exists")

            return redirect(url_for("register"))

        user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password)
        )

        db.session.add(user)
        db.session.commit()

        flash("Account created")

        return redirect(url_for("login"))

    return render_template("register.html")


# ================= LOGIN =================

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form.get("email")
        password = request.form.get("password")

        user = User.query.filter_by(
            email=email
        ).first()

        if user and check_password_hash(
            user.password_hash,
            password
        ):

            otp = generate_otp()

            session["otp"] = otp
            session["email"] = email

            send_otp_email(
                email,
                otp
            )

            return redirect(
                url_for("verify_otp")
            )

        flash("Invalid login")

    return render_template("login.html")


# ================= VERIFY OTP =================

@app.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():

    if request.method == "POST":

        entered = request.form.get("otp")

        stored = session.get("otp")

        print("Entered:", entered)
        print("Stored:", stored)

        if entered == stored:

            email = session.get("email")

            user = User.query.filter_by(
                email=email
            ).first()

            login_user(user)

            session.pop("otp", None)

            return redirect(
                url_for("dashboard")
            )

        flash("Invalid OTP")

    return render_template("verify_otp.html")


# ================= LOGOUT =================

@app.route("/logout")
@login_required
def logout():

    logout_user()

    return redirect(url_for("login"))


# ================= DASHBOARD =================

@app.route("/dashboard")
@login_required
def dashboard():

    history = RiskHistory.query.order_by(
        RiskHistory.timestamp.asc()
    ).limit(20).all()

    network_data = NetworkTraffic.query.order_by(
        NetworkTraffic.timestamp.asc()
    ).limit(20).all()

    quarantine_count = (
        QuarantineFile.query.count()
    )

    top_threats = db.session.query(
        QuarantineFile.threat_type,
        func.count()
    ).group_by(
        QuarantineFile.threat_type
    ).all()

    return render_template(
        "dashboard.html",
        history=history,
        network_data=network_data,
        quarantine_count=quarantine_count,
        top_threats=top_threats
    )


# ================= NAVIGATION =================

@app.route("/process")
@login_required
def process_activity():
    return render_template("process_activity.html")


@app.route("/threats")
@login_required
def threats():

    try:

        logs = Log.query.order_by(
            Log.timestamp.desc()
        ).limit(50).all()

        return render_template(
            "threats.html",
            logs=logs
        )

    except Exception as e:

        print("Threat route error:", e)

        return render_template(
            "threats.html",
            logs=[]
        )

@app.route("/files")
@login_required
def file_monitor():
    return render_template("file_monitor.html")


@app.route("/network")
@login_required
def network():
    return render_template("network.html")


@app.route("/logs")
@login_required
def logs():
    return render_template("logs.html")


@app.route("/alerts")
@login_required
def alerts():
    return render_template("alerts.html")


@app.route("/reports")
@login_required
def reports():
    return render_template("reports.html")


@app.route("/backup")
@login_required
def backup():
    return render_template("backup.html")


@app.route("/system")
@login_required
def system():
    return render_template("system.html")


@app.route("/settings")
@login_required
def settings():
    return render_template("settings.html")


# ================= REAL KILL SWITCH =================
@app.route("/kill-switch", methods=["POST"])
@login_required
def kill_switch():

    killed = 0

    try:

        for proc in psutil.process_iter(
            ["pid", "name", "cpu_percent"]
        ):

            try:

                name = proc.info["name"]

                cpu = proc.info["cpu_percent"]

                if cpu > 80:

                    proc.kill()

                    killed += 1

                    print(
                        "Killed:",
                        name
                    )

            except:

                pass

        message = (
            f"{killed} processes terminated"
        )

        log_threat(message)

        # SEND EMAIL

        send_security_alert(

            mail,

            current_user.email,

            "KILL_SWITCH",

            message,

            "CRITICAL"

        )

        return jsonify({

            "message": message

        })

    except Exception as e:

        print(

            "Kill switch error:",

            e

        )

        return jsonify({

            "message":

            "Kill switch failed"

        })
# ================= QUARANTINE MANAGER =================

@app.route("/quarantine")
@login_required
def quarantine_manager():

    try:

        files = QuarantineFile.query.order_by(
        QuarantineFile.quarantined_at.desc()
         ).all()   

        return render_template(
            "quarantine_manager.html",
            files=files
        )

    except Exception as e:

        print("Quarantine error:", e)

        return render_template(
            "quarantine_manager.html",
            files=[]
        )
    

# ================= DELETE QUARANTINE FILE =================

@app.route(
    "/delete-quarantine/<int:file_id>",
    methods=["POST"]
)
@login_required
def delete_quarantine(file_id):

    try:

        file = QuarantineFile.query.get(
            file_id
        )

        if file:

            db.session.delete(file)

            db.session.commit()

            print(
                "File deleted:",
                file.filename
            )

        return jsonify({
            "message":
            "File deleted"
        })

    except Exception as e:

        print("Delete error:", e)

        return jsonify({
            "message":
            "Delete failed"
        })
# ================= REAL-TIME SYSTEM =================

def emit_real_time_data():

    print("Real system monitor running")

    counter = 0

    while True:

        try:

            counter += 1

            cpu = psutil.cpu_percent(interval=1)

            memory = psutil.virtual_memory().percent

            disk = psutil.disk_usage("C:/").percent

            processes = len(psutil.pids())

            connections = len(
                psutil.net_connections()
            )

            risk_score = 0

            if cpu > 80:
                risk_score += 40

            if memory > 80:
                risk_score += 30

            if connections > 100:
                risk_score += 20

            alert = "System normal"

            timestamp = datetime.now().strftime(
                "%H:%M:%S"
            )

            data = {

                # MUST MATCH FRONTEND

                "cpu": cpu,

                "memory": memory,

                "disk": disk,

                "processes": processes,

                "connections": connections,

                "risk_score": risk_score,

                "alert": alert,

                "timestamp": timestamp,

                "counter": counter

            }

            print("Sending:", data)

            socketio.emit(
                "live_update",
                data
            )

            time.sleep(2)

        except Exception as e:

            print(
                "System monitor error:",
                e
            )
# ================= LOG THREAT =================
def log_threat(message):

    try:

        record = Log(

            event_type="Threat",

            description=message,

            risk_level="HIGH",

            timestamp=datetime.now()

        )

        db.session.add(record)

        db.session.commit()

        print("Threat logged")

        # SEND EMAIL TO USER

        send_security_alert(

            mail,

            current_user.email,   # ✅ FIX

            "THREAT",

            message,

            "CRITICAL"

        )

        socketio.emit(

            "threat_update",

            {

                "message": message,

                "timestamp":

                datetime.now()
                .strftime("%H:%M:%S")

            }

        )

    except Exception as e:

        print("Log error:", e)

        db.session.rollback()

# ================= CLEANUP =================

def start_cleanup_scheduler():

    while True:

        with app.app_context():

            cleanup_old_files()

        time.sleep(86400)

# ================= BACKGROUND SERVICES =================

def start_background_services():

    def run_file_monitor():

        with app.app_context():

            print("File monitor started")

            start_file_monitor(
                 socketio,
                 db,
                 app,
                 mail
            )

    def run_process_monitor():

        with app.app_context():

            print("Process monitor started")

            start_process_monitor(
                socketio,
                db
            )

    def run_network_monitor():

        with app.app_context():

            print("Network monitor started")

            start_network_monitor(
                socketio
            )

    def run_cleanup():

        with app.app_context():

            print("Cleanup scheduler started")

            start_cleanup_scheduler()

    def run_system_monitor():

        with app.app_context():

            print("Real-time system monitor started")

            emit_real_time_data()

    threading.Thread(
        target=run_file_monitor,
        daemon=True
    ).start()

    threading.Thread(
        target=run_process_monitor,
        daemon=True
    ).start()

    threading.Thread(
        target=run_network_monitor,
        daemon=True
    ).start()

    threading.Thread(
        target=run_cleanup,
        daemon=True
    ).start()

    threading.Thread(
        target=run_system_monitor,
        daemon=True
    ).start()


# ================= HEALTH =================

@app.route("/api/health")
def health():

    return jsonify({

        "status": "running",

        "time": datetime.now().strftime("%H:%M:%S")

    })

# ================= ACTION BUTTON APIs =================

@app.route("/simulate-attack", methods=["POST"])
@login_required
def simulate_attack():

    print("Simulated attack running")

    alert = "Ransomware behavior detected"

    log_threat(alert)

    socketio.emit(
        "live_update",
        {
            "risk_score": 85,
            "processes": len(psutil.pids()),
            "connections":
            len(psutil.net_connections()),
            "alert": alert,
            "timestamp":
            datetime.now()
            .strftime("%H:%M:%S")
        }
    )

    return jsonify({
        "message":
        "Attack simulation executed"
    })




@app.route("/backup-system", methods=["POST"])
@login_required
def backup_system():

    import shutil

    source = "monitored_folder"

    backup = "backup_folder"

    try:

        print("Backup started")

        # CREATE SOURCE FOLDER IF NOT EXISTS

        if not os.path.exists(source):

            os.makedirs(source)

            print("Source folder created")

        # CREATE BACKUP FOLDER

        if not os.path.exists(backup):

            os.makedirs(backup)

            print("Backup folder created")

        files_copied = 0

        copied_files = []

        # COPY FILES

        for file in os.listdir(source):

            src = os.path.join(source, file)

            dst = os.path.join(backup, file)

            if os.path.isfile(src):

                shutil.copy2(src, dst)

                files_copied += 1

                copied_files.append(file)

                print("Copied:", file)

        # MESSAGE

        message = f"{files_copied} files backed up successfully"

        print(message)

        # LOG THREAT / EVENT

        log_threat(message)

        # SEND EMAIL TO USER

        send_security_alert(

            mail,

            current_user.email,

            "BACKUP",

            message,

            "MEDIUM"

        )

        # SOCKET UPDATE

        socketio.emit(

            "live_update",

            {

                "alert": message,

                "timestamp":

                datetime.now()

                .strftime("%H:%M:%S")

            }

        )

        return jsonify({

            "status": "success",

            "files_copied": files_copied,

            "message": message

        })

    except Exception as e:

        print("Backup error:", e)

        return jsonify({

            "status": "error",

            "message": "Backup failed"

        })

# ================= MAIN =================

if __name__ == "__main__":

    with app.app_context():

        db.create_all()

    start_background_services()

    print("Real-time monitoring started")

    socketio.run(
        app,
        host="0.0.0.0",
        port=5000,
        debug=True,
        allow_unsafe_werkzeug=True
    )