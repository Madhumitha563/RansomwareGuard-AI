import os
import shutil
import time

from datetime import datetime

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from flask_login import current_user

from models import db, QuarantineFile
from response.email_service import send_security_alert


QUARANTINE_FOLDER = "quarantine"

SUSPICIOUS_EXTENSIONS = [

    ".exe",
    ".bat",
    ".vbs",
    ".js",
    ".ps1"

]


class FileHandler(FileSystemEventHandler):

    def __init__(self, socketio, app, mail):

        self.socketio = socketio
        self.app = app
        self.mail = mail

    # ================= FILE CREATED =================

    def on_created(self, event):

        if event.is_directory:

            return

        file_path = event.src_path

        file_name = os.path.basename(file_path)

        print("New file detected:", file_name)

        ext = os.path.splitext(file_name)[1].lower()

        # NORMAL FILE

        self.socketio.emit(

            "file_update",

            {

                "time":

                datetime.now()

                .strftime("%H:%M:%S"),

                "name": file_name,

                "path": file_path,

                "action": "Created"

            }

        )

        # SUSPICIOUS FILE

        if ext in SUSPICIOUS_EXTENSIONS:

            self.quarantine_file(

                file_name,

                file_path

            )

    # ================= QUARANTINE =================

    def quarantine_file(self,
                        file_name,
                        file_path):

        try:

            with self.app.app_context():

                if not os.path.exists(
                        QUARANTINE_FOLDER):

                    os.makedirs(
                        QUARANTINE_FOLDER)

                destination = os.path.join(

                    QUARANTINE_FOLDER,

                    file_name

                )

                shutil.move(

                    file_path,

                    destination

                )

                print(
                    "File moved to quarantine:",
                    file_name
                )

                record = QuarantineFile(

                    filename=file_name,

                    original_path=file_path,

                    threat_type="Suspicious File",

                    risk_level="High",

                    quarantined_at=datetime.now()

                )

                db.session.add(record)

                db.session.commit()

                # SOCKET UPDATE

                self.socketio.emit(

                    "quarantine_update",

                    {

                        "file_name": file_name,

                        "file_path": file_path,

                        "timestamp":

                        datetime.now()

                        .strftime("%H:%M:%S")

                    }

                )

                # EMAIL ALERT

                send_security_alert(

                    self.mail,

                    current_user.email,

                    "QUARANTINE",

                    file_name,

                    "CRITICAL"

                )

        except Exception as e:

            print(

                "Quarantine error:",

                e

            )

            db.session.rollback()


# ================= START MONITOR =================

def start_file_monitor(
        socketio,
        db,
        app,
        mail):

    path = "monitored_folder"

    if not os.path.exists(path):

        os.makedirs(path)

    event_handler = FileHandler(

        socketio,
        app,
        mail

    )

    observer = Observer()

    observer.schedule(

        event_handler,

        path,

        recursive=True

    )

    observer.start()

    print(
        "File monitor started on:",
        path
    )

    try:

        while True:

            time.sleep(1)

    except KeyboardInterrupt:

        observer.stop()

    observer.join()