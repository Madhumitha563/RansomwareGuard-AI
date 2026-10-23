def log_threat(alert_message):

    try:

        from models import Log
        from datetime import datetime

        record = Log(

            message=alert_message,

            level="CRITICAL",

            timestamp=datetime.now()

        )

        db.session.add(record)

        db.session.commit()

        print("Threat logged:", alert_message)

    except Exception as e:

        print("Log error:", e)

        db.session.rollback()