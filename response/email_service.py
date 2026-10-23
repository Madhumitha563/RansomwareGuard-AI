from flask_mail import Message
from datetime import datetime


def send_security_alert(
    mail,
    recipient_email,
    alert_type,
    details,
    risk_level="MEDIUM"
):

    try:

        time_now = datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        # ================= MESSAGE TEMPLATES =================

        if alert_type == "THREAT":

            subject = "🚨 Ransomware Threat Detected"

            body = f"""

🚨 RANSOMWARE ALERT

System:
RansomwareGuard AI

Threat Details:
{details}

Risk Level:
{risk_level}

Immediate Action:
System monitoring intensified

Time:
{time_now}

"""

        elif alert_type == "KILL_SWITCH":

            subject = "🛑 Kill Switch Activated"

            body = f"""

🛑 SYSTEM PROTECTION TRIGGERED

Kill switch has been activated.

All suspicious processes stopped.

Details:
{details}

Time:
{time_now}

"""

        elif alert_type == "BACKUP":

            subject = "💾 Backup Completed Successfully"

            body = f"""

💾 SYSTEM BACKUP REPORT

Backup Status:
Completed

Files:
{details}

System remains protected.

Time:
{time_now}

"""

        elif alert_type == "QUARANTINE":

            subject = "⚠️ File Quarantined"

            body = f"""

⚠️ SECURITY ALERT

A suspicious file has been isolated.

File:
{details}

Risk Level:
{risk_level}

System Status:
Protected

Time:
{time_now}

"""

        else:

            subject = "Security Notification"

            body = f"""

System Notification

Details:
{details}

Time:
{time_now}

"""

        # ================= SEND EMAIL =================

        msg = Message(

            subject=subject,

            recipients=[

               recipient_email,

               mail.app.config["MAIL_USERNAME"]

        ]

        )

        msg.body = body

        mail.send(msg)

        print(
            "Email sent to:",
            recipient_email
        )

    except Exception as e:

        print(
            "Email error:",
            e
        )