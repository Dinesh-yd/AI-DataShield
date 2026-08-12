import smtplib
from email.message import EmailMessage

from app.core.config import settings


def send_email_notification(to_email: str, subject: str, body: str) -> bool:
    if not settings.smtp_enabled:
        return False

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = settings.smtp_sender
    msg["To"] = to_email
    msg.set_content(body)

    try:
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=10) as server:
            if settings.smtp_username:
                server.starttls()
                server.login(settings.smtp_username, settings.smtp_password)
            server.send_message(msg)
        return True
    except Exception:
        return False
