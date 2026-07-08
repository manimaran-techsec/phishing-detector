import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from app.config import config
from app.models import db, AlertRecord, EmailRecord
from app.modules.logger import get_logger

logger = get_logger("alert_system")


def send_alert(email_record: EmailRecord, indicators: list, risk_score: float):
    subject = f"[PHISHING ALERT] {email_record.subject}"
    body = _build_alert_body(email_record, indicators, risk_score)

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = config.ADMIN_EMAIL
        msg["To"] = config.ADMIN_EMAIL
        msg.attach(MIMEText(body, "html"))

        with smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT) as server:
            server.ehlo()
            server.starttls()
            server.login(config.ADMIN_EMAIL, config.ALERT_EMAIL_PASSWORD)
            server.sendmail(config.ADMIN_EMAIL, config.ADMIN_EMAIL, msg.as_string())

        # Save alert to DB
        db.session.add(AlertRecord(
            email_id=email_record.id,
            alert_type="PHISHING_DETECTED",
            message=f"Risk Score: {risk_score} | Indicators: {', '.join(indicators)}"
        ))
        db.session.commit()
        logger.info(f"Alert sent for email {email_record.gmail_id}, score={risk_score}")

    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to send alert: {e}")


def _build_alert_body(email_record: EmailRecord, indicators: list, risk_score: float) -> str:
    indicator_list = "".join(f"<li>{i}</li>" for i in indicators)
    color = "#e74c3c" if risk_score >= 80 else "#e67e22"

    return f"""
    <html><body>
    <h2 style="color:{color}">⚠ Phishing Email Detected</h2>
    <table border="1" cellpadding="8" style="border-collapse:collapse;">
        <tr><td><b>Sender</b></td><td>{email_record.sender}</td></tr>
        <tr><td><b>Subject</b></td><td>{email_record.subject}</td></tr>
        <tr><td><b>Risk Score</b></td><td style="color:{color}"><b>{risk_score}/100</b></td></tr>
        <tr><td><b>Quarantined</b></td><td>{"Yes" if email_record.is_quarantined else "No"}</td></tr>
        <tr><td><b>Time</b></td><td>{email_record.received_at}</td></tr>
    </table>
    <h3>Detected Indicators:</h3>
    <ul>{indicator_list}</ul>
    <p>Login to the dashboard to review this email.</p>
    </body></html>
    """
