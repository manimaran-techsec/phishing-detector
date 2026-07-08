import time
from urllib.parse import urlparse
from app.config import config
from app.models import db, EmailRecord, URLRecord, AttachmentRecord
from app.modules.gmail_monitor import authenticate_gmail, fetch_unread_emails, mark_as_read
from app.modules.virustotal_scanner import scan_url, scan_file_hash
from app.modules.ai_detector import detect_phishing
from app.modules.quarantine import quarantine_email
from app.modules.alert_system import send_alert
from app.modules.logger import get_logger

logger = get_logger("scanner")


def process_email(service, email_data: dict):
    # Skip if already processed
    existing = EmailRecord.query.filter_by(gmail_id=email_data["id"]).first()
    if existing:
        return

    logger.info(f"Processing email: {email_data['subject']} from {email_data['sender']}")

    # Scan URLs
    url_results = []
    url_records = []
    for url in email_data.get("urls", [])[:10]:  # Limit to 10 URLs per email
        result = scan_url(url)
        url_results.append(result)
        url_records.append(URLRecord(
            url=url,
            domain=urlparse(url).netloc,
            is_malicious=result["is_malicious"],
            vt_positives=result["malicious"],
            vt_total=result["total"]
        ))

    # Scan attachments
    attachment_results = []
    attachment_records = []
    for att in email_data.get("attachments", []):
        result = scan_file_hash(att["sha256"])
        attachment_results.append(result)
        attachment_records.append(AttachmentRecord(
            filename=att["filename"],
            sha256_hash=att["sha256"],
            is_malicious=result["is_malicious"],
            vt_positives=result["malicious"],
            vt_total=result["total"]
        ))

    # AI Detection
    detection = detect_phishing(email_data, url_results, attachment_results)
    risk_score = detection["risk_score"]
    is_phishing = detection["is_phishing"]

    # Save email record
    email_record = EmailRecord(
        gmail_id=email_data["id"],
        sender=email_data["sender"],
        subject=email_data["subject"],
        body_snippet=email_data["body"][:500],
        risk_score=risk_score,
        is_phishing=is_phishing
    )
    db.session.add(email_record)
    db.session.flush()

    # Link URL and attachment records
    for r in url_records:
        r.email_id = email_record.id
        db.session.add(r)
    for r in attachment_records:
        r.email_id = email_record.id
        db.session.add(r)

    db.session.commit()

    # Build indicators list
    indicators = []
    if any(r["is_malicious"] for r in url_results):
        indicators.append("Malicious URL detected")
    if any(r["is_malicious"] for r in attachment_results):
        indicators.append("Malicious attachment detected")
    if risk_score >= config.PHISHING_THRESHOLD:
        indicators.append(f"High risk score: {risk_score}/100")

    # Quarantine if above threshold
    if risk_score >= config.PHISHING_THRESHOLD:
        reason = f"Risk score {risk_score} exceeds threshold {config.PHISHING_THRESHOLD}"
        quarantine_email(service, email_record, reason)
        send_alert(email_record, indicators, risk_score)

    mark_as_read(service, email_data["id"])
    logger.info(f"Email {email_data['id']} processed. Score={risk_score}")


def run_monitor(app, interval: int = 60):
    """Main monitoring loop - runs inside Flask app context."""
    service = authenticate_gmail()
    logger.info(f"Monitoring started. Checking every {interval}s.")

    with app.app_context():
        while True:
            try:
                emails = fetch_unread_emails(service, max_results=20)
                for email_data in emails:
                    process_email(service, email_data)
            except Exception as e:
                logger.error(f"Monitor loop error: {e}")

            time.sleep(interval)
