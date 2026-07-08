from datetime import datetime
from app.models import db, QuarantineRecord, EmailRecord
from app.modules.gmail_monitor import move_to_quarantine
from app.modules.logger import get_logger

logger = get_logger("quarantine")


def quarantine_email(service, email_record: EmailRecord, reason: str):
    try:
        # Move in Gmail
        move_to_quarantine(service, email_record.gmail_id)

        # Update DB
        email_record.is_quarantined = True
        db.session.add(QuarantineRecord(
            email_id=email_record.id,
            reason=reason,
            quarantined_at=datetime.utcnow()
        ))
        db.session.commit()

        _write_quarantine_log(email_record, reason)
        logger.info(f"Email {email_record.gmail_id} quarantined. Reason: {reason}")

    except Exception as e:
        db.session.rollback()
        logger.error(f"Quarantine failed for {email_record.gmail_id}: {e}")


def release_from_quarantine(email_record: EmailRecord, released_by: str):
    record = QuarantineRecord.query.filter_by(
        email_id=email_record.id, released=False
    ).first()

    if record:
        record.released = True
        record.released_at = datetime.utcnow()
        record.released_by = released_by
        email_record.is_quarantined = False
        db.session.commit()
        logger.info(f"Email {email_record.gmail_id} released by {released_by}.")


def _write_quarantine_log(email_record: EmailRecord, reason: str):
    with open("logs/quarantine.log", "a") as f:
        f.write(
            f"{datetime.utcnow()} | QUARANTINED | "
            f"id={email_record.gmail_id} | "
            f"sender={email_record.sender} | "
            f"subject={email_record.subject} | "
            f"score={email_record.risk_score} | "
            f"reason={reason}\n"
        )
