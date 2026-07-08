from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class EmailRecord(db.Model):
    __tablename__ = "emails"

    id = db.Column(db.Integer, primary_key=True)
    gmail_id = db.Column(db.String(100), unique=True, nullable=False)
    sender = db.Column(db.String(255))
    subject = db.Column(db.String(500))
    body_snippet = db.Column(db.Text)
    received_at = db.Column(db.DateTime, default=datetime.utcnow)
    risk_score = db.Column(db.Float, default=0.0)
    is_phishing = db.Column(db.Boolean, default=False)
    is_quarantined = db.Column(db.Boolean, default=False)
    scanned_at = db.Column(db.DateTime, default=datetime.utcnow)

    urls = db.relationship("URLRecord", backref="email", lazy=True)
    attachments = db.relationship("AttachmentRecord", backref="email", lazy=True)
    alerts = db.relationship("AlertRecord", backref="email", lazy=True)


class URLRecord(db.Model):
    __tablename__ = "urls"

    id = db.Column(db.Integer, primary_key=True)
    email_id = db.Column(db.Integer, db.ForeignKey("emails.id"), nullable=False)
    url = db.Column(db.Text)
    domain = db.Column(db.String(255))
    is_malicious = db.Column(db.Boolean, default=False)
    vt_positives = db.Column(db.Integer, default=0)
    vt_total = db.Column(db.Integer, default=0)
    scanned_at = db.Column(db.DateTime, default=datetime.utcnow)


class AttachmentRecord(db.Model):
    __tablename__ = "attachments"

    id = db.Column(db.Integer, primary_key=True)
    email_id = db.Column(db.Integer, db.ForeignKey("emails.id"), nullable=False)
    filename = db.Column(db.String(255))
    sha256_hash = db.Column(db.String(64))
    is_malicious = db.Column(db.Boolean, default=False)
    vt_positives = db.Column(db.Integer, default=0)
    vt_total = db.Column(db.Integer, default=0)
    scanned_at = db.Column(db.DateTime, default=datetime.utcnow)


class QuarantineRecord(db.Model):
    __tablename__ = "quarantine"

    id = db.Column(db.Integer, primary_key=True)
    email_id = db.Column(db.Integer, db.ForeignKey("emails.id"), nullable=False)
    quarantined_at = db.Column(db.DateTime, default=datetime.utcnow)
    reason = db.Column(db.Text)
    released = db.Column(db.Boolean, default=False)
    released_at = db.Column(db.DateTime, nullable=True)
    released_by = db.Column(db.String(100), nullable=True)


class AlertRecord(db.Model):
    __tablename__ = "alerts"

    id = db.Column(db.Integer, primary_key=True)
    email_id = db.Column(db.Integer, db.ForeignKey("emails.id"), nullable=False)
    alert_type = db.Column(db.String(100))
    message = db.Column(db.Text)
    sent_at = db.Column(db.DateTime, default=datetime.utcnow)
    acknowledged = db.Column(db.Boolean, default=False)
