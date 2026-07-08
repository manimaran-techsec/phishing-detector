from flask import Flask, render_template, jsonify, request
from sqlalchemy import func
from app.config import config
from app.models import db, EmailRecord, URLRecord, QuarantineRecord, AlertRecord
from app.modules.quarantine import release_from_quarantine
from app.modules.logger import get_logger

logger = get_logger("dashboard")


def create_app():
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config["SECRET_KEY"] = config.SECRET_KEY
    app.config["SQLALCHEMY_DATABASE_URI"] = config.DATABASE_URL
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    db.init_app(app)

    with app.app_context():
        db.create_all()

    @app.route("/")
    def index():
        return render_template("dashboard.html")

    @app.route("/api/stats")
    def stats():
        total = EmailRecord.query.count()
        phishing = EmailRecord.query.filter_by(is_phishing=True).count()
        quarantined = EmailRecord.query.filter_by(is_quarantined=True).count()
        avg_score = db.session.query(func.avg(EmailRecord.risk_score)).scalar() or 0

        return jsonify({
            "total_scanned": total,
            "phishing_detected": phishing,
            "quarantined": quarantined,
            "avg_risk_score": round(avg_score, 2)
        })

    @app.route("/api/recent-alerts")
    def recent_alerts():
        alerts = AlertRecord.query.order_by(AlertRecord.sent_at.desc()).limit(10).all()
        return jsonify([{
            "id": a.id,
            "email_id": a.email_id,
            "alert_type": a.alert_type,
            "message": a.message,
            "sent_at": a.sent_at.isoformat(),
            "acknowledged": a.acknowledged
        } for a in alerts])

    @app.route("/api/top-malicious-domains")
    def top_malicious_domains():
        results = db.session.query(
            URLRecord.domain, func.count(URLRecord.id).label("count")
        ).filter_by(is_malicious=True)\
         .group_by(URLRecord.domain)\
         .order_by(func.count(URLRecord.id).desc())\
         .limit(10).all()

        return jsonify([{"domain": r.domain, "count": r.count} for r in results])

    @app.route("/api/risk-distribution")
    def risk_distribution():
        low = EmailRecord.query.filter(EmailRecord.risk_score < 30).count()
        medium = EmailRecord.query.filter(
            EmailRecord.risk_score >= 30, EmailRecord.risk_score < 70
        ).count()
        high = EmailRecord.query.filter(EmailRecord.risk_score >= 70).count()

        return jsonify({"low": low, "medium": medium, "high": high})

    @app.route("/api/quarantine")
    def quarantine_list():
        records = QuarantineRecord.query.filter_by(released=False)\
            .order_by(QuarantineRecord.quarantined_at.desc()).limit(20).all()
        return jsonify([{
            "id": r.id,
            "email_id": r.email_id,
            "reason": r.reason,
            "quarantined_at": r.quarantined_at.isoformat()
        } for r in records])

    @app.route("/api/quarantine/release/<int:record_id>", methods=["POST"])
    def release_email(record_id):
        q = QuarantineRecord.query.get_or_404(record_id)
        email_record = EmailRecord.query.get(q.email_id)
        released_by = request.json.get("released_by", "admin")
        release_from_quarantine(email_record, released_by)
        return jsonify({"status": "released"})

    @app.route("/api/alerts/acknowledge/<int:alert_id>", methods=["POST"])
    def acknowledge_alert(alert_id):
        alert = AlertRecord.query.get_or_404(alert_id)
        alert.acknowledged = True
        db.session.commit()
        return jsonify({"status": "acknowledged"})

    @app.route("/api/scan-email", methods=["POST"])
    def scan_email_api():
        from app.modules.ai_detector import detect_phishing, extract_features, calculate_risk_score
        from urllib.parse import urlparse
        import re

        data = request.json
        sender = data.get("sender", "")
        subject = data.get("subject", "")
        body = data.get("body", "")
        urls = data.get("urls", [])

        email_data = {"sender": sender, "subject": subject, "body": body, "urls": urls, "attachments": []}
        detection = detect_phishing(email_data, [], [])
        risk_score = detection["risk_score"]
        is_phishing = detection["is_phishing"]

        # Build indicators
        indicators = []
        combined = (subject + " " + body).lower()
        KEYWORDS = ["verify", "urgent", "suspended", "click here", "password", "bank", "won", "prize", "free", "expire", "credentials", "bitcoin", "crypto", "winner", "claim", "security alert"]
        found_kw = [kw for kw in KEYWORDS if kw in combined]
        if found_kw:
            indicators.append({"label": f"Phishing keywords: {', '.join(found_kw[:4])}", "type": "bad"})
        if any(tld in sender.lower() for tld in [".xyz", ".top", ".tk", ".ml", ".ga", ".online", ".club"]):
            indicators.append({"label": "Suspicious sender domain", "type": "bad"})
        if urls:
            suspicious_urls = [u for u in urls if any(t in u for t in [".xyz", ".top", ".tk", ".ml"])]
            if suspicious_urls:
                indicators.append({"label": f"Suspicious URL detected: {suspicious_urls[0]}", "type": "bad"})
        if re.search(r"https?://\d+\.\d+\.\d+\.\d+", " ".join(urls)):
            indicators.append({"label": "IP-based URL detected", "type": "bad"})
        if combined.count("!") > 2:
            indicators.append({"label": "Excessive exclamation marks", "type": "bad"})
        if not indicators:
            indicators.append({"label": "No suspicious patterns found", "type": "good"})

        # Save to DB
        import time
        record = EmailRecord(
            gmail_id=f"manual_{int(time.time())}",
            sender=sender,
            subject=subject,
            body_snippet=body[:500],
            risk_score=risk_score,
            is_phishing=is_phishing,
            is_quarantined=is_phishing
        )
        db.session.add(record)
        db.session.flush()

        if is_phishing:
            db.session.add(QuarantineRecord(
                email_id=record.id,
                reason=f"Risk score {risk_score} exceeds threshold 70"
            ))
            db.session.add(AlertRecord(
                email_id=record.id,
                alert_type="PHISHING_DETECTED",
                message=f"Risk Score: {risk_score} | Sender: {sender} | Manual scan"
            ))
        db.session.commit()

        return jsonify({"risk_score": risk_score, "is_phishing": is_phishing, "indicators": indicators})

    return app
