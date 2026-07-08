import sys
import os
import time
import random
import threading
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.dashboard import create_app
from app.models import db, EmailRecord, URLRecord, AttachmentRecord, QuarantineRecord, AlertRecord

app = create_app()

SAMPLE_EMAILS = [
    {
        "gmail_id": "demo001",
        "sender": "security-alert@paypa1.xyz",
        "subject": "URGENT! Your PayPal account has been suspended",
        "body_snippet": "Click here immediately to verify your account credentials or it will be deleted...",
        "risk_score": 95.0,
        "is_phishing": True,
        "is_quarantined": True,
    },
    {
        "gmail_id": "demo002",
        "sender": "noreply@bank-secure.top",
        "subject": "Action Required: Verify your bank account NOW",
        "body_snippet": "Your account will expire in 24 hours. Enter your SSN and password to continue...",
        "risk_score": 88.5,
        "is_phishing": True,
        "is_quarantined": True,
    },
    {
        "gmail_id": "demo003",
        "sender": "winner@lottery-claim.tk",
        "subject": "Congratulations! You won $1,000,000 - Claim Now!!!",
        "body_snippet": "You are the lucky winner! Wire transfer details required. Act now limited time offer...",
        "risk_score": 92.0,
        "is_phishing": True,
        "is_quarantined": True,
    },
    {
        "gmail_id": "demo004",
        "sender": "hr@company.com",
        "subject": "Team meeting scheduled for Monday",
        "body_snippet": "Hi team, please join the meeting at 10am on Monday. Agenda attached.",
        "risk_score": 5.0,
        "is_phishing": False,
        "is_quarantined": False,
    },
    {
        "gmail_id": "demo005",
        "sender": "admin@crypto-free.ml",
        "subject": "Free Bitcoin! Claim your 0.5 BTC reward today",
        "body_snippet": "Login with your credentials to claim free bitcoin. Limited offer expires soon...",
        "risk_score": 85.0,
        "is_phishing": True,
        "is_quarantined": True,
    },
    {
        "gmail_id": "demo006",
        "sender": "newsletter@amazon.com",
        "subject": "Your Amazon order has been shipped",
        "body_snippet": "Your order #123-456 has been shipped and will arrive by Friday.",
        "risk_score": 8.0,
        "is_phishing": False,
        "is_quarantined": False,
    },
    {
        "gmail_id": "demo007",
        "sender": "support@apple-id.online",
        "subject": "Your Apple ID has been compromised - Immediate action required",
        "body_snippet": "Suspicious login detected. Verify your Apple ID credentials immediately...",
        "risk_score": 78.0,
        "is_phishing": True,
        "is_quarantined": True,
    },
    {
        "gmail_id": "demo008",
        "sender": "boss@office365.com",
        "subject": "Quarterly report attached",
        "body_snippet": "Please find the quarterly report attached for your review.",
        "risk_score": 12.0,
        "is_phishing": False,
        "is_quarantined": False,
    },
]

SAMPLE_URLS = [
    ("paypa1.xyz", True, 45, 70),
    ("bank-secure.top", True, 38, 65),
    ("lottery-claim.tk", True, 52, 72),
    ("crypto-free.ml", True, 41, 68),
    ("apple-id.online", True, 33, 60),
    ("amazon.com", False, 0, 80),
    ("office365.com", False, 0, 75),
]

SAMPLE_ATTACHMENTS = [
    ("invoice_urgent.exe", "a3f1c2d4e5b6789012345678901234567890abcdef1234567890abcdef123456", True, 40, 65),
    ("claim_form.pdf.bat", "b4e2d3c5f6a7890123456789012345678901bcdef2345678901bcdef234567", True, 35, 60),
    ("report_Q4.pdf", "c5f3e4d6a7b8901234567890123456789012cdef3456789012cdef3456789", False, 0, 70),
]


def seed_demo_data():
    with app.app_context():
        if EmailRecord.query.count() > 0:
            print("[DEMO] Data already seeded.")
            return

        print("[DEMO] Seeding demo data...")
        base_time = datetime.utcnow() - timedelta(hours=6)

        for i, email_data in enumerate(SAMPLE_EMAILS):
            received = base_time + timedelta(minutes=i * 45)
            record = EmailRecord(
                gmail_id=email_data["gmail_id"],
                sender=email_data["sender"],
                subject=email_data["subject"],
                body_snippet=email_data["body_snippet"],
                risk_score=email_data["risk_score"],
                is_phishing=email_data["is_phishing"],
                is_quarantined=email_data["is_quarantined"],
                received_at=received,
                scanned_at=received + timedelta(seconds=5),
            )
            db.session.add(record)
            db.session.flush()

            # Add URLs
            for domain, is_mal, positives, total in SAMPLE_URLS[:3]:
                db.session.add(URLRecord(
                    email_id=record.id,
                    url=f"http://{domain}/verify?id={record.id}",
                    domain=domain,
                    is_malicious=is_mal and email_data["is_phishing"],
                    vt_positives=positives if email_data["is_phishing"] else 0,
                    vt_total=total,
                    scanned_at=received + timedelta(seconds=3),
                ))

            # Add attachments for phishing emails
            if email_data["is_phishing"] and i % 2 == 0:
                fname, fhash, is_mal, pos, tot = SAMPLE_ATTACHMENTS[i % len(SAMPLE_ATTACHMENTS)]
                db.session.add(AttachmentRecord(
                    email_id=record.id,
                    filename=fname,
                    sha256_hash=fhash,
                    is_malicious=is_mal,
                    vt_positives=pos,
                    vt_total=tot,
                    scanned_at=received + timedelta(seconds=4),
                ))

            # Quarantine record
            if email_data["is_quarantined"]:
                db.session.add(QuarantineRecord(
                    email_id=record.id,
                    reason=f"Risk score {email_data['risk_score']} exceeds threshold 70",
                    quarantined_at=received + timedelta(seconds=6),
                ))

            # Alert record
            if email_data["is_phishing"]:
                db.session.add(AlertRecord(
                    email_id=record.id,
                    alert_type="PHISHING_DETECTED",
                    message=f"Risk Score: {email_data['risk_score']} | Sender: {email_data['sender']} | Malicious URL + Suspicious Keywords detected",
                    sent_at=received + timedelta(seconds=7),
                    acknowledged=False,
                ))

        db.session.commit()
        print("[DEMO] Demo data seeded successfully!")
        print(f"[DEMO] {EmailRecord.query.count()} emails loaded")
        print(f"[DEMO] {AlertRecord.query.count()} alerts generated")
        print(f"[DEMO] {QuarantineRecord.query.count()} quarantine records")


def simulate_live_scan():
    """Simulate live email scanning every 20 seconds"""
    live_emails = [
        ("phish@evil-bank.xyz", "WARNING: Your account will be closed!", 91.0, True),
        ("deals@newsletter.com", "Weekend sale - 50% off everything", 6.0, False),
        ("admin@secure-login.top", "Reset your password immediately", 82.0, True),
        ("team@slack.com", "New message from your team", 4.0, False),
        ("winner@prize-claim.tk", "You have been selected! Claim now", 96.0, True),
    ]
    idx = 0
    with app.app_context():
        while True:
            time.sleep(20)
            sender, subject, score, is_phish = live_emails[idx % len(live_emails)]
            idx += 1
            gmail_id = f"live_{int(time.time())}"

            record = EmailRecord(
                gmail_id=gmail_id,
                sender=sender,
                subject=subject,
                body_snippet=f"Auto-scanned at {datetime.utcnow().strftime('%H:%M:%S')}",
                risk_score=score,
                is_phishing=is_phish,
                is_quarantined=is_phish,
                received_at=datetime.utcnow(),
                scanned_at=datetime.utcnow(),
            )
            db.session.add(record)
            db.session.flush()

            if is_phish:
                db.session.add(QuarantineRecord(
                    email_id=record.id,
                    reason=f"Risk score {score} exceeds threshold 70",
                    quarantined_at=datetime.utcnow(),
                ))
                db.session.add(AlertRecord(
                    email_id=record.id,
                    alert_type="PHISHING_DETECTED",
                    message=f"Risk Score: {score} | Sender: {sender} | Live scan detected phishing",
                    sent_at=datetime.utcnow(),
                ))

            db.session.commit()
            print(f"[LIVE SCAN] {sender} | Score: {score} | Phishing: {is_phish}")


if __name__ == "__main__":
    seed_demo_data()

    # Start live simulation in background
    live_thread = threading.Thread(target=simulate_live_scan, daemon=True)
    live_thread.start()

    print("\n" + "="*55)
    print("  AI Phishing Detection System - DEMO MODE")
    print("="*55)
    print("  Dashboard: http://localhost:5000")
    print("  Live scan: Every 20 seconds auto update")
    print("  Press Ctrl+C to stop")
    print("="*55 + "\n")

    app.run(host="0.0.0.0", port=5000, debug=False)
