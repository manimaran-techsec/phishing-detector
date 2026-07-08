import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # Gmail
    GMAIL_CREDENTIALS_FILE = os.getenv("GMAIL_CREDENTIALS_FILE", "credentials.json")
    GMAIL_TOKEN_FILE = os.getenv("GMAIL_TOKEN_FILE", "token.json")
    GMAIL_SCOPES = [
        "https://www.googleapis.com/auth/gmail.modify",
        "https://www.googleapis.com/auth/gmail.readonly"
    ]

    # VirusTotal
    VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
    VIRUSTOTAL_URL_SCAN = "https://www.virustotal.com/api/v3/urls"
    VIRUSTOTAL_FILE_SCAN = "https://www.virustotal.com/api/v3/files"

    # Admin
    ADMIN_EMAIL = os.getenv("ADMIN_EMAIL")
    ALERT_EMAIL_PASSWORD = os.getenv("ALERT_EMAIL_PASSWORD")
    SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
    SMTP_PORT = int(os.getenv("SMTP_PORT", 587))

    # Database
    DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///phishing_detector.db")

    # Phishing
    PHISHING_THRESHOLD = int(os.getenv("PHISHING_THRESHOLD", 70))

    # Flask
    SECRET_KEY = os.getenv("FLASK_SECRET_KEY", "changeme")
    DEBUG = os.getenv("FLASK_DEBUG", "False") == "True"

    # Logging
    LOG_FILE = "logs/phishing_detector.log"
    QUARANTINE_LOG = "logs/quarantine.log"

config = Config()
