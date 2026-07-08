# AI-Powered Phishing Email Detection System

An automated cybersecurity system that detects phishing emails, quarantines them, and alerts administrators using Gmail API, VirusTotal API, and Machine Learning.

---

## Project Structure

```
PhishingDetector/
├── app/
│   ├── __init__.py
│   ├── config.py           # All configuration
│   ├── models.py           # SQLAlchemy DB models
│   ├── dashboard.py        # Flask web dashboard
│   ├── templates/
│   │   └── dashboard.html  # Dashboard UI
│   ├── static/
│   └── modules/
│       ├── __init__.py
│       ├── logger.py           # Logging setup
│       ├── gmail_monitor.py    # Gmail API integration
│       ├── virustotal_scanner.py # VirusTotal API
│       ├── ai_detector.py      # ML phishing detection
│       ├── quarantine.py       # Quarantine management
│       ├── alert_system.py     # Email alerts
│       └── scanner.py          # Main orchestrator
├── logs/
│   ├── phishing_detector.log
│   └── quarantine.log
├── models/
│   └── (ML model saved here after training)
├── data/
├── tests/
├── main.py                 # Entry point
├── requirements.txt
├── .env                    # Environment variables
└── README.md
```

---

## Installation Guide

### Step 1: Clone & Setup Environment

```bash
cd C:\Users\ADMIN\PhishingDetector
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

### Step 2: Gmail API Setup

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project
3. Enable **Gmail API**
4. Go to **Credentials** → Create **OAuth 2.0 Client ID** (Desktop App)
5. Download the JSON file and rename it to `credentials.json`
6. Place `credentials.json` in `C:\Users\ADMIN\PhishingDetector\`

### Step 3: VirusTotal API Setup

1. Register at [VirusTotal](https://www.virustotal.com/)
2. Go to your profile → **API Key**
3. Copy the key and paste in `.env` file

### Step 4: Configure .env

Edit `.env` file:
```
VIRUSTOTAL_API_KEY=your_actual_key_here
ADMIN_EMAIL=your_gmail@gmail.com
ALERT_EMAIL_PASSWORD=your_gmail_app_password
PHISHING_THRESHOLD=70
FLASK_SECRET_KEY=any_random_secret_string
```

> For Gmail app password: Go to Google Account → Security → 2-Step Verification → App Passwords

### Step 5: Run the System

```bash
python main.py
```

First run will open a browser for Gmail OAuth authentication.

### Step 6: Access Dashboard

Open browser: **http://localhost:5000**

---

## System Architecture

```
Gmail Inbox
    │
    ▼
Email Monitor (Gmail API)
    │
    ├──► URL Extractor ──► VirusTotal URL Scan
    │
    ├──► Attachment Extractor ──► VirusTotal Hash Scan
    │
    ▼
AI Phishing Detector (Scikit-learn)
    │ Risk Score (0-100)
    │
    ├── Score >= Threshold ──► Quarantine + Admin Alert
    │
    └── All results ──► SQLite Database
                            │
                            ▼
                    Flask Dashboard (http://localhost:5000)
```

---

## Data Flow

1. Gmail API fetches unread emails every 60 seconds
2. URLs and attachment hashes extracted from each email
3. VirusTotal API scans URLs and file hashes
4. AI model analyzes 11 features to generate risk score (0-100)
5. If score >= threshold (default 70), email is quarantined
6. Admin receives HTML email alert with details
7. All data stored in SQLite database
8. Dashboard displays real-time stats and alerts

---

## Security Features

- API keys stored in `.env` (never in code)
- Gmail OAuth2 authentication
- Input validation on all API responses
- Exception handling throughout
- Rotating log files (max 5MB)
- Audit trail for quarantine actions

---

## Testing

```bash
# Test Gmail connection
python -c "from app.modules.gmail_monitor import authenticate_gmail; authenticate_gmail()"

# Test VirusTotal
python -c "from app.modules.virustotal_scanner import scan_url; print(scan_url('http://google.com'))"

# Test AI detector
python -c "
from app.modules.ai_detector import detect_phishing
email = {'sender': 'hack@evil.com', 'subject': 'Urgent! Verify your account now!!!', 'body': 'Click here to verify your bank credentials', 'urls': [], 'attachments': []}
print(detect_phishing(email, [], []))
"

# Start full system
python main.py
```

---

## Dashboard Features

| Feature | Description |
|---|---|
| Total Emails Scanned | Count of all processed emails |
| Phishing Detected | Emails flagged as phishing |
| Quarantined | Emails moved to quarantine |
| Avg Risk Score | Average risk across all emails |
| Recent Alerts | Last 10 admin alerts |
| Top Malicious Domains | Most frequent malicious domains |
| Risk Distribution | Low/Medium/High breakdown |
| Quarantine Queue | Active quarantined emails |

Dashboard auto-refreshes every 30 seconds.
