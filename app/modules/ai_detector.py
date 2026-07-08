import os
import re
import pickle
import numpy as np
from urllib.parse import urlparse
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from app.modules.logger import get_logger

logger = get_logger("ai_detector")

MODEL_PATH = "models/phishing_model.pkl"
SCALER_PATH = "models/scaler.pkl"

PHISHING_KEYWORDS = [
    "verify your account", "update your information", "suspended", "urgent",
    "click here", "confirm your password", "bank account", "won", "prize",
    "free", "limited time", "act now", "login", "credentials", "ssn",
    "social security", "wire transfer", "paypal", "bitcoin", "crypto",
    "congratulations", "winner", "claim", "expire", "warning", "security alert"
]

SUSPICIOUS_TLDS = [".xyz", ".top", ".club", ".online", ".site", ".tk", ".ml", ".ga"]
SUSPICIOUS_SENDERS = ["noreply@", "no-reply@", "support@", "admin@", "security@"]


def extract_features(email_data: dict, url_results: list, attachment_results: list) -> np.ndarray:
    sender = email_data.get("sender", "").lower()
    subject = email_data.get("subject", "").lower()
    body = email_data.get("body", "").lower()
    urls = email_data.get("urls", [])
    combined_text = subject + " " + body

    # Feature 1: Phishing keyword count
    keyword_count = sum(1 for kw in PHISHING_KEYWORDS if kw in combined_text)

    # Feature 2: Suspicious sender
    suspicious_sender = int(any(s in sender for s in SUSPICIOUS_SENDERS))

    # Feature 3: URL count
    url_count = len(urls)

    # Feature 4: Malicious URLs
    malicious_url_count = sum(1 for r in url_results if r.get("is_malicious"))

    # Feature 5: Suspicious TLD in URLs
    suspicious_tld_count = sum(
        1 for url in urls
        if any(urlparse(url).netloc.endswith(tld) for tld in SUSPICIOUS_TLDS)
    )

    # Feature 6: Malicious attachments
    malicious_attachment_count = sum(1 for a in attachment_results if a.get("is_malicious"))

    # Feature 7: HTML content (phishing often uses HTML)
    has_html = int("<html" in body or "<a href" in body)

    # Feature 8: Urgency words
    urgency_words = ["urgent", "immediately", "action required", "expire", "24 hours"]
    urgency_count = sum(1 for w in urgency_words if w in combined_text)

    # Feature 9: IP-based URLs
    ip_url_count = sum(
        1 for url in urls
        if re.match(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", url)
    )

    # Feature 10: Excessive exclamation/caps
    exclamation_count = combined_text.count("!")
    caps_ratio = sum(1 for c in subject if c.isupper()) / max(len(subject), 1)

    features = np.array([[
        keyword_count, suspicious_sender, url_count, malicious_url_count,
        suspicious_tld_count, malicious_attachment_count, has_html,
        urgency_count, ip_url_count, exclamation_count, caps_ratio
    ]])

    return features


def calculate_risk_score(features: np.ndarray) -> float:
    """Rule-based risk score from 0-100 when no trained model exists."""
    f = features[0]
    score = 0.0

    score += min(f[0] * 8, 30)   # keywords (max 30)
    score += f[1] * 10             # suspicious sender
    score += min(f[2] * 2, 10)    # url count (max 10)
    score += f[3] * 15             # malicious URLs
    score += f[4] * 8              # suspicious TLD
    score += f[5] * 20             # malicious attachments
    score += f[6] * 5              # HTML content
    score += f[7] * 5              # urgency words
    score += f[8] * 10             # IP-based URLs
    score += min(f[9], 5)          # exclamation marks
    score += f[10] * 10            # caps ratio

    return min(round(score, 2), 100.0)


def train_model(X: np.ndarray, y: np.ndarray):
    os.makedirs("models", exist_ok=True)
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_scaled, y)

    with open(MODEL_PATH, "wb") as f:
        pickle.dump(model, f)
    with open(SCALER_PATH, "wb") as f:
        pickle.dump(scaler, f)

    logger.info("ML model trained and saved.")
    return model, scaler


def load_model():
    if os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH):
        with open(MODEL_PATH, "rb") as f:
            model = pickle.load(f)
        with open(SCALER_PATH, "rb") as f:
            scaler = pickle.load(f)
        return model, scaler
    return None, None


def detect_phishing(email_data: dict, url_results: list, attachment_results: list) -> dict:
    features = extract_features(email_data, url_results, attachment_results)
    model, scaler = load_model()

    if model and scaler:
        X_scaled = scaler.transform(features)
        proba = model.predict_proba(X_scaled)[0]
        risk_score = round(proba[1] * 100, 2)
        is_phishing = model.predict(X_scaled)[0] == 1
    else:
        risk_score = calculate_risk_score(features)
        is_phishing = risk_score >= 70

    logger.info(f"Phishing detection: score={risk_score}, is_phishing={is_phishing}")
    return {
        "risk_score": risk_score,
        "is_phishing": is_phishing,
        "features": features[0].tolist()
    }
