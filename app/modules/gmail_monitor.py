import os
import base64
import hashlib
from typing import List, Dict
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from app.config import config
from app.modules.logger import get_logger

logger = get_logger("gmail_monitor")


def authenticate_gmail():
    creds = None
    if os.path.exists(config.GMAIL_TOKEN_FILE):
        creds = Credentials.from_authorized_user_file(config.GMAIL_TOKEN_FILE, config.GMAIL_SCOPES)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                config.GMAIL_CREDENTIALS_FILE, config.GMAIL_SCOPES
            )
            creds = flow.run_local_server(port=0)
        with open(config.GMAIL_TOKEN_FILE, "w") as token:
            token.write(creds.to_json())

    logger.info("Gmail authenticated successfully.")
    return build("gmail", "v1", credentials=creds)


def fetch_unread_emails(service, max_results: int = 10) -> List[Dict]:
    results = service.users().messages().list(
        userId="me", labelIds=["INBOX"], q="is:unread", maxResults=max_results
    ).execute()

    messages = results.get("messages", [])
    emails = []

    for msg in messages:
        email_data = _parse_email(service, msg["id"])
        if email_data:
            emails.append(email_data)

    logger.info(f"Fetched {len(emails)} unread emails.")
    return emails


def _parse_email(service, msg_id: str) -> Dict:
    try:
        msg = service.users().messages().get(
            userId="me", id=msg_id, format="full"
        ).execute()

        headers = {h["name"]: h["value"] for h in msg["payload"].get("headers", [])}
        sender = headers.get("From", "Unknown")
        subject = headers.get("Subject", "No Subject")
        body, urls, attachments = _extract_parts(service, msg["payload"], msg_id)

        return {
            "id": msg_id,
            "sender": sender,
            "subject": subject,
            "body": body,
            "urls": urls,
            "attachments": attachments
        }
    except Exception as e:
        logger.error(f"Error parsing email {msg_id}: {e}")
        return None


def _extract_parts(service, payload, msg_id: str):
    import re
    body = ""
    urls = []
    attachments = []

    url_pattern = re.compile(r"https?://[^\s\"'>]+")

    def process_part(part):
        nonlocal body, urls, attachments

        mime = part.get("mimeType", "")
        data = part.get("body", {}).get("data")

        if mime in ("text/plain", "text/html") and data:
            decoded = base64.urlsafe_b64decode(data).decode("utf-8", errors="ignore")
            body += decoded
            urls.extend(url_pattern.findall(decoded))

        # Attachment
        filename = part.get("filename")
        attachment_id = part.get("body", {}).get("attachmentId")
        if filename and attachment_id:
            att_data = service.users().messages().attachments().get(
                userId="me", messageId=msg_id, id=attachment_id
            ).execute()
            file_bytes = base64.urlsafe_b64decode(att_data["data"])
            sha256 = hashlib.sha256(file_bytes).hexdigest()
            attachments.append({"filename": filename, "sha256": sha256})

        for sub_part in part.get("parts", []):
            process_part(sub_part)

    process_part(payload)
    return body, list(set(urls)), attachments


def mark_as_read(service, msg_id: str):
    service.users().messages().modify(
        userId="me", id=msg_id, body={"removeLabelIds": ["UNREAD"]}
    ).execute()


def move_to_quarantine(service, msg_id: str):
    # Move to SPAM label as quarantine
    service.users().messages().modify(
        userId="me", id=msg_id,
        body={"addLabelIds": ["SPAM"], "removeLabelIds": ["INBOX"]}
    ).execute()
    logger.info(f"Email {msg_id} moved to quarantine (SPAM).")
