import base64
import time
import requests
from typing import Dict
from app.config import config
from app.modules.logger import get_logger

logger = get_logger("virustotal")

HEADERS = {
    "x-apikey": config.VIRUSTOTAL_API_KEY,
    "Accept": "application/json"
}


def scan_url(url: str) -> Dict:
    try:
        # Submit URL
        encoded_url = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        response = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{encoded_url}",
            headers=HEADERS, timeout=15
        )

        if response.status_code == 404:
            # URL not in VT, submit for scan
            submit = requests.post(
                config.VIRUSTOTAL_URL_SCAN,
                headers=HEADERS,
                data={"url": url},
                timeout=15
            )
            submit.raise_for_status()
            time.sleep(15)  # Wait for scan
            response = requests.get(
                f"https://www.virustotal.com/api/v3/urls/{encoded_url}",
                headers=HEADERS, timeout=15
            )

        data = response.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        total = sum(stats.values()) if stats else 0

        result = {
            "url": url,
            "malicious": malicious,
            "total": total,
            "is_malicious": malicious > 0
        }
        logger.info(f"URL scan result: {url} -> malicious={malicious}/{total}")
        return result

    except Exception as e:
        logger.error(f"URL scan error for {url}: {e}")
        return {"url": url, "malicious": 0, "total": 0, "is_malicious": False}


def scan_file_hash(sha256: str) -> Dict:
    try:
        response = requests.get(
            f"https://www.virustotal.com/api/v3/files/{sha256}",
            headers=HEADERS, timeout=15
        )

        if response.status_code == 404:
            logger.info(f"Hash {sha256} not found in VirusTotal.")
            return {"sha256": sha256, "malicious": 0, "total": 0, "is_malicious": False}

        data = response.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        total = sum(stats.values()) if stats else 0

        result = {
            "sha256": sha256,
            "malicious": malicious,
            "total": total,
            "is_malicious": malicious > 0
        }
        logger.info(f"File hash scan: {sha256} -> malicious={malicious}/{total}")
        return result

    except Exception as e:
        logger.error(f"File hash scan error for {sha256}: {e}")
        return {"sha256": sha256, "malicious": 0, "total": 0, "is_malicious": False}
