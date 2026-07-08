import logging
import os
from logging.handlers import RotatingFileHandler

os.makedirs("logs", exist_ok=True)

def get_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)

    if not logger.handlers:
        formatter = logging.Formatter(
            "%(asctime)s | %(levelname)s | %(name)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )

        # File handler (rotating - max 5MB, keep 3 backups)
        file_handler = RotatingFileHandler(
            "logs/phishing_detector.log",
            maxBytes=5 * 1024 * 1024,
            backupCount=3
        )
        file_handler.setFormatter(formatter)

        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)

        logger.addHandler(file_handler)
        logger.addHandler(console_handler)

    return logger
