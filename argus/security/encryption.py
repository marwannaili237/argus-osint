"""Fernet encryption for evidence storage."""
import logging
import base64
from cryptography.fernet import Fernet
from argus.config import settings

logger = logging.getLogger(__name__)
_fernet: Fernet | None = None


def get_fernet() -> Fernet:
    """Get or create Fernet instance from config."""
    global _fernet
    if _fernet is None:
        key = settings.ENCRYPTION_KEY
        if not key:
            key = Fernet.generate_key().decode()
        try:
            if not key.startswith("gAAAAA"):
                key = base64.urlsafe_b64encode(key.encode()[:32].ljust(32, b"0")).decode()
            _fernet = Fernet(key.encode() if isinstance(key, str) else key)
        except Exception:
            _fernet = Fernet(Fernet.generate_key())
            logger.warning("Generated new encryption key.")
    return _fernet


def encrypt_data(plaintext: str) -> str:
    """Encrypt data and return token string."""
    try:
        return get_fernet().encrypt(plaintext.encode()).decode()
    except Exception as e:
        logger.error(f"Encryption failed: {e}")
        return ""


def decrypt_data(token: str) -> str:
    """Decrypt data from token string."""
    try:
        return get_fernet().decrypt(token.encode()).decode()
    except Exception as e:
        logger.error(f"Decryption failed: {e}")
        return ""
