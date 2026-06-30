"""TOTP two-factor authentication."""
import pyotp
import logging

logger = logging.getLogger(__name__)


def generate_totp_secret() -> str:
    """Generate a new TOTP secret."""
    return pyotp.random_base32()


def verify_totp(secret: str, code: str, valid_window: int = 1) -> bool:
    """Verify a TOTP code."""
    try:
        totp = pyotp.TOTP(secret)
        return totp.verify(code, valid_window=valid_window)
    except Exception as e:
        logger.error(f"TOTP verify failed: {e}")
        return False


def get_totp_provisioning_uri(secret: str, email: str, issuer: str = "Argus OSINT") -> str:
    """Get the otpauth:// URI for QR code generation."""
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=email, issuer_name=issuer)
