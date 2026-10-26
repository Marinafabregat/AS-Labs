import os
import base64
from typing import Optional

from dotenv import load_dotenv

# Load .env BEFORE reading keys below (this module is imported before main.py calls load_dotenv)
load_dotenv()
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --- 1. PII STRING ENCRYPTION (Fernet / AES-128-CBC) ---
DEFAULT_PII_KEY = b"uV9M0_y2T-Z-X5c70H811vG53_64y5K5-64y5K5-64y="
ENV_PII_KEY = os.getenv("PII_ENCRYPTION_KEY")
PII_KEY = ENV_PII_KEY.encode("utf-8") if ENV_PII_KEY else DEFAULT_PII_KEY

fernet = Fernet(PII_KEY)

def encrypt_pii(text: Optional[str]) -> Optional[str]:
    if not text:
        return None
    return fernet.encrypt(text.encode("utf-8")).decode("utf-8")

def decrypt_pii(ciphertext: Optional[str]) -> Optional[str]:
    if not ciphertext:
        return None
    try:
        return fernet.decrypt(ciphertext.encode("utf-8")).decode("utf-8")
    except Exception:
        return ciphertext


# --- 1b. OAUTH / SECRET TOKEN ENCRYPTION (same Fernet key as PII) ---
def encrypt_secret(text: Optional[str]) -> Optional[str]:
    """Cifra un secreto (p.ej. un token OAuth) para almacenarlo en reposo."""
    if not text:
        return None
    return fernet.encrypt(text.encode("utf-8")).decode("utf-8")


def decrypt_secret(ciphertext: Optional[str]) -> Optional[str]:
    if not ciphertext:
        return None
    try:
        return fernet.decrypt(ciphertext.encode("utf-8")).decode("utf-8")
    except Exception:
        return ciphertext


# --- 2. ITEM IMAGE ENCRYPTION AT REST (AES-256-GCM) ---
# The key MUST come from the environment (base64 of exactly 32 random bytes).
# There is deliberately no hardcoded fallback: a key in the source code is no key at all.
#   python3 -c "import os,base64; print(base64.b64encode(os.urandom(32)).decode())"
def _load_image_key() -> bytes:
    raw = os.getenv("IMAGE_ENCRYPTION_KEY")
    if not raw:
        raise RuntimeError("IMAGE_ENCRYPTION_KEY is not set (base64-encoded 32-byte key required)")
    try:
        key = base64.b64decode(raw, validate=True)
    except Exception as exc:
        raise RuntimeError("IMAGE_ENCRYPTION_KEY is not valid base64") from exc
    if len(key) != 32:
        raise RuntimeError(f"IMAGE_ENCRYPTION_KEY must decode to 32 bytes (AES-256), got {len(key)}")
    return key

aesgcm = AESGCM(_load_image_key())

def encrypt_image(image_bytes: bytes, aad: Optional[bytes] = None) -> bytes:
    """Encrypt image bytes with AES-256-GCM.

    A fresh random 96-bit nonce is generated per call and prepended to the output:
    nonce (12 bytes) || ciphertext || GCM tag (16 bytes).
    `aad` (associated data) is authenticated but not encrypted; we bind it to the
    stored filename so a ciphertext cannot be swapped between files undetected.
    """
    if not image_bytes:
        return b""
    nonce = os.urandom(12)
    return nonce + aesgcm.encrypt(nonce, image_bytes, aad)

def decrypt_image(encrypted_data: bytes, aad: Optional[bytes] = None) -> bytes:
    """Split off the nonce and decrypt. Raises cryptography.exceptions.InvalidTag
    if the data was tampered with, the key is wrong, or the aad does not match."""
    if not encrypted_data or len(encrypted_data) < 12 + 16:
        raise ValueError("Encrypted image is truncated or empty")
    return aesgcm.decrypt(encrypted_data[:12], encrypted_data[12:], aad)
