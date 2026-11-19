import base64
import logging
import os
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from dotenv import load_dotenv

# Load .env before reading the keys.
load_dotenv()

log = logging.getLogger("crypto")
IN_DOCKER = os.path.exists("/app")

# Development-only keys.
DEFAULT_PII_KEY = "uV9M0_y2T-Z-X5c70H811vG53_64y5K5-64y5K5-64y="
DEFAULT_IMAGE_KEY_HEX = (
    "00112233445566778899aabbccddeeff"
    "00112233445566778899aabbccddeeff"
)


def _require_env_or_dev_default(name: str, default: str) -> str:
    value = os.getenv(name)

    if value:
        return value

    if IN_DOCKER:
        raise RuntimeError(
            f"{name} is required in Docker/production"
        )

    log.warning(
        "%s is not set: using an UNSAFE development key",
        name,
    )
    return default


# --- 1. PII and tokens: Fernet ---

PII_KEY = _require_env_or_dev_default(
    "PII_ENCRYPTION_KEY",
    DEFAULT_PII_KEY,
)

try:
    fernet = Fernet(PII_KEY.encode("utf-8"))
except (ValueError, TypeError) as exc:
    raise RuntimeError(
        "PII_ENCRYPTION_KEY is not a valid Fernet key"
    ) from exc


def encrypt_pii(text: Optional[str]) -> Optional[str]:
    if not text:
        return None

    return fernet.encrypt(text.encode("utf-8")).decode("utf-8")


def decrypt_pii(ciphertext: Optional[str]) -> Optional[str]:
    """Return None if decryption fails."""
    if not ciphertext:
        return None

    try:
        return fernet.decrypt(
            ciphertext.encode("utf-8")
        ).decode("utf-8")
    except (InvalidToken, ValueError, UnicodeDecodeError):
        log.error(
            "Could not decrypt a PII field "
            "(wrong key or corrupted data)"
        )
        return None


# --- 1b. OAuth tokens: same mechanism ---

def encrypt_secret(text: Optional[str]) -> Optional[str]:
    return encrypt_pii(text)


def decrypt_secret(ciphertext: Optional[str]) -> Optional[str]:
    return decrypt_pii(ciphertext)


# --- 2. Images: AES-256-GCM ---

def _load_image_key() -> bytes:
    """Load a 32-byte AES key from the environment
    or use the default key in development only.
    """
    image_env = os.getenv("IMAGE_ENCRYPTION_KEY")

    if image_env:
        try:
            # The environment variable must contain the key in Base64.
            key = base64.b64decode(image_env, validate=True)
        except (ValueError, base64.binascii.Error) as exc:
            raise RuntimeError(
                "IMAGE_ENCRYPTION_KEY must be Base64-encoded"
            ) from exc
    else:
        if IN_DOCKER:
            raise RuntimeError(
                "IMAGE_ENCRYPTION_KEY is required in Docker/production"
            )

        log.warning(
            "IMAGE_ENCRYPTION_KEY is not set: "
            "using an UNSAFE development key"
        )
        key = bytes.fromhex(DEFAULT_IMAGE_KEY_HEX)

    if len(key) != 32:
        raise RuntimeError(
            "IMAGE_ENCRYPTION_KEY must represent exactly "
            "32 bytes for AES-256-GCM"
        )

    return key


aesgcm = AESGCM(_load_image_key())


def encrypt_image(
    image_bytes: bytes,
    aad: Optional[bytes] = None,
) -> bytes:
    """Encrypt an image with AES-256-GCM.

    Stored format:
    random 12-byte nonce || ciphertext || 16-byte tag.
    """
    if not image_bytes:
        return b""

    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, image_bytes, aad)

    return nonce + ciphertext


def decrypt_image(
    encrypted_data: bytes,
    aad: Optional[bytes] = None,
) -> bytes:
    """Decrypt an image and verify its authenticity."""
    if not encrypted_data or len(encrypted_data) < 12 + 16:
        raise ValueError(
            "Encrypted image is truncated or empty"
        )

    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]

    return aesgcm.decrypt(nonce, ciphertext, aad)
