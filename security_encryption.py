import base64
import logging
import os
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

log = logging.getLogger("crypto")
IN_DOCKER = os.path.exists("/app")

# Claves SOLO de desarrollo. En Docker son obligatorias desde variables de entorno.
DEFAULT_PII_KEY = "uV9M0_y2T-Z-X5c70H811vG53_64y5K5-64y5K5-64y="
DEFAULT_IMAGE_KEY_HEX = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"


def _require_env_or_dev_default(name: str, default: str) -> str:
    value = os.getenv(name)
    if value:
        return value
    if IN_DOCKER:
        raise RuntimeError(f"{name} es obligatoria en Docker/producción")
    log.warning("%s no definida: usando clave de desarrollo INSEGURA", name)
    return default


# --- 1. PII y tokens: Fernet (AES-128-CBC + HMAC) ---
fernet = Fernet(_require_env_or_dev_default("PII_ENCRYPTION_KEY", DEFAULT_PII_KEY).encode("utf-8"))


def encrypt_pii(text: Optional[str]) -> Optional[str]:
    if not text:
        return None
    return fernet.encrypt(text.encode("utf-8")).decode("utf-8")


def decrypt_pii(ciphertext: Optional[str]) -> Optional[str]:
    """Devuelve None si el descifrado falla. Nunca devuelve el texto cifrado."""
    if not ciphertext:
        return None
    try:
        return fernet.decrypt(ciphertext.encode("utf-8")).decode("utf-8")
    except (InvalidToken, ValueError):
        log.error("No se pudo descifrar un campo PII (clave incorrecta o dato corrupto)")
        return None


# --- 1b. Tokens OAuth: mismo mecanismo ---
def encrypt_secret(text: Optional[str]) -> Optional[str]:
    return encrypt_pii(text)


def decrypt_secret(ciphertext: Optional[str]) -> Optional[str]:
    return decrypt_pii(ciphertext)


# --- 2. Imágenes: AES-256-GCM ---
_image_env = os.getenv("IMAGE_ENCRYPTION_KEY")
if _image_env:
    IMAGE_KEY = base64.b64decode(_image_env)
else:
    if IN_DOCKER:
        raise RuntimeError("IMAGE_ENCRYPTION_KEY es obligatoria en Docker/producción")
    log.warning("IMAGE_ENCRYPTION_KEY no definida: usando clave de desarrollo INSEGURA")
    IMAGE_KEY = bytes.fromhex(DEFAULT_IMAGE_KEY_HEX)

aesgcm = AESGCM(IMAGE_KEY)


def encrypt_image(image_bytes: bytes) -> bytes:
    """Nonce de 12 bytes al inicio del resultado."""
    if not image_bytes:
        return b""
    nonce = os.urandom(12)
    return nonce + aesgcm.encrypt(nonce, image_bytes, associated_data=None)


def decrypt_image(encrypted_data: bytes) -> bytes:
    if not encrypted_data or len(encrypted_data) < 12:
        return b""
    nonce, ciphertext = encrypted_data[:12], encrypted_data[12:]
    return aesgcm.decrypt(nonce, ciphertext, associated_data=None)