import base64
import logging
import os
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from dotenv import load_dotenv

# Cargar .env antes de leer las claves.
load_dotenv()

log = logging.getLogger("crypto")
IN_DOCKER = os.path.exists("/app")

# Claves SOLO para desarrollo.
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
            f"{name} es obligatoria en Docker/producción"
        )

    log.warning(
        "%s no definida: usando clave de desarrollo INSEGURA",
        name,
    )
    return default


# --- 1. PII y tokens: Fernet ---

PII_KEY = _require_env_or_dev_default(
    "PII_ENCRYPTION_KEY",
    DEFAULT_PII_KEY,
)

try:
    fernet = Fernet(PII_KEY.encode("utf-8"))
except (ValueError, TypeError) as exc:
    raise RuntimeError(
        "PII_ENCRYPTION_KEY no es una clave Fernet válida"
    ) from exc


def encrypt_pii(text: Optional[str]) -> Optional[str]:
    if not text:
        return None

    return fernet.encrypt(text.encode("utf-8")).decode("utf-8")


def decrypt_pii(ciphertext: Optional[str]) -> Optional[str]:
    """Devuelve None si el descifrado falla."""
    if not ciphertext:
        return None

    try:
        return fernet.decrypt(
            ciphertext.encode("utf-8")
        ).decode("utf-8")
    except (InvalidToken, ValueError, UnicodeDecodeError):
        log.error(
            "No se pudo descifrar un campo PII "
            "(clave incorrecta o dato corrupto)"
        )
        return None


# --- 1b. Tokens OAuth: mismo mecanismo ---

def encrypt_secret(text: Optional[str]) -> Optional[str]:
    return encrypt_pii(text)


def decrypt_secret(ciphertext: Optional[str]) -> Optional[str]:
    return decrypt_pii(ciphertext)


# --- 2. Imágenes: AES-256-GCM ---

def _load_image_key() -> bytes:
    """Carga una clave AES de 32 bytes desde el entorno
    o utiliza la clave predeterminada únicamente en desarrollo.
    """
    image_env = os.getenv("IMAGE_ENCRYPTION_KEY")

    if image_env:
        try:
            # La variable de entorno debe contener la clave en Base64.
            key = base64.b64decode(image_env, validate=True)
        except (ValueError, base64.binascii.Error) as exc:
            raise RuntimeError(
                "IMAGE_ENCRYPTION_KEY debe estar codificada en Base64"
            ) from exc
    else:
        if IN_DOCKER:
            raise RuntimeError(
                "IMAGE_ENCRYPTION_KEY es obligatoria en Docker/producción"
            )

        log.warning(
            "IMAGE_ENCRYPTION_KEY no definida: "
            "usando clave de desarrollo INSEGURA"
        )
        key = bytes.fromhex(DEFAULT_IMAGE_KEY_HEX)

    if len(key) != 32:
        raise RuntimeError(
            "IMAGE_ENCRYPTION_KEY debe representar exactamente "
            "32 bytes para AES-256-GCM"
        )

    return key


aesgcm = AESGCM(_load_image_key())


def encrypt_image(
    image_bytes: bytes,
    aad: Optional[bytes] = None,
) -> bytes:
    """Cifra una imagen con AES-256-GCM.

    Formato almacenado:
    nonce aleatorio de 12 bytes || ciphertext || tag de 16 bytes.
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
    """Descifra una imagen y verifica su autenticidad."""
    if not encrypted_data or len(encrypted_data) < 12 + 16:
        raise ValueError(
            "Encrypted image is truncated or empty"
        )

    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]

    return aesgcm.decrypt(nonce, ciphertext, aad)
