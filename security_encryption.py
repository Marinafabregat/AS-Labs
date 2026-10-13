import os
import base64
from typing import Optional
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


# --- 2. ITEM IMAGE ENCRYPTION AT REST (AES-256-GCM) ---
DEFAULT_IMAGE_KEY_HEX = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
ENV_IMAGE_KEY = os.getenv("IMAGE_ENCRYPTION_KEY")
IMAGE_KEY = bytes.fromhex(ENV_IMAGE_KEY) if ENV_IMAGE_KEY else bytes.fromhex(DEFAULT_IMAGE_KEY_HEX)

aesgcm = AESGCM(IMAGE_KEY)

def encrypt_image(image_bytes: bytes) -> bytes:
    """Encripta bytes de imagen con AES-256-GCM.
    Genera un nonce único de 12 bytes y lo concatena al inicio del contenido cifrado.
    """
    if not image_bytes:
        return b""
    
    nonce = os.urandom(12)  # Nonce de 96 bits recomendado para GCM
    ciphertext = aesgcm.encrypt(nonce, image_bytes, associated_data=None)
    
    return nonce + ciphertext

def decrypt_image(encrypted_data: bytes) -> bytes:
    """Extrae el nonce de los primeros 12 bytes y desencripta el resto del contenido."""
    if not encrypted_data or len(encrypted_data) < 12:
        return b""
    
    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]
    
    return aesgcm.decrypt(nonce, ciphertext, associated_data=None)