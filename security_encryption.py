import os
from typing import Optional
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


#PII STRING ENCRYPTION (Fernet / AES-128-CBC)

PII_KEY = os.getenv("PII_ENCRYPTION_KEY", Fernet.generate_key())
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



#ITEM IMAGE ENCRYPTION AT REST (AES-256-GCM)

# AESGCM requires a 256-bit key (32 bytes)
IMAGE_KEY = os.getenv("IMAGE_ENCRYPTION_KEY", AESGCM.generate_key(bit_length=256))
aesgcm = AESGCM(IMAGE_KEY)

def encrypt_image(image_bytes: bytes) -> bytes:
    """Encrypts raw image bytes using AES-256-GCM.
    Generates a secure 12-byte nonce and prepends it to the ciphertext.
    """
    if not image_bytes:
        return b""
    
    nonce = os.urandom(12)  # 12-byte nonce recommended for GCM
    ciphertext = aesgcm.encrypt(nonce, image_bytes, associated_data=None)
    
    # Store nonce + ciphertext together so decryption knows the nonce
    return nonce + ciphertext

def decrypt_image(encrypted_data: bytes) -> bytes:
    """Decrypts AES-256-GCM encrypted image bytes from disk 
    only when requested by an authorized user.
    """
    if not encrypted_data:
        return b""
    
    # Extract the first 12 bytes as the nonce, the rest as ciphertext
    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]
    
    return aesgcm.decrypt(nonce, ciphertext, associated_data=None)