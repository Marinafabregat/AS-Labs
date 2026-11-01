import re
from pathlib import Path
from typing import Optional

from security_encryption import encrypt_image, decrypt_image

UPLOAD_DIR = Path(__file__).parent / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)

ENC_SUFFIX = ".enc"
_SAFE_NAME = re.compile(r"^[A-Za-z0-9_-]+\.(jpg|jpeg|png|webp)$")
MEDIA_TYPES = {".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".png": "image/png", ".webp": "image/webp"}


def is_valid_name(name: Optional[str]) -> bool:
    return bool(name) and _SAFE_NAME.fullmatch(name) is not None


def _enc_path(name: str) -> Path:
    if not is_valid_name(name):
        raise ValueError("Invalid image name")
    path = (UPLOAD_DIR / (name + ENC_SUFFIX)).resolve()
    if path.parent != UPLOAD_DIR.resolve():
        raise ValueError("Invalid image path")
    return path


def media_type(name: str) -> str:
    return MEDIA_TYPES.get(Path(name).suffix.lower(), "application/octet-stream")


def save_image(name: str, data: bytes) -> None:
    path = _enc_path(name)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(encrypt_image(data, aad=name.encode()))
    tmp.replace(path)


def load_image(name: str) -> bytes:
    return decrypt_image(_enc_path(name).read_bytes(), aad=name.encode())


def delete_image(name: Optional[str]) -> None:
    if not is_valid_name(name):
        return
    path = _enc_path(name)
    if path.is_file():
        path.unlink()


def migrate_plaintext_uploads() -> int:
    migrated = 0
    for path in UPLOAD_DIR.iterdir():
        if not path.is_file() or path.name.endswith((ENC_SUFFIX, ".tmp")):
            continue
        if not is_valid_name(path.name):
            continue  # unknown file: leave it alone (and it is no longer web-served)
        save_image(path.name, path.read_bytes())
        path.unlink()
        migrated += 1
    return migrated
