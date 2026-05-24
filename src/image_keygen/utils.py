"""
src/image_keygen/utils.py

Utility helpers for image-keygen-crypto.

This module contains small, well-documented helpers used across the project:
- safe file I/O (atomic writes, directory creation)
- deterministic salt derivation helpers
- hashing helpers
- best-effort secure zeroing of sensitive buffers
- simple image load/save helpers that work with PIL bytes

These helpers are intentionally small and dependency-free (beyond the stdlib
and Pillow for image helpers). They are designed for clarity and auditability.
"""

from __future__ import annotations

import hashlib
import io
import os
import secrets
import tempfile
from pathlib import Path
from typing import Optional, Tuple

from PIL import Image

# Public API
__all__ = [
    "hash_sha256",
    "deterministic_salt",
    "secure_zero",
    "atomic_write_bytes",
    "save_png_bytes_to_file",
    "load_image_from_bytes",
    "ensure_parent_dir",
    "bytes_to_hex",
    "hex_to_bytes",
]


# -------------------------
# Hashing helpers
# -------------------------
def hash_sha256(data: bytes) -> bytes:
    """
    Compute SHA-256 digest of `data` and return raw bytes.

    Args:
        data: input bytes

    Returns:
        32-byte SHA-256 digest
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes or bytearray")
    h = hashlib.sha256()
    h.update(data)
    return h.digest()


# -------------------------
# Salt helpers
# -------------------------
def deterministic_salt(seed: bytes, length: int = 16) -> bytes:
    """
    Derive a deterministic salt from a seed using SHA-256.

    Use this only when you explicitly need reproducible salts and you
    understand the security implications. The seed must be protected
    like a password/secret if reproducibility is required.

    Args:
        seed: secret seed bytes (e.g., user-provided secret or deterministic image seed)
        length: desired salt length in bytes (default 16)

    Returns:
        salt bytes of requested length
    """
    if not isinstance(seed, (bytes, bytearray)):
        raise TypeError("seed must be bytes or bytearray")
    if length <= 0:
        raise ValueError("length must be > 0")
    digest = hashlib.sha256(bytes(seed)).digest()
    # If longer salt requested, expand by hashing digest||counter
    if length <= len(digest):
        return digest[:length]
    out = bytearray(digest)
    counter = 1
    while len(out) < length:
        extra = hashlib.sha256(digest + counter.to_bytes(4, "big")).digest()
        out.extend(extra)
        counter += 1
    return bytes(out[:length])


# -------------------------
# Memory zeroing helpers
# -------------------------
def secure_zero(b: Optional[bytes]) -> None:
    """
    Best-effort attempt to overwrite sensitive data in memory.

    Notes:
      - Python bytes are immutable; this function converts to a bytearray and
        overwrites that buffer. This is best-effort and cannot guarantee that
        all copies are removed (Python may have internal copies).
      - Use this to reduce exposure windows for sensitive data, but do not
        rely on it as a sole protection against memory disclosure.

    Args:
        b: bytes or bytearray to zero. If None, does nothing.
    """
    try:
        if b is None:
            return
        if isinstance(b, bytearray):
            for i in range(len(b)):
                b[i] = 0
        else:
            # Convert to bytearray and overwrite
            ba = bytearray(b)
            for i in range(len(ba)):
                ba[i] = 0
    except Exception:
        # Never raise from zeroing; it's best-effort only.
        pass


# -------------------------
# File I/O helpers
# -------------------------
def ensure_parent_dir(path: str | Path) -> None:
    """
    Ensure the parent directory of `path` exists (creates it if necessary).

    Args:
        path: file path or directory path
    """
    p = Path(path)
    parent = p.parent if p.is_file() else p
    parent.mkdir(parents=True, exist_ok=True)


def atomic_write_bytes(path: str | Path, data: bytes, mode: int = 0o600) -> None:
    """
    Atomically write bytes to `path`.

    The function writes to a temporary file in the same directory and then
    renames it into place. File permissions are set to `mode`.

    Args:
        path: destination file path
        data: bytes to write
        mode: file permission bits (default 0o600)
    """
    path = Path(path)
    ensure_parent_dir(path)
    dirpath = path.parent
    # Use NamedTemporaryFile to ensure unique temp file in same directory
    fd, tmp_path = tempfile.mkstemp(dir=dirpath)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp_path, mode)
        # Atomic replace
        os.replace(tmp_path, str(path))
    finally:
        # If tmp file still exists, try to remove it
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except Exception:
            pass


def save_png_bytes_to_file(png_bytes: bytes, dest: str | Path, *, compress_level: int = 6, optimize: bool = False) -> None:
    """
    Save PNG bytes to a file path atomically.

    If `png_bytes` is already a PNG file bytes blob, this writes it directly.
    If you have a PIL Image object, prefer using `Image.save()` to a BytesIO
    and then call this helper.

    Args:
        png_bytes: PNG file bytes
        dest: destination file path
        compress_level: (ignored if png_bytes already encoded) kept for API parity
        optimize: (ignored if png_bytes already encoded)
    """
    if not isinstance(png_bytes, (bytes, bytearray)):
        raise TypeError("png_bytes must be bytes or bytearray")
    atomic_write_bytes(dest, bytes(png_bytes))


def load_image_from_bytes(data: bytes) -> Image.Image:
    """
    Load a PIL Image from raw bytes.

    Args:
        data: image file bytes (PNG/JPEG/etc.)

    Returns:
        PIL.Image.Image
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes or bytearray")
    bio = io.BytesIO(data)
    img = Image.open(bio)
    # Force load to catch errors early and avoid lazy file handles
    img.load()
    return img


# -------------------------
# Small helpers
# -------------------------
def bytes_to_hex(b: bytes) -> str:
    """Return hex string for bytes."""
    if not isinstance(b, (bytes, bytearray)):
        raise TypeError("b must be bytes or bytearray")
    return b.hex()


def hex_to_bytes(h: str) -> bytes:
    """Convert hex string to bytes."""
    if not isinstance(h, str):
        raise TypeError("h must be a str")
    return bytes.fromhex(h)
