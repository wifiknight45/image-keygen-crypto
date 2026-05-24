"""
src/kdf.py

Standalone KDF helpers intended for use in development or as a simple top-level
compatibility module. This file provides:

- derive_key: HKDF-SHA256 wrapper for high-entropy input material (IKM).
- derive_argon2: Argon2id wrapper for low-entropy / password-like inputs.
- derive_key_from_image_bytes: convenience selector between HKDF and Argon2.

Security notes
--------------
- HKDF is appropriate when the input material already has high entropy.
- Use Argon2id for password-like or low-entropy inputs.
- Always protect and store salts securely if you need reproducible keys.
- This module returns (key_bytes, salt_bytes). If salt is None a random salt
  will be generated.
"""

from __future__ import annotations

import secrets
import logging
from typing import Optional, Tuple

# HKDF imports
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Argon2 imports (argon2-cffi)
try:
    from argon2.low_level import Type as Argon2Type
    from argon2.low_level import hash_secret_raw as _argon2_hash_raw
except Exception:  # pragma: no cover - helpful error if dependency missing
    _argon2_hash_raw = None  # type: ignore
    Argon2Type = None  # type: ignore

logger = logging.getLogger(__name__)

# -------------------------
# Defaults and constants
# -------------------------
DEFAULT_HKDF_LENGTH = 32  # bytes
DEFAULT_HKDF_SALT_LEN = 16  # bytes

# Example Argon2id defaults suitable for interactive use.
# Tune these for your environment before production use.
DEFAULT_ARGON2_TIME_COST = 3
DEFAULT_ARGON2_MEMORY_COST = 65536  # KiB (64 MiB)
DEFAULT_ARGON2_PARALLELISM = 2
DEFAULT_ARGON2_HASH_LEN = 32
DEFAULT_ARGON2_SALT_LEN = 16


# -------------------------
# Helpers
# -------------------------
def _ensure_salt(salt: Optional[bytes], length: int) -> bytes:
    """
    Return a salt of the requested length. If salt is None, generate a random one.
    """
    if salt is None:
        return secrets.token_bytes(length)
    if not isinstance(salt, (bytes, bytearray)):
        raise TypeError("salt must be bytes or bytearray")
    if len(salt) < length:
        raise ValueError(f"salt must be at least {length} bytes")
    return bytes(salt[:length])


def _zero_bytes(b: Optional[bytes]) -> None:
    """
    Best-effort attempt to overwrite sensitive data in memory.
    Note: Python bytes are immutable; converting to bytearray and overwriting
    may help in some cases but is not guaranteed to remove all copies.
    """
    try:
        if b is None:
            return
        ba = bytearray(b)
        for i in range(len(ba)):
            ba[i] = 0
    except Exception:
        # If zeroing fails, do not raise; this is best-effort only.
        pass


# -------------------------
# HKDF wrapper
# -------------------------
def derive_key(
    ikm: bytes,
    *,
    salt: Optional[bytes] = None,
    info: bytes = b"image-keygen",
    length: int = DEFAULT_HKDF_LENGTH,
    salt_len: int = DEFAULT_HKDF_SALT_LEN,
) -> Tuple[bytes, bytes]:
    """
    Derive a key from input keying material (ikm) using HKDF-SHA256.

    Parameters
    ----------
    ikm : bytes
        Input keying material (e.g., hash of image bytes or raw image bytes).
    salt : Optional[bytes]
        Optional salt. If None a random salt of salt_len bytes is generated.
        If provided, it must be at least salt_len bytes; only the first salt_len
        bytes are used.
    info : bytes
        Optional context/application-specific info string for HKDF.
    length : int
        Desired output key length in bytes.
    salt_len : int
        Salt length in bytes when generating a random salt.

    Returns
    -------
    (key_bytes, salt_used)
    """
    if not isinstance(ikm, (bytes, bytearray)):
        raise TypeError("ikm must be bytes or bytearray")
    salt_used = _ensure_salt(salt, salt_len)
    try:
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=salt_used,
            info=info,
            backend=default_backend(),
        )
        key = hkdf.derive(bytes(ikm))
        return key, salt_used
    finally:
        _zero_bytes(salt_used)


# -------------------------
# Argon2id wrapper
# -------------------------
def derive_argon2(
    secret: bytes,
    *,
    salt: Optional[bytes] = None,
    time_cost: int = DEFAULT_ARGON2_TIME_COST,
    memory_cost: int = DEFAULT_ARGON2_MEMORY_COST,
    parallelism: int = DEFAULT_ARGON2_PARALLELISM,
    hash_len: int = DEFAULT_ARGON2_HASH_LEN,
    salt_len: int = DEFAULT_ARGON2_SALT_LEN,
) -> Tuple[bytes, bytes]:
    """
    Derive a key using Argon2id (raw output).

    Parameters
    ----------
    secret : bytes
        Password-like or low-entropy input (e.g., user-chosen seed or image hash).
    salt : Optional[bytes]
        Optional salt. If None a random salt of salt_len bytes is generated.
    time_cost : int
        Argon2 time cost (iterations).
    memory_cost : int
        Argon2 memory cost in KiB (e.g., 65536 = 64 MiB).
    parallelism : int
        Degree of parallelism (threads).
    hash_len : int
        Desired output length in bytes.
    salt_len : int
        Salt length in bytes when generating a random salt.

    Returns
    -------
    (key_bytes, salt_used)

    Raises
    ------
    RuntimeError if argon2-cffi is not installed.
    """
    if _argon2_hash_raw is None:
        raise RuntimeError("argon2-cffi is required for derive_argon2; install argon2-cffi")

    if not isinstance(secret, (bytes, bytearray)):
        raise TypeError("secret must be bytes or bytearray")

    salt_used = _ensure_salt(salt, salt_len)
    try:
        # argon2.low_level.hash_secret_raw expects:
        #   password, salt, time_cost, memory_cost, parallelism, hash_len, type
        # memory_cost is in KiB.
        key = _argon2_hash_raw(
            secret,
            salt_used,
            time_cost,
            memory_cost,
            parallelism,
            hash_len,
            Argon2Type.ID,
        )
        return key, salt_used
    finally:
        _zero_bytes(salt_used)


# -------------------------
# Convenience helper
# -------------------------
def derive_key_from_image_bytes(
    image_bytes: bytes,
    *,
    use_argon2: bool = False,
    argon2_params: Optional[dict] = None,
    hkdf_info: bytes = b"image-keygen",
    length: int = DEFAULT_HKDF_LENGTH,
) -> Tuple[bytes, bytes]:
    """
    Convenience helper that chooses between HKDF and Argon2 based on use_argon2.

    - If use_argon2 is False (default), HKDF is used and returns (key, salt).
    - If use_argon2 is True, Argon2id is used with provided argon2_params.

    Note: For Argon2, the input should be treated like a password/seed.
    """
    if use_argon2:
        params = argon2_params or {}
        return derive_argon2(
            image_bytes,
            salt=params.get("salt"),
            time_cost=params.get("time_cost", DEFAULT_ARGON2_TIME_COST),
            memory_cost=params.get("memory_cost", DEFAULT_ARGON2_MEMORY_COST),
            parallelism=params.get("parallelism", DEFAULT_ARGON2_PARALLELISM),
            hash_len=params.get("hash_len", DEFAULT_ARGON2_HASH_LEN),
            salt_len=params.get("salt_len", DEFAULT_ARGON2_SALT_LEN),
        )
    else:
        return derive_key(image_bytes, salt=None, info=hkdf_info, length=length)


# Public API
__all__ = [
    "derive_key",
    "derive_argon2",
    "derive_key_from_image_bytes",
    "DEFAULT_HKDF_LENGTH",
    "DEFAULT_ARGON2_HASH_LEN",
]
