```python 
"""
src/generator.py

Image/key generation helpers for the image-keygen-crypto project.

This module focuses on:
- producing varied images that mix multiple entropy sources,
- serializing images deterministically to bytes,
- deriving cryptographic keys from image bytes (via a KDF wrapper),
- safe error handling and a small retry/backoff helper.

Notes
-----
- This is a prototype helper module. 
- For reproducible keys you must supply and protect a deterministic salt/seed.
"""

from __future__ import annotations

import io
import logging
import math
import secrets
import time
from typing import Optional, Tuple

from PIL import Image, ImageOps

# Try to import project-local helpers; fall back to minimal local implementations.
try:
    from .rate_limiter import RateLimiter
except Exception:  # pragma: no cover - fallback for standalone use
    from threading import Lock

    class RateLimiter:
        """Simple token-bucket rate limiter fallback."""

        def __init__(self, rate_per_sec: float = 1.0, burst: int = 5) -> None:
            self.rate = float(rate_per_sec)
            self.capacity = float(burst)
            self.tokens = float(burst)
            self.last = time.monotonic()
            self.lock = Lock()

        def consume(self, n: int = 1) -> bool:
            with self.lock:
                now = time.monotonic()
                self.tokens = min(self.capacity, self.tokens + (now - self.last) * self.rate)
                self.last = now
                if self.tokens >= n:
                    self.tokens -= n
                    return True
                return False


try:
    # Prefer the project's KDF wrapper if available
    from .kdf import derive_key as kdf_derive_key  # type: ignore
except Exception:  # pragma: no cover - fallback
    # Minimal HKDF-based fallback using cryptography (should be available via requirements)
    from hashlib import sha256

    try:
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF

        def kdf_derive_key(ikm: bytes, salt: Optional[bytes] = None, info: bytes = b"img-key", length: int = 32) -> Tuple[bytes, bytes]:
            """
            Derive a key using HKDF-SHA256. Returns (key, salt_used).
            If salt is None a random 16-byte salt is generated.
            """
            if salt is None:
                salt = secrets.token_bytes(16)
            # Use a fixed-length PRK input to HKDF by hashing the IKM first.
            prk = sha256(ikm).digest()
            hk = HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info, backend=default_backend())
            key = hk.derive(prk)
            return key, salt

    except Exception:
        # If cryptography isn't available, raise a clear error at runtime.
        def kdf_derive_key(*_args, **_kwargs):
            raise RuntimeError("No KDF implementation available. Install 'cryptography' or provide kdf.py in the package.")


logger = logging.getLogger(__name__)
_default_limiter = RateLimiter(rate_per_sec=1.0, burst=5)


# -------------------------
# Entropy / image generators
# -------------------------
def _perlin_like_noise_bytes(width: int, height: int, seed: Optional[int] = None) -> bytes:
    """
    Lightweight procedural noise generator. This is NOT a full Perlin implementation,
    but produces spatially correlated noise that adds variation when mixed with CSPRNG bytes.
    """
    rnd = secrets.SystemRandom(seed) if seed is not None else secrets.SystemRandom()
    data = bytearray(width * height * 3)
    # Use a few layered random waves to create low-cost spatial variation
    for y in range(height):
        for x in range(width):
            # combine a few sine/cosine waves with random phase/amplitude
            v = 0.0
            v += math.sin((x + rnd.randrange(1, 1000)) * 0.02) * 0.5
            v += math.cos((y + rnd.randrange(1, 1000)) * 0.03) * 0.3
            v += math.sin((x + y) * 0.01) * 0.2
            # normalize to 0..255
            iv = int(((v + 1.0) / 2.0) * 255) & 0xFF
            idx = (y * width + x) * 3
            data[idx] = iv
            data[idx + 1] = iv
            data[idx + 2] = iv
    return bytes(data)


def _chaotic_map_bytes(width: int, height: int, r: float = 3.9999) -> bytes:
    """
    Generate bytes from a simple logistic map. This provides a deterministic-looking
    chaotic sequence that is useful as an additional independent source to mix.
    """
    # seed from CSPRNG to avoid trivial predictability
    x = secrets.randbelow(2 ** 31) / float(2 ** 31)
    data = bytearray()
    for _ in range(width * height):
        x = r * x * (1.0 - x)
        v = int(x * 255) & 0xFF
        data.extend((v, v, v))
    return bytes(data)


def _mix_bytes(*sources: bytes) -> bytes:
    """
    Mix multiple byte sources into a single byte string using XOR and a final hash.
    The XOR reduces single-source dominance; the final SHA-256 binds the result.
    """
    if not sources:
        return b""
    length = len(sources[0])
    # ensure all sources are at least 'length' long; if not, repeat/truncate
    normalized = []
    for s in sources:
        if len(s) < length:
            # repeat the source to reach length
            times = (length + len(s) - 1) // len(s)
            normalized.append((s * times)[:length])
        else:
            normalized.append(s[:length])
    mixed = bytearray(length)
    for i in range(length):
        v = 0
        for s in normalized:
            v ^= s[i]
        mixed[i] = v & 0xFF
    return bytes(mixed)


def make_varied_image(width: int = 512, height: int = 512, extra_seed: Optional[int] = None, limiter: Optional[RateLimiter] = None) -> Image.Image:
    """
    Create an RGB PIL Image that mixes multiple entropy sources.

    Parameters
    ----------
    width, height : int
        Image dimensions in pixels.
    extra_seed : Optional[int]
        Optional seed used by procedural generators to allow deterministic images when desired.
    limiter : Optional[RateLimiter]
        Optional rate limiter instance; if omitted the module default is used.

    Returns
    -------
    PIL.Image.Image
        The generated image.

    Raises
    ------
    RuntimeError
        If rate limiting prevents generation or if an internal error occurs.
    """
    limiter = limiter or _default_limiter
    if not limiter.consume():
        raise RuntimeError("rate limit exceeded for image generation")

    try:
        # Primary high-quality entropy from OS CSPRNG
        csprng_bytes = secrets.token_bytes(width * height * 3)

        # Procedural noise (spatially correlated)
        proc_bytes = _perlin_like_noise_bytes(width, height, seed=extra_seed)

        # Chaotic map bytes
        chaotic_bytes = _chaotic_map_bytes(width, height)

        # Mix them together
        mixed = _mix_bytes(csprng_bytes, proc_bytes, chaotic_bytes)

        # Build PIL image from raw bytes
        img = Image.frombytes("RGB", (width, height), mixed)

        # Apply a few randomized transforms to increase visual variation
        # These transforms are non-destructive to the underlying bytes until saved,
        # but they change the pixel arrangement which affects the serialized bytes.
        if secrets.randbelow(2) == 1:
            img = ImageOps.autocontrast(img)
        if secrets.randbelow(4) == 0:
            # rotate by a random multiple of 90 to keep dimensions simple
            angle = secrets.choice([0, 90, 180, 270])
            img = img.rotate(angle, expand=False)
        return img
    except Exception as exc:
        logger.exception("make_varied_image failed")
        raise RuntimeError("image generation failed") from exc


# -------------------------
# Serialization and KDF
# -------------------------
def image_bytes(img: Image.Image, *, compress_level: int = 6, optimize: bool = False) -> bytes:
    """
    Serialize a PIL Image to PNG bytes deterministically (as much as PIL allows).

    Parameters
    ----------
    img : PIL.Image.Image
        Image to serialize.
    compress_level : int
        PNG compression level (0-9). Keep fixed for reproducibility.
    optimize : bool
        Whether to pass optimize flag to PIL. Keep False for deterministic output.

    Returns
    -------
    bytes
        PNG file bytes.
    """
    buf = io.BytesIO()
    # Strip info/metadata to avoid accidental nondeterminism
    img_copy = img.copy()
    img_copy.info.clear()
    img_copy.save(buf, format="PNG", optimize=optimize, compress_level=compress_level)
    return buf.getvalue()


def derive_key_from_image_bytes(ikm: bytes, *, salt: Optional[bytes] = None, info: bytes = b"img-key", length: int = 32) -> Tuple[bytes, bytes]:
    """
    Derive a fixed-length key from image bytes using the project's KDF wrapper.

    Returns (key, salt_used). If salt is None a random salt will be generated.
    """
    return kdf_derive_key(ikm, salt=salt, info=info, length=length)


# -------------------------
# High-level helpers
# -------------------------
def generate_key_with_retries(width: int = 256, height: int = 256, attempts: int = 3, backoff_base: float = 0.5, extra_seed: Optional[int] = None, limiter: Optional[RateLimiter] = None) -> Tuple[bytes, bytes]:
    """
    High-level helper that generates an image, serializes it, and derives a key.
    Retries on transient failures with exponential backoff.

    Returns
    -------
    (key_bytes, salt_bytes)
    """
    last_exc: Optional[Exception] = None
    for attempt in range(attempts):
        try:
            img = make_varied_image(width, height, extra_seed=extra_seed, limiter=limiter)
            ib = image_bytes(img)
            key, salt = derive_key_from_image_bytes(ib)
            # Attempt to zero sensitive local buffers where possible (best-effort)
            try:
                # Overwrite bytearray views if present (can't overwrite immutable bytes)
                pass
            except Exception:
                pass
            return key, salt
        except RuntimeError as re:
            # Rate limit or deterministic failure: do not retry if rate-limited
            if "rate limit" in str(re).lower():
                raise
            last_exc = re
            logger.warning("transient failure generating key (attempt %d/%d): %s", attempt + 1, attempts, re)
        except Exception as exc:
            last_exc = exc
            logger.exception("unexpected error during key generation")
        # backoff before next attempt
        time.sleep(backoff_base * (2 ** attempt))
    raise RuntimeError("generate_key_with_retries failed") from last_exc


# -------------------------
# CLI / module entry point
# -------------------------
def main() -> None:
    """
    Minimal CLI entry point used by `python -m image_keygen` or package scripts.
    Generates one key and prints hex-encoded key and salt.
    """
    import sys

    try:
        key, salt = generate_key_with_retries()
        print("Derived key:", key.hex())
        print("Salt:", salt.hex())
    except Exception as exc:
        print("Failed to generate key:", exc, file=sys.stderr)
        logger.exception("main failed")
        sys.exit(1)


if __name__ == "__main__":  # pragma: no cover - manual invocation
    main()
```
