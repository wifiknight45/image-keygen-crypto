"""
src/generator2.py
Image/key generation helpers for the image-keygen-crypto project.
Enhanced with rich visual variety: colors, patterns, transforms, and watermarks.

CLI Usage
---------
Single key (original behaviour):
    python generator2.py

Batch mode — generate N keys + save images:
    python generator2.py batch [--count 20] [--width 256] [--height 256] [--outdir ./output]

Examples:
    python generator2.py batch                        # 20 keys, 256×256, ./output
    python generator2.py batch --count 5              # 5 keys
    python generator2.py batch --count 20 --outdir /tmp/keys
    python generator2.py batch --width 512 --height 512 --count 20
"""
from __future__ import annotations
import argparse
import io
import logging
import math
import os
import secrets
import time
from typing import Optional, Tuple
from PIL import Image, ImageOps, ImageFilter, ImageDraw, ImageEnhance

# ---------------------------------------------------------------------------
# Optional project-local helpers with safe fallbacks
# ---------------------------------------------------------------------------
try:
    from .rate_limiter import RateLimiter
except Exception:  # pragma: no cover
    from threading import Lock

    class RateLimiter:
        def __init__(self, rate_per_sec: float = 1.0, burst: int = 5) -> None:
            self.rate = float(rate_per_sec)
            self.capacity = float(burst)
            self.tokens = float(burst)
            self.last = time.monotonic()
            self.lock = Lock()

        def consume(self, n: int = 1) -> bool:
            with self.lock:
                now = time.monotonic()
                self.tokens = min(
                    self.capacity, self.tokens + (now - self.last) * self.rate
                )
                self.last = now
                if self.tokens >= n:
                    self.tokens -= n
                    return True
                return False


try:
    from .kdf import derive_key as kdf_derive_key  # type: ignore
except Exception:  # pragma: no cover
    from hashlib import sha256

    try:
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF

        def kdf_derive_key(
            ikm: bytes,
            salt: Optional[bytes] = None,
            info: bytes = b"img-key",
            length: int = 32,
        ) -> Tuple[bytes, bytes]:
            if salt is None:
                salt = secrets.token_bytes(16)
            prk = sha256(ikm).digest()
            hk = HKDF(
                algorithm=hashes.SHA256(),
                length=length,
                salt=salt,
                info=info,
                backend=default_backend(),
            )
            key = hk.derive(prk)
            return key, salt

    except Exception:

        def kdf_derive_key(*_args, **_kwargs):
            raise RuntimeError(
                "No KDF implementation available. "
                "Install 'cryptography' or provide kdf.py in the package."
            )


logger = logging.getLogger(__name__)

# Separate limiters so batch mode doesn't starve the default single-shot limiter.
_default_limiter = RateLimiter(rate_per_sec=1.0, burst=5)
_batch_limiter = RateLimiter(rate_per_sec=4.0, burst=20)


# ---------------------------------------------------------------------------
# Low-level entropy generators
# ---------------------------------------------------------------------------

def _perlin_like_noise_bytes(
    width: int, height: int, seed: Optional[int] = None
) -> bytes:
    rnd = secrets.SystemRandom(seed) if seed is not None else secrets.SystemRandom()
    data = bytearray(width * height * 3)
    for y in range(height):
        for x in range(width):
            v = 0.0
            v += math.sin((x + rnd.randrange(1, 1000)) * 0.02) * 0.5
            v += math.cos((y + rnd.randrange(1, 1000)) * 0.03) * 0.3
            v += math.sin((x + y) * 0.01) * 0.2
            iv = int(((v + 1.0) / 2.0) * 255) & 0xFF
            idx = (y * width + x) * 3
            data[idx : idx + 3] = (iv, iv, iv)
    return bytes(data)


def _chaotic_map_bytes(width: int, height: int, r: float = 3.9999) -> bytes:
    x = secrets.randbelow(2**31) / float(2**31)
    data = bytearray()
    for _ in range(width * height):
        x = r * x * (1.0 - x)
        v = int(x * 255) & 0xFF
        data.extend((v, v, v))
    return bytes(data)


def _mix_bytes(*sources: bytes) -> bytes:
    if not sources:
        return b""
    length = len(sources[0])
    normalized = [
        (s * ((length + len(s) - 1) // len(s)))[:length] for s in sources
    ]
    mixed = bytearray(length)
    for i in range(length):
        v = 0
        for s in normalized:
            v ^= s[i]
        mixed[i] = v & 0xFF
    return bytes(mixed)


# ---------------------------------------------------------------------------
# Visual enhancement helpers
# ---------------------------------------------------------------------------

def _add_color_tint(img: Image.Image) -> Image.Image:
    if secrets.randbelow(3) == 0:
        return img
    r = secrets.randbelow(50) - 25
    g = secrets.randbelow(50) - 25
    b = secrets.randbelow(50) - 25
    img = img.point(
        lambda p, offset=r: max(0, min(255, p + offset)) if p % 3 == 0 else p
    )
    img = img.point(
        lambda p, offset=g: max(0, min(255, p + offset)) if p % 3 == 1 else p
    )
    img = img.point(
        lambda p, offset=b: max(0, min(255, p + offset)) if p % 3 == 2 else p
    )
    return img


def _add_radial_gradient(img: Image.Image) -> Image.Image:
    if secrets.randbelow(2) == 0:
        return img
    width, height = img.size
    draw = ImageDraw.Draw(img)
    cx, cy = width // 2, height // 2
    max_r = max(width, height) // 2
    for radius in range(max_r, 0, -12):
        alpha = int(30 * (radius / max_r))
        color = (
            *secrets.choice(
                [(200, 50, 50), (50, 200, 50), (50, 50, 200), (200, 200, 50)]
            ),
            alpha,
        )
        draw.ellipse(
            [cx - radius, cy - radius, cx + radius, cy + radius], fill=color
        )
    return img


def _add_watermark(img: Image.Image) -> Image.Image:
    if secrets.randbelow(3) != 0:
        return img
    draw = ImageDraw.Draw(img)
    symbols = ["◆", "◉", "▲", "■", "✦", "∞", "⚡", "⬡", "⌘"]
    symbol = secrets.choice(symbols)
    x = secrets.randbelow(max(1, img.width - 100))
    y = secrets.randbelow(max(1, img.height - 100))
    draw.text((x, y), symbol, fill=(255, 255, 255, 80), size=140)
    return img


# ---------------------------------------------------------------------------
# Core image factory
# ---------------------------------------------------------------------------

def make_varied_image(
    width: int = 512,
    height: int = 512,
    extra_seed: Optional[int] = None,
    limiter: Optional[RateLimiter] = None,
) -> Image.Image:
    limiter = limiter or _default_limiter
    if not limiter.consume():
        raise RuntimeError("rate limit exceeded for image generation")

    try:
        csprng_bytes = secrets.token_bytes(width * height * 3)
        proc_bytes = _perlin_like_noise_bytes(width, height, seed=extra_seed)
        chaotic_bytes = _chaotic_map_bytes(width, height)
        mixed = _mix_bytes(csprng_bytes, proc_bytes, chaotic_bytes)
        img = Image.frombytes("RGB", (width, height), mixed)

        # Visual enhancements
        img = _add_color_tint(img)

        if secrets.randbelow(2) == 1:
            img = ImageOps.autocontrast(img, cutoff=secrets.randbelow(12))
        if secrets.randbelow(3) == 0:
            img = ImageOps.equalize(img)
        if secrets.randbelow(2) == 1:
            img = img.filter(ImageFilter.SHARPEN)
        if secrets.randbelow(2) == 1:
            img = img.filter(ImageFilter.EDGE_ENHANCE_MORE)

        if secrets.randbelow(3) == 0:
            angle = secrets.choice([90, 180, 270])
            img = img.rotate(angle, expand=True, fillcolor=(10, 10, 20))
        if secrets.randbelow(4) == 0:
            img = ImageOps.flip(img)
        if secrets.randbelow(4) == 0:
            img = ImageOps.mirror(img)

        img = _add_radial_gradient(img)
        img = _add_watermark(img)

        if secrets.randbelow(3) == 0:
            enhancer = ImageEnhance.Brightness(img)
            img = enhancer.enhance(1.1 + secrets.SystemRandom().random() * 0.5)

        return img

    except Exception as exc:
        logger.exception("make_varied_image failed")
        raise RuntimeError("image generation failed") from exc


# ---------------------------------------------------------------------------
# Serialisation and KDF
# ---------------------------------------------------------------------------

def image_bytes(
    img: Image.Image,
    *,
    compress_level: int = 6,
    optimize: bool = False,
) -> bytes:
    buf = io.BytesIO()
    img_copy = img.copy()
    img_copy.info.clear()
    img_copy.save(
        buf, format="PNG", optimize=optimize, compress_level=compress_level
    )
    return buf.getvalue()


def derive_key_from_image_bytes(
    ikm: bytes,
    *,
    salt: Optional[bytes] = None,
    info: bytes = b"img-key",
    length: int = 32,
) -> Tuple[bytes, bytes]:
    return kdf_derive_key(ikm, salt=salt, info=info, length=length)


# ---------------------------------------------------------------------------
# High-level helpers
# ---------------------------------------------------------------------------

def generate_key_with_retries(
    width: int = 256,
    height: int = 256,
    attempts: int = 3,
    backoff_base: float = 0.5,
    extra_seed: Optional[int] = None,
    limiter: Optional[RateLimiter] = None,
) -> Tuple[bytes, bytes]:
    last_exc: Optional[Exception] = None
    for attempt in range(attempts):
        try:
            img = make_varied_image(width, height, extra_seed=extra_seed, limiter=limiter)
            ib = image_bytes(img)
            key, salt = derive_key_from_image_bytes(ib)
            return key, salt
        except RuntimeError as re:
            if "rate limit" in str(re).lower():
                raise
            last_exc = re
            logger.warning(
                "transient failure generating key (attempt %d/%d): %s",
                attempt + 1,
                attempts,
                re,
            )
        except Exception as exc:
            last_exc = exc
            logger.exception("unexpected error during key generation")
        time.sleep(backoff_base * (2**attempt))
    raise RuntimeError("generate_key_with_retries failed") from last_exc


# ---------------------------------------------------------------------------
# Batch generation
# ---------------------------------------------------------------------------

def batch_generate(
    count: int = 20,
    width: int = 256,
    height: int = 256,
    outdir: str = "./output",
) -> None:
    """Generate *count* key/image pairs and save them to *outdir*.

    Each iteration produces:
        <outdir>/key_<N>.txt   — hex key + hex salt
        <outdir>/image_<N>.png — the source image
    """
    os.makedirs(outdir, exist_ok=True)

    # A generous limiter so 20 images don't stall
    limiter = RateLimiter(rate_per_sec=float(count), burst=count)

    print(f"Generating {count} key/image pair(s) → {os.path.abspath(outdir)}\n")

    success = 0
    for i in range(1, count + 1):
        label = f"{i:03d}"
        try:
            img = make_varied_image(width, height, limiter=limiter)
            ib = image_bytes(img)
            key, salt = derive_key_from_image_bytes(ib)

            img_path = os.path.join(outdir, f"image_{label}.png")
            key_path = os.path.join(outdir, f"key_{label}.txt")

            img.save(img_path, format="PNG")
            with open(key_path, "w") as fh:
                fh.write(f"key:  {key.hex()}\n")
                fh.write(f"salt: {salt.hex()}\n")

            print(f"  [{label}/{count:03d}]  key={key.hex()[:16]}…  salt={salt.hex()[:8]}…  ✓")
            success += 1

        except Exception as exc:
            print(f"  [{label}/{count:03d}]  ERROR: {exc}")
            logger.exception("batch item %s failed", label)

    print(f"\nDone. {success}/{count} pairs generated in '{outdir}'.")


# ---------------------------------------------------------------------------
# CLI entry-point
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="generator2",
        description="Image-based cryptographic key generator.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = parser.add_subparsers(dest="command")

    # -- batch subcommand --
    batch_cmd = sub.add_parser(
        "batch",
        help="Generate multiple key/image pairs and save them to disk.",
    )
    batch_cmd.add_argument(
        "--count",
        type=int,
        default=20,
        metavar="N",
        help="Number of pairs to generate (default: 20).",
    )
    batch_cmd.add_argument(
        "--width",
        type=int,
        default=256,
        metavar="PX",
        help="Image width in pixels (default: 256).",
    )
    batch_cmd.add_argument(
        "--height",
        type=int,
        default=256,
        metavar="PX",
        help="Image height in pixels (default: 256).",
    )
    batch_cmd.add_argument(
        "--outdir",
        default="./output",
        metavar="DIR",
        help="Output directory (default: ./output).",
    )

    return parser


def main() -> None:
    import sys

    logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")

    parser = _build_parser()
    args = parser.parse_args()

    if args.command == "batch":
        # ---- batch mode ----
        if args.count < 1:
            parser.error("--count must be at least 1")
        batch_generate(
            count=args.count,
            width=args.width,
            height=args.height,
            outdir=args.outdir,
        )
    else:
        # ---- original single-key mode (no subcommand) ----
        try:
            key, salt = generate_key_with_retries()
            print("Derived key:", key.hex())
            print("Salt:       ", salt.hex())
        except Exception as exc:
            print("Failed to generate key:", exc, file=sys.stderr)
            logger.exception("main failed")
            sys.exit(1)


if __name__ == "__main__":
    main()
