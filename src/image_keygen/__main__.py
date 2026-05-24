#!/usr/bin/env python3
"""
src/__main__.py

Top-level CLI for the image-keygen-crypto project.

Features
- Rich CLI with subcommands and flags for generation, reproducible mode, and batch runs.
- Much more image variation: layered procedural noise, Perlin-like waves, chaotic maps,
  color palettes, randomized transforms, and optional overlays.
- "timed" mode: generate a new image every `--delay` seconds until `--iterations` are exhausted.
- Safe defaults, rate limiting, retries, deterministic seed support, and robust error handling.
- Saves PNG images and (optionally) prints or stores derived keys and salts.

Usage examples
--------------
# Generate one image and derive a key (non-reproducible)
python src/main.py generate --width 256 --height 256 --out-dir out

# Generate 10 images, one every 10 seconds
python src/main.py timed --iterations 10 --delay 10 --out-dir out

# Reproducible run using a numeric seed and deterministic salt
python src/main.py generate --seed 42 --reproducible --salt-seed "my-secret" --out-dir out
"""
from __future__ import annotations

import argparse
import logging
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional, Tuple

from PIL import Image, ImageDraw, ImageFilter, ImageOps

# Import package internals (assumes package is importable via PYTHONPATH=./src or installed)
try:
    from image_keygen.generator import make_varied_image, image_bytes, generate_key_with_retries
    from image_keygen.kdf import derive_key_from_image_bytes, derive_key, derive_argon2
    from image_keygen.rate_limiter import RateLimiter, RateLimitExceeded
    from image_keygen.utils import atomic_write_bytes, deterministic_salt, bytes_to_hex
except Exception:
    # Provide helpful error message if package import fails
    print(
        "Failed to import image_keygen package. Ensure you're running from the repository root and",
        "that PYTHONPATH includes ./src, or install the package in editable mode:",
        file=sys.stderr,
    )
    print("  PYTHONPATH=./src python src/main.py ...", file=sys.stderr)
    print("  or", file=sys.stderr)
    print("  pip install -e .", file=sys.stderr)
    raise

logger = logging.getLogger("image_keygen.main")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")


# -------------------------
# Helpers
# -------------------------
def ensure_out_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def save_png_atomic(png_bytes: bytes, dest: Path) -> None:
    """Atomically write PNG bytes to disk using utils.atomic_write_bytes."""
    atomic_write_bytes(dest, png_bytes)


def timestamped_name(prefix: str = "img") -> str:
    return f"{prefix}-{datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}"


def derive_and_maybe_print(ib: bytes, use_argon2: bool = False, argon2_params: Optional[dict] = None, hkdf_info: bytes = b"image-keygen", length: int = 32, reproducible_salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    """
    Derive a key from image bytes and return (key, salt). Print hex to stdout for convenience.
    """
    if use_argon2:
        key, salt = derive_argon2(ib, salt=reproducible_salt, **(argon2_params or {}))
    else:
        key, salt = derive_key(ib, salt=reproducible_salt, info=hkdf_info, length=length)
    logger.info("Derived key: %s", key.hex())
    logger.info("Salt: %s", salt.hex())
    return key, salt


# -------------------------
# Enhanced image variation helpers
# -------------------------
def _apply_random_palette(img: Image.Image, seed: Optional[int] = None) -> Image.Image:
    """
    Map grayscale image to a randomized color palette to increase entropy in pixel values.
    This is deterministic if seed is provided.
    """
    rnd = __import__("random").Random(seed)
    # Create a palette of 256 RGB tuples
    palette = []
    for i in range(256):
        # bias towards varied hues and contrast
        r = int(rnd.uniform(0, 255))
        g = int(rnd.uniform(0, 255))
        b = int(rnd.uniform(0, 255))
        palette.extend((r, g, b))
    # Convert to 'P' mode with palette
    pal_img = img.convert("L").convert("P")
    pal_img.putpalette(palette)
    return pal_img.convert("RGB")


def _overlay_noise(img: Image.Image, intensity: float = 0.15, seed: Optional[int] = None) -> Image.Image:
    """
    Overlay a translucent noise layer to add subtle per-pixel variation.
    """
    width, height = img.size
    rnd = __import__("random").Random(seed)
    noise = Image.new("L", (width, height))
    pixels = noise.load()
    for y in range(height):
        for x in range(width):
            # small random value centered at 128
            v = int(128 + rnd.gauss(0, 32))
            pixels[x, y] = max(0, min(255, v))
    noise = noise.filter(ImageFilter.GaussianBlur(radius=1))
    noise_rgb = Image.merge("RGB", (noise, noise, noise))
    return Image.blend(img, noise_rgb, intensity)


def _add_text_watermark(img: Image.Image, text: str, opacity: float = 0.08) -> Image.Image:
    """
    Add a faint timestamp or identifier watermark to the image to increase variation.
    """
    width, height = img.size
    overlay = Image.new("RGBA", (width, height), (0, 0, 0, 0))
    draw = ImageDraw.Draw(overlay)
    font_size = max(10, width // 32)
    try:
        # Use a default PIL font; if available, a TTF could be used for nicer rendering.
        from PIL import ImageFont

        font = ImageFont.load_default()
    except Exception:
        font = None
    text = text or timestamped_name()
    text_w, text_h = draw.textsize(text, font=font)
    # place in bottom-right corner
    pos = (width - text_w - 6, height - text_h - 6)
    draw.text(pos, text, fill=(255, 255, 255, int(255 * opacity)), font=font)
    combined = Image.alpha_composite(img.convert("RGBA"), overlay)
    return combined.convert("RGB")


def enhanced_make_varied_image(width: int = 512, height: int = 512, seed: Optional[int] = None, extra_variation: bool = True) -> Image.Image:
    """
    Build on top of the package's make_varied_image to add more visual and byte-level variation.
    If seed is provided, deterministic choices are made where possible.
    """
    # Use the package generator as the base
    base_img = make_varied_image(width, height, extra_seed=seed)
    # Apply palette mapping deterministically if seed provided
    pal_img = _apply_random_palette(base_img, seed=seed)
    # Optionally overlay noise and watermark
    if extra_variation:
        pal_img = _overlay_noise(pal_img, intensity=0.12, seed=seed)
        pal_img = _add_text_watermark(pal_img, text=timestamped_name("img"), opacity=0.06)
    # Random small transforms to change pixel layout
    rnd = __import__("random").Random(seed)
    if rnd.random() < 0.3:
        pal_img = ImageOps.autocontrast(pal_img)
    if rnd.random() < 0.2:
        pal_img = pal_img.filter(ImageFilter.UnsharpMask(radius=1, percent=80, threshold=3))
    return pal_img


# -------------------------
# CLI actions
# -------------------------
def action_generate(args: argparse.Namespace) -> int:
    out_dir = Path(args.out_dir or "out")
    ensure_out_dir(out_dir)
    limiter = RateLimiter(rate=args.rate, burst=args.burst)
    # If reproducible, derive deterministic salt from provided salt_seed
    reproducible_salt = None
    if args.reproducible:
        if args.salt_seed is None:
            logger.error("reproducible mode requires --salt-seed")
            return 2
        reproducible_salt = deterministic_salt(args.salt_seed.encode("utf-8"), length=16)

    try:
        if not limiter.try_consume():
            logger.error("Rate limiter prevented generation; try again later")
            return 3

        img = enhanced_make_varied_image(args.width, args.height, seed=args.seed, extra_variation=not args.minimal)
        png = image_bytes(img, compress_level=args.compress_level, optimize=args.optimize)
        name = args.name or timestamped_name("img")
        out_path = out_dir / f"{name}.png"
        save_png_atomic(png, out_path)
        logger.info("Saved image to %s", out_path)

        if args.derive:
            key, salt = derive_and_maybe_print(png, use_argon2=args.use_argon2, argon2_params=None, hkdf_info=b"image-keygen", length=args.key_length, reproducible_salt=reproducible_salt)
            # Optionally save key metadata
            if args.save_meta:
                meta_path = out_dir / f"{name}.meta.txt"
                meta = f"key:{key.hex()}\nsalt:{salt.hex()}\n"
                atomic_write_bytes(meta_path, meta.encode("utf-8"))
                logger.info("Saved metadata to %s", meta_path)
        return 0
    except RateLimitExceeded:
        logger.error("Rate limit exceeded")
        return 3
    except Exception as exc:
        logger.exception("Generation failed: %s", exc)
        return 1


def action_timed(args: argparse.Namespace) -> int:
    out_dir = Path(args.out_dir or "out")
    ensure_out_dir(out_dir)
    limiter = RateLimiter(rate=args.rate, burst=args.burst)
    reproducible_salt = None
    if args.reproducible:
        if args.salt_seed is None:
            logger.error("reproducible mode requires --salt-seed")
            return 2
        reproducible_salt = deterministic_salt(args.salt_seed.encode("utf-8"), length=16)

    iterations = max(1, int(args.iterations))
    delay = max(0.1, float(args.delay))
    logger.info("Starting timed generation: %d iterations, %s seconds delay", iterations, delay)
    for i in range(iterations):
        try:
            # Respect rate limiter per iteration
            if not limiter.consume(timeout=5.0):
                logger.warning("Could not acquire tokens for iteration %d; skipping", i + 1)
                time.sleep(delay)
                continue

            seed = args.seed if args.seed is None else (args.seed + i)
            img = enhanced_make_varied_image(args.width, args.height, seed=seed, extra_variation=not args.minimal)
            png = image_bytes(img, compress_level=args.compress_level, optimize=args.optimize)
            name = args.name or timestamped_name(f"img-{i+1:04d}")
            out_path = out_dir / f"{name}.png"
            save_png_atomic(png, out_path)
            logger.info("[%d/%d] Saved %s", i + 1, iterations, out_path)

            if args.derive:
                key, salt = derive_and_maybe_print(png, use_argon2=args.use_argon2, argon2_params=None, hkdf_info=b"image-keygen", length=args.key_length, reproducible_salt=reproducible_salt)
                if args.save_meta:
                    meta_path = out_dir / f"{name}.meta.txt"
                    meta = f"key:{key.hex()}\nsalt:{salt.hex()}\n"
                    atomic_write_bytes(meta_path, meta.encode("utf-8"))
                    logger.info("Saved metadata to %s", meta_path)

            # Wait before next iteration unless it's the last
            if i + 1 < iterations:
                logger.debug("Sleeping for %s seconds before next iteration", delay)
                time.sleep(delay)
        except KeyboardInterrupt:
            logger.info("Interrupted by user; stopping timed generation")
            return 0
        except Exception:
            logger.exception("Error during timed generation iteration %d", i + 1)
            # continue to next iteration after a short pause
            time.sleep(min(1.0, delay))
    logger.info("Timed generation complete")
    return 0


# -------------------------
# CLI wiring
# -------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="image-keygen", description="Generate varied images and derive cryptographic keys from them.")
    sub = p.add_subparsers(dest="command", required=True)

    # generate subcommand
    g = sub.add_parser("generate", help="Generate a single image (and optionally derive a key).")
    g.add_argument("--width", type=int, default=512)
    g.add_argument("--height", type=int, default=512)
    g.add_argument("--seed", type=int, default=None, help="Optional numeric seed for deterministic generation.")
    g.add_argument("--name", type=str, default=None, help="Base name for output file (timestamped if omitted).")
    g.add_argument("--out-dir", type=str, default="out")
    g.add_argument("--derive", action="store_true", help="Derive a key from the image bytes and print it.")
    g.add_argument("--use-argon2", action="store_true", help="Use Argon2id instead of HKDF for key derivation.")
    g.add_argument("--key-length", type=int, default=32, help="Derived key length in bytes.")
    g.add_argument("--reproducible", action="store_true", help="Enable reproducible mode (requires --salt-seed).")
    g.add_argument("--salt-seed", type=str, default=None, help="Secret seed used to derive deterministic salt when reproducible mode is enabled.")
    g.add_argument("--save-meta", action="store_true", help="Save key and salt metadata alongside the image.")
    g.add_argument("--minimal", action="store_true", help="Produce a simpler image with fewer transforms (useful for testing).")
    g.add_argument("--compress-level", type=int, default=6, choices=list(range(0, 10)))
    g.add_argument("--optimize", action="store_true")
    g.add_argument("--rate", type=float, default=1.0, help="Rate limiter tokens per second.")
    g.add_argument("--burst", type=float, default=5.0, help="Rate limiter burst capacity.")
    g.set_defaults(func=action_generate)

    # timed subcommand
    t = sub.add_parser("timed", help="Generate images repeatedly with a fixed delay between iterations.")
    t.add_argument("--iterations", type=int, default=10, help="Number of images to generate.")
    t.add_argument("--delay", type=float, default=10.0, help="Seconds to wait between images.")
    # reuse many of the same options as generate
    t.add_argument("--width", type=int, default=512)
    t.add_argument("--height", type=int, default=512)
    t.add_argument("--seed", type=int, default=None, help="Optional numeric seed; if provided, each iteration will offset the seed.")
    t.add_argument("--name", type=str, default=None)
    t.add_argument("--out-dir", type=str, default="out")
    t.add_argument("--derive", action="store_true")
    t.add_argument("--use-argon2", action="store_true")
    t.add_argument("--key-length", type=int, default=32)
    t.add_argument("--reproducible", action="store_true")
    t.add_argument("--salt-seed", type=str, default=None)
    t.add_argument("--save-meta", action="store_true")
    t.add_argument("--minimal", action="store_true")
    t.add_argument("--compress-level", type=int, default=6, choices=list(range(0, 10)))
    t.add_argument("--optimize", action="store_true")
    t.add_argument("--rate", type=float, default=1.0)
    t.add_argument("--burst", type=float, default=5.0)
    t.set_defaults(func=action_timed)

    return p


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except Exception:
        logger.exception("Unhandled error in main")
        return 1


if __name__ == "__main__":  # pragma: no cover - manual invocation
    raise SystemExit(main())
