"""
image_keygen package initializer.

This file exposes the public API for the package and provides a small
convenience entry point so the package can be used as:

    python -m image_keygen

It intentionally keeps logic minimal; the heavy lifting lives in the
submodules (generator.py, kdf.py, rate_limiter.py, utils.py).

Public API:
- make_varied_image
- image_bytes
- derive_key
- generate_key_with_retries
- RateLimiter
- __version__

Example
-------
>>> from image_keygen import generate_key_with_retries
>>> key, salt = generate_key_with_retries()
>>> print(key.hex(), salt.hex())
"""
from __future__ import annotations

# Package version (bump on releases)
__version__ = "0.1.0"

# Re-export commonly used functions and classes from submodules so users can:
#   from image_keygen import make_varied_image, derive_key
try:
    from .generator import (
        make_varied_image,
        image_bytes,
        generate_key_with_retries,
    )
except Exception:  # pragma: no cover - import-time fallback
    # If submodules are missing or fail to import, provide clear placeholders
    make_varied_image = None  # type: ignore
    image_bytes = None  # type: ignore
    generate_key_with_retries = None  # type: ignore

try:
    from .kdf import derive_key, derive_argon2
except Exception:  # pragma: no cover - import-time fallback
    derive_key = None  # type: ignore
    derive_argon2 = None  # type: ignore

try:
    from .rate_limiter import RateLimiter
except Exception:  # pragma: no cover - import-time fallback
    RateLimiter = None  # type: ignore

# Public names exported by the package
__all__ = [
    "__version__",
    "make_varied_image",
    "image_bytes",
    "generate_key_with_retries",
    "derive_key",
    "derive_argon2",
    "RateLimiter",
]

# Minimal module-level entry point used by `python -m image_keygen`
def main() -> None:
    """
    Convenience entry point for quick testing.

    Behavior:
      - Attempts to call generate_key_with_retries() from generator.py.
      - Prints the derived key and salt in hex if successful.
      - Prints a helpful message if the function is unavailable.

    This function is intentionally small and safe for interactive use.
    """
    import sys
    import traceback

    if generate_key_with_retries is None:
        print(
            "image_keygen package is not fully installed or submodules failed to import.",
            file=sys.stderr,
        )
        print("Try running from the repository root with PYTHONPATH=./src", file=sys.stderr)
        return

    try:
        key, salt = generate_key_with_retries()
        print("Derived key:", key.hex())
        print("Salt:", salt.hex())
    except Exception:
        print("Failed to generate key; see traceback below.", file=sys.stderr)
        traceback.print_exc()

# Allow `python -m image_keygen` to run the convenience main
if __name__ == "__main__":  # pragma: no cover - manual invocation
    main()
