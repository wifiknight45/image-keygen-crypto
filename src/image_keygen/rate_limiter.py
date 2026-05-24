"""
src/image_keygen/rate_limiter.py

A small, well-documented token-bucket rate limiter used by the image-keygen-crypto
project to prevent runaway generation and to slow brute-force style loops.

Features
- Thread-safe token-bucket implementation.
- Blocking consume with timeout and non-blocking try_consume.
- Context manager for "reserve and release" style usage.
- Optional decorator to rate-limit function calls.
- Small, dependency-free implementation suitable for local use and testing.

Behavior notes
- Tokens are refilled continuously at `rate` tokens per second up to `capacity`.
- `consume(n)` will attempt to remove `n` tokens and return True/False or block
  until tokens are available (if timeout provided).
- Use a small `burst` capacity to allow short bursts while enforcing a steady rate.
"""

from __future__ import annotations

import threading
import time
import functools
import logging
from typing import Optional, Callable

logger = logging.getLogger(__name__)


class RateLimitExceeded(Exception):
    """Raised when a non-blocking consume fails due to insufficient tokens."""


class RateLimiter:
    """
    Token-bucket rate limiter.

    Parameters
    ----------
    rate : float
        Tokens added per second.
    burst : float
        Maximum number of tokens the bucket can hold (burst capacity).
    initial_tokens : Optional[float]
        Initial token count; defaults to `burst`.
    """

    def __init__(self, rate: float = 1.0, burst: float = 5.0, initial_tokens: Optional[float] = None) -> None:
        if rate <= 0:
            raise ValueError("rate must be > 0")
        if burst <= 0:
            raise ValueError("burst must be > 0")
        self._rate = float(rate)
        self._capacity = float(burst)
        self._tokens = float(initial_tokens if initial_tokens is not None else burst)
        self._last = time.monotonic()
        self._lock = threading.Lock()

    # -------------------------
    # Internal helpers
    # -------------------------
    def _refill(self) -> None:
        """Refill tokens based on elapsed time since last update."""
        now = time.monotonic()
        elapsed = now - self._last
        if elapsed <= 0:
            return
        added = elapsed * self._rate
        if added > 0:
            self._tokens = min(self._capacity, self._tokens + added)
            self._last = now

    # -------------------------
    # Public API
    # -------------------------
    def try_consume(self, tokens: float = 1.0) -> bool:
        """
        Attempt to consume `tokens` without blocking.

        Returns True if tokens were consumed, False otherwise.
        """
        if tokens <= 0:
            raise ValueError("tokens must be > 0")
        with self._lock:
            self._refill()
            if self._tokens >= tokens:
                self._tokens -= tokens
                return True
            return False

    def consume(self, tokens: float = 1.0, timeout: Optional[float] = None) -> bool:
        """
        Consume `tokens`, blocking up to `timeout` seconds if necessary.

        Parameters
        ----------
        tokens : float
            Number of tokens to consume.
        timeout : Optional[float]
            Maximum time in seconds to wait for tokens. If None, do not wait
            and behave like try_consume. If timeout is 0, behave non-blocking.

        Returns
        -------
        bool
            True if tokens were consumed, False if timed out.

        Raises
        ------
        ValueError if tokens <= 0.
        """
        if tokens <= 0:
            raise ValueError("tokens must be > 0")

        deadline = None if timeout is None else (time.monotonic() + timeout)
        while True:
            with self._lock:
                self._refill()
                if self._tokens >= tokens:
                    self._tokens -= tokens
                    return True
                # Not enough tokens now
                if timeout is None:
                    # Non-blocking mode
                    return False
                # Compute time until at least `tokens` will be available
                needed = tokens - self._tokens
                wait_time = needed / self._rate if self._rate > 0 else None

            # If wait_time is None (shouldn't happen), break
            if wait_time is None:
                return False

            # If deadline exists and wait_time would exceed it, return False
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                # Sleep the smaller of remaining and wait_time to re-check
                sleep_for = min(wait_time, remaining, 0.1) if wait_time > 0.1 else min(wait_time, remaining)
            else:
                # No deadline: sleep the computed wait_time but cap to a small value
                sleep_for = min(wait_time, 0.1) if wait_time > 0.1 else wait_time

            # Avoid busy-waiting; sleep a short interval
            if sleep_for and sleep_for > 0:
                time.sleep(sleep_for)
            else:
                # If computed sleep is zero or negative, yield briefly
                time.sleep(0.001)

    def reserve(self, tokens: float = 1.0, timeout: Optional[float] = None) -> "Reservation":
        """
        Reserve `tokens` and return a Reservation context manager.

        The reservation will consume the tokens when the context is entered.
        If tokens cannot be reserved within `timeout`, RateLimitExceeded is raised.
        """
        ok = self.consume(tokens=tokens, timeout=timeout)
        if not ok:
            raise RateLimitExceeded("could not reserve tokens within timeout")
        return Reservation(self, tokens)

    def tokens_available(self) -> float:
        """Return the current approximate number of available tokens."""
        with self._lock:
            self._refill()
            return float(self._tokens)

    def set_rate(self, rate: float) -> None:
        """Change the refill rate (tokens per second)."""
        if rate <= 0:
            raise ValueError("rate must be > 0")
        with self._lock:
            self._refill()
            self._rate = float(rate)

    def set_capacity(self, capacity: float) -> None:
        """Change the bucket capacity (burst)."""
        if capacity <= 0:
            raise ValueError("capacity must be > 0")
        with self._lock:
            self._refill()
            self._capacity = float(capacity)
            # clamp tokens to new capacity
            if self._tokens > self._capacity:
                self._tokens = self._capacity

    # -------------------------
    # Convenience decorator
    # -------------------------
    def decorate(self, tokens: float = 1.0, timeout: Optional[float] = None) -> Callable:
        """
        Return a decorator that rate-limits calls to the decorated function.

        Usage:
            limiter = RateLimiter(rate=1, burst=2)
            @limiter.decorate(tokens=1, timeout=2)
            def work(...):
                ...

        If the call cannot acquire tokens within `timeout`, RateLimitExceeded is raised.
        """

        def decorator(func: Callable) -> Callable:
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                if not self.consume(tokens=tokens, timeout=timeout):
                    raise RateLimitExceeded("rate limit exceeded for function call")
                return func(*args, **kwargs)

            return wrapper

        return decorator


class Reservation:
    """
    Context manager representing a reserved token allocation.

    The reservation is a simple object that can be used to indicate intent.
    Currently it does not "release" tokens back to the bucket on exit because
    the token-bucket model consumes tokens when reserved. This object exists
    primarily for API symmetry and future extension.
    """

    def __init__(self, limiter: RateLimiter, tokens: float) -> None:
        self._limiter = limiter
        self._tokens = tokens
        self._entered = False

    def __enter__(self) -> "Reservation":
        self._entered = True
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        # No-op: tokens are consumed at reservation time.
        self._entered = False

    def tokens(self) -> float:
        return self._tokens


# -------------------------
# Simple usage example (for docs/tests)
# -------------------------
if __name__ == "__main__":  # pragma: no cover - manual run
    logging.basicConfig(level=logging.DEBUG)
    rl = RateLimiter(rate=2.0, burst=4.0)
    print("Initial tokens:", rl.tokens_available())
    for i in range(6):
        ok = rl.try_consume()
        print(f"try_consume {i}: {ok}, tokens left: {rl.tokens_available():.2f}")
        time.sleep(0.3)
