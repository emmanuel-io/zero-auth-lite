"""Constant-time comparison helpers."""

import hmac


def constant_time_equals(a: str | None, b: str | None) -> bool:
    """Compare two non-empty strings without content-dependent early returns."""
    if not a or not b:
        return False
    return hmac.compare_digest(a, b)
