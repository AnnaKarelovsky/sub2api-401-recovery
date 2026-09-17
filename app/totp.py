from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import struct
import time
import urllib.parse


class TOTPError(ValueError):
    pass


def normalize_totp_secret(value: str) -> str:
    raw = str(value or "").strip()
    if raw.lower().startswith("otpauth://"):
        query = urllib.parse.parse_qs(urllib.parse.urlparse(raw).query)
        raw = (query.get("secret") or [""])[0]
    normalized = "".join(char for char in raw.upper() if char.isalnum())
    if not normalized:
        raise TOTPError("TOTP secret is empty")
    try:
        base64.b32decode(normalized + "=" * (-len(normalized) % 8), casefold=True)
    except (binascii.Error, ValueError) as exc:
        raise TOTPError("TOTP secret is not valid base32") from exc
    return normalized


def totp_code(secret: str, *, timestamp: int | None = None, digits: int = 6, period: int = 30) -> str:
    normalized = normalize_totp_secret(secret)
    if digits not in (6, 8) or period <= 0:
        raise TOTPError("unsupported TOTP parameters")
    key = base64.b32decode(normalized + "=" * (-len(normalized) % 8), casefold=True)
    counter = int((timestamp if timestamp is not None else time.time()) // period)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    number = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(number % (10**digits)).zfill(digits)
