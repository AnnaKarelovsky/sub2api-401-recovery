from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class SecretBox:
    """Small AES-256-GCM envelope for values persisted in SQLite."""

    def __init__(self, encoded_key: str):
        self.key = self._decode_key(encoded_key)
        self.aead = AESGCM(self.key)

    @staticmethod
    def _decode_key(encoded_key: str) -> bytes:
        value = encoded_key.strip()
        candidates: list[bytes] = []
        try:
            candidates.append(base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)))
        except ValueError:
            pass
        try:
            candidates.append(bytes.fromhex(value))
        except ValueError:
            pass
        for candidate in candidates:
            if len(candidate) == 32:
                return candidate
        raise ValueError("ENCRYPTION_KEY must be a 32-byte base64url or hex key")

    def encrypt(self, value: str) -> str:
        nonce = secrets.token_bytes(12)
        ciphertext = self.aead.encrypt(nonce, value.encode("utf-8"), b"sub2api-recovery")
        payload = base64.urlsafe_b64encode(nonce + ciphertext).decode("ascii").rstrip("=")
        return f"v1:{payload}"

    def decrypt(self, value: str | None) -> str | None:
        if not value:
            return None
        if not value.startswith("v1:"):
            raise ValueError("unsupported encrypted value version")
        payload = value[3:]
        raw = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
        if len(raw) < 13:
            raise ValueError("encrypted value is truncated")
        return self.aead.decrypt(raw[:12], raw[12:], b"sub2api-recovery").decode("utf-8")

    def encrypt_json(self, value: dict[str, Any]) -> str:
        return self.encrypt(json.dumps(value, ensure_ascii=True, separators=(",", ":")))

    def decrypt_json(self, value: str | None) -> dict[str, Any]:
        raw = self.decrypt(value)
        if not raw:
            return {}
        parsed = json.loads(raw)
        if not isinstance(parsed, dict):
            raise ValueError("encrypted JSON payload must be an object")
        return parsed


@dataclass(frozen=True)
class SessionToken:
    subject: str
    expires_at: int


def issue_session_token(secret: str, subject: str, ttl_seconds: int) -> str:
    expires_at = int(time.time()) + max(60, ttl_seconds)
    nonce = secrets.token_urlsafe(12)
    payload = f"{subject}|{expires_at}|{nonce}"
    signature = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).digest()
    encoded_payload = base64.urlsafe_b64encode(payload.encode()).decode().rstrip("=")
    encoded_signature = base64.urlsafe_b64encode(signature).decode().rstrip("=")
    return f"{encoded_payload}.{encoded_signature}"


def verify_session_token(secret: str, token: str) -> SessionToken | None:
    try:
        encoded_payload, encoded_signature = token.split(".", 1)
        payload = base64.urlsafe_b64decode(
            encoded_payload + "=" * (-len(encoded_payload) % 4)
        ).decode("utf-8")
        signature = base64.urlsafe_b64decode(
            encoded_signature + "=" * (-len(encoded_signature) % 4)
        )
        subject, expires_raw, nonce = payload.split("|", 2)
        expected = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(signature, expected) or not nonce:
            return None
        expires_at = int(expires_raw)
        if expires_at <= int(time.time()):
            return None
        return SessionToken(subject=subject, expires_at=expires_at)
    except (ValueError, TypeError, UnicodeDecodeError):
        return None
