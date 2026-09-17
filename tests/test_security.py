from __future__ import annotations

from app.redaction import redact_text
from app.security import SecretBox, issue_session_token, verify_session_token


def test_secret_box_round_trip(encryption_key):
    box = SecretBox(encryption_key)
    encrypted = box.encrypt("refresh-secret")
    assert encrypted.startswith("v1:")
    assert box.decrypt(encrypted) == "refresh-secret"
    assert "refresh-secret" not in encrypted


def test_secret_box_json_round_trip(encryption_key):
    box = SecretBox(encryption_key)
    value = {"access_token": "a", "expires_at": 123, "nested": {"ok": True}}
    assert box.decrypt_json(box.encrypt_json(value)) == value


def test_session_token_verification(encryption_key):
    for _ in range(100):
        token = issue_session_token("secret", "admin", 600)
        session = verify_session_token("secret", token)
        assert session is not None
        assert session.subject == "admin"
        assert verify_session_token("wrong", token) is None


def test_redaction_covers_tokens_and_passwords():
    text = '{"access_token":"abc","refresh_token":"def","password":"pw","ok":"yes"}'
    redacted = redact_text(text)
    assert "abc" not in redacted
    assert "def" not in redacted
    assert "pw" not in redacted
    assert '"ok":"yes"' in redacted


def test_redaction_covers_oauth_code_and_state_in_text():
    redacted = redact_text("code=auth-code&state=csrf-state")
    assert "auth-code" not in redacted
    assert "csrf-state" not in redacted


def test_redaction_covers_bearer_and_url_credentials():
    redacted = redact_text("Authorization: Bearer live-token https://user:password@example.test/path")
    assert "live-token" not in redacted
    assert "user:password" not in redacted
    assert "***:***@example.test" in redacted
