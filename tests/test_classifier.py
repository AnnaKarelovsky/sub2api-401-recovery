from app.classifier import FailureClass, classify_account_snapshot, classify_failure


def test_explicit_401_is_recoverable():
    result = classify_failure(http_status=401, message="token_revoked")
    assert result.category == FailureClass.AUTH_FAILURE
    assert result.recoverable


def test_invalid_grant_requires_reauthorization():
    result = classify_failure(message="oauth token refresh failed: invalid_grant")
    assert result.category == FailureClass.AUTH_FAILURE
    assert result.needs_reauthorization


def test_non_auth_errors_are_not_queued_as_401():
    assert classify_failure(http_status=429, message="rate limit").category == FailureClass.RATE_LIMIT
    assert classify_failure(http_status=403, message="forbidden").category == FailureClass.PERMISSION
    assert classify_failure(message="proxy timeout").category == FailureClass.NETWORK


def test_generic_error_status_does_not_become_auth_failure():
    result = classify_account_snapshot({"id": 1, "status": "error", "error_message": "database unavailable"})
    assert result is not None
    assert result.category == FailureClass.UNKNOWN


def test_deactivated_workspace_is_a_non_recoverable_account_error():
    result = classify_account_snapshot(
        {"id": 292, "status": "error", "error_message": '{"code":"deactivated_workspace"}'}
    )
    assert result is not None
    assert result.category == FailureClass.ACCOUNT_ERROR
    assert result.reason == "Sub2API workspace is deactivated"
    assert not result.recoverable


def test_expiry_accepts_rfc3339_string():
    result = classify_account_snapshot(
        {"id": 1, "status": "active", "credentials": {"expires_at": "2000-01-01T00:00:00Z"}}
    )
    assert result is not None
    assert result.category == FailureClass.AUTH_FAILURE


def test_snapshot_reads_nested_oauth_error_and_upstream_status():
    result = classify_account_snapshot(
        {
            "id": 1,
            "status": "active",
            "http_status": 502,
            "error": {"status_code": 401, "message": "upstream token rejected"},
        }
    )
    assert result is not None
    assert result.category == FailureClass.AUTH_FAILURE


def test_snapshot_reads_explicit_oauth_error_without_generic_error_status():
    result = classify_account_snapshot(
        {"id": 1, "status": "active", "oauth_error": "invalid_grant"}
    )
    assert result is not None
    assert result.category == FailureClass.AUTH_FAILURE
    assert result.needs_reauthorization
