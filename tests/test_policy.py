from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timedelta, timezone

import pytest

from minas_auditor.policy import ensure_public_target, verify_authorization


def test_authorization_requires_key(tmp_path, monkeypatch):
    monkeypatch.delenv("MINAS_AUTHORIZATION_KEY", raising=False)
    allowed, reason = verify_authorization(tmp_path / "missing.json", "example.com")
    assert not allowed
    assert "not set" in reason


def test_signed_authorization_is_domain_and_scope_bound(tmp_path, monkeypatch):
    key = "test-only-owner-key"
    document = {
        "owner": "Example LLC",
        "domains": ["example.com"],
        "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        "scope": ["owner_approved_security_headers"],
    }
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    document["signature"] = hmac.new(key.encode(), canonical, hashlib.sha256).hexdigest()
    path = tmp_path / "authorization.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    monkeypatch.setenv("MINAS_AUTHORIZATION_KEY", key)

    allowed, _ = verify_authorization(path, "www.example.com")
    outside, reason = verify_authorization(path, "example.net")

    assert allowed
    assert not outside
    assert "outside" in reason


@pytest.mark.asyncio
async def test_private_targets_are_rejected():
    with pytest.raises(ValueError, match="Non-public target"):
        await ensure_public_target("http://127.0.0.1/")

