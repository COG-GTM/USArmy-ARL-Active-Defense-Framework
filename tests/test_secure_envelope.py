"""Unit tests for ``adf.secure_envelope``.

These tests cover the wire-protocol contract that replaces
``pickle.loads()`` on TCP/SSL/UDP/CAN-IP transports.  They intentionally
avoid network I/O — the security guarantees live in the envelope, not in
the transport plumbing.
"""

import json
import os
import time

import pytest

from adf import secure_envelope as se


SECRET = b"x" * 64


@pytest.fixture(autouse=True)
def _isolate_replay_cache():
    se._seen_nonces.clear()
    yield
    se._seen_nonces.clear()


@pytest.fixture(autouse=True)
def _set_secret(monkeypatch):
    monkeypatch.setenv(se.SECRET_ENV_VAR, SECRET.decode())


def test_wrap_returns_bytes_with_expected_envelope_structure():
    raw = se.wrap({"hello": "world"})
    assert isinstance(raw, bytes)
    env = json.loads(raw.decode("utf-8"))
    assert set(env) == {"alg", "sig", "body"}
    assert env["alg"] == "sha256"
    body = env["body"]
    assert body["v"] == se.ENVELOPE_VERSION
    assert isinstance(body["ts"], int)
    assert isinstance(body["nonce"], str) and len(body["nonce"]) == 32
    assert body["payload"] == {"hello": "world"}


def test_wrap_unwrap_round_trip():
    payload = {"a": 1, "nested": {"b": [1, 2, 3]}, "flag": True}
    raw = se.wrap(payload)
    assert se.unwrap(raw) == payload


def test_wrap_requires_dict_payload():
    with pytest.raises(se.EnvelopeSchemaError):
        se.wrap("not a dict")  # type: ignore[arg-type]


def test_unwrap_rejects_non_json():
    with pytest.raises(se.EnvelopeError):
        se.unwrap(b"not json at all")


def test_unwrap_rejects_non_utf8():
    with pytest.raises(se.EnvelopeError):
        se.unwrap(b"\xff\xfe\xfd")


def test_unwrap_rejects_tampered_signature():
    raw = se.wrap({"x": 1})
    env = json.loads(raw.decode("utf-8"))
    env["sig"] = "0" * 64
    with pytest.raises(se.EnvelopeAuthError):
        se.unwrap(json.dumps(env).encode("utf-8"))


def test_unwrap_rejects_tampered_body():
    raw = se.wrap({"x": 1})
    env = json.loads(raw.decode("utf-8"))
    env["body"]["payload"] = {"x": 2}
    with pytest.raises(se.EnvelopeAuthError):
        se.unwrap(json.dumps(env).encode("utf-8"))


def test_unwrap_rejects_unknown_algorithm():
    raw = se.wrap({"x": 1})
    env = json.loads(raw.decode("utf-8"))
    env["alg"] = "md5"
    with pytest.raises(se.EnvelopeAuthError):
        se.unwrap(json.dumps(env).encode("utf-8"))


def test_unwrap_rejects_wrong_version():
    raw = se.wrap({"x": 1})
    env = json.loads(raw.decode("utf-8"))
    env["body"]["v"] = 99
    # version is inside the body so re-sign against the same secret
    body_bytes = json.dumps(env["body"], sort_keys=True, separators=(",", ":")).encode()
    import hashlib
    import hmac
    env["sig"] = hmac.new(SECRET, body_bytes, hashlib.sha256).hexdigest()
    with pytest.raises(se.EnvelopeError):
        se.unwrap(json.dumps(env).encode("utf-8"))


def test_unwrap_rejects_stale_timestamp():
    raw = se.wrap({"x": 1})
    env = json.loads(raw.decode("utf-8"))
    env["body"]["ts"] = int(time.time()) - 99999
    body_bytes = json.dumps(env["body"], sort_keys=True, separators=(",", ":")).encode()
    import hashlib
    import hmac
    env["sig"] = hmac.new(SECRET, body_bytes, hashlib.sha256).hexdigest()
    with pytest.raises(se.EnvelopeStaleError):
        se.unwrap(json.dumps(env).encode("utf-8"))


def test_unwrap_rejects_replay():
    raw = se.wrap({"x": 1})
    se.unwrap(raw)
    with pytest.raises(se.EnvelopeReplayError):
        se.unwrap(raw)


def test_missing_secret_raises(monkeypatch):
    monkeypatch.delenv(se.SECRET_ENV_VAR, raising=False)
    with pytest.raises(se.EnvelopeError):
        se.wrap({"x": 1})
    with pytest.raises(se.EnvelopeError):
        se.unwrap(b"{}")


def test_short_secret_raises(monkeypatch):
    monkeypatch.setenv(se.SECRET_ENV_VAR, "short")
    with pytest.raises(se.EnvelopeError):
        se.wrap({"x": 1})


def test_explicit_secret_overrides_env(monkeypatch):
    monkeypatch.delenv(se.SECRET_ENV_VAR, raising=False)
    raw = se.wrap({"x": 1}, secret=SECRET)
    assert se.unwrap(raw, secret=SECRET) == {"x": 1}


def test_schema_violation_on_wrap():
    schema = {
        "type": "object",
        "required": ["count"],
        "properties": {"count": {"type": "integer"}},
    }
    with pytest.raises(se.EnvelopeSchemaError):
        se.wrap({"count": "not-an-int"}, schema=schema)


def test_schema_violation_on_unwrap_with_strict_schema():
    payload = {"count": 1, "extra": "ok"}
    raw = se.wrap(payload)
    strict_schema = {
        "type": "object",
        "required": ["count"],
        "properties": {"count": {"type": "integer"}},
        "additionalProperties": False,
    }
    with pytest.raises(se.EnvelopeSchemaError):
        se.unwrap(raw, schema=strict_schema)


def test_event_round_trip():
    from adf.event import Event
    e = Event("plugin.foo", sync=True, alpha=1, beta="two")
    e.path = ["sender", "router"]
    raw = se.wrap_event(e)
    decoded = se.unwrap_event(raw)
    assert decoded.name == "plugin.foo"
    assert decoded.sync is True
    assert decoded.path == ["sender", "router"]
    assert decoded["alpha"] == 1
    assert decoded["beta"] == "two"


def test_event_payload_rejects_unexpected_top_level_key():
    raw = se.wrap({"name": "x", "path": [], "sync": False, "data": {}, "extra": 1})
    with pytest.raises(se.EnvelopeSchemaError):
        se.unwrap(raw, schema=se.EVENT_SCHEMA)


def test_replay_cache_purges_old_entries():
    raw = se.wrap({"x": 1})
    se.unwrap(raw)
    assert len(se._seen_nonces) == 1
    # advance the cache's internal sense of time and ensure purge works
    nonce = next(iter(se._seen_nonces))
    se._seen_nonces[nonce] = int(time.time()) - se._REPLAY_WINDOW_SEC - 10
    se._purge_seen(int(time.time()))
    assert se._seen_nonces == {}
