"""HMAC-signed JSON envelope for trusted-network event transport.

Replaces ``pickle.loads()`` over TCP/SSL/UDP/CAN-IP transports
(CWE-502, NIST SI-10/SC-8/SR-3/SR-4, STIG V-220631/V-220632).

The envelope shape is::

    {
      "alg":  "sha256",
      "sig":  "<hex hmac-sha256 of canonical(body)>",
      "body": {
        "v":       1,
        "ts":      <unix seconds>,
        "nonce":   "<hex>",
        "payload": { ... arbitrary JSON object ... }
      }
    }

The shared secret is read from the ``ADF_FRAMEWORK_SECRET`` environment
variable.  The rotation runbook is documented in ``SECURITY.md``.

Failures during ``unwrap`` raise :class:`EnvelopeError` (or a subclass).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time
from typing import Any, Dict, Optional

try:
    import jsonschema  # type: ignore
    _HAS_JSONSCHEMA = True
except ImportError:  # pragma: no cover - jsonschema is a soft dep
    _HAS_JSONSCHEMA = False


SECRET_ENV_VAR = "ADF_FRAMEWORK_SECRET"
ENVELOPE_VERSION = 1
HMAC_ALGO = "sha256"
NONCE_BYTES = 16
DEFAULT_MAX_AGE_SEC = 300
_REPLAY_WINDOW_SEC = 600
_MIN_SECRET_BYTES = 32

# Bounded in-process replay cache: nonce -> insertion timestamp.
_seen_nonces: Dict[str, int] = {}


class EnvelopeError(Exception):
    """Base error for ``secure_envelope`` (NIST SI-11: do not leak detail)."""


class EnvelopeAuthError(EnvelopeError):
    """HMAC verification failed or signature/algorithm is malformed."""


class EnvelopeStaleError(EnvelopeError):
    """Envelope timestamp is outside the acceptable window."""


class EnvelopeReplayError(EnvelopeError):
    """Envelope nonce was already consumed in this process."""


class EnvelopeSchemaError(EnvelopeError):
    """Payload failed the caller-supplied JSON schema."""


def _get_secret(secret: Optional[bytes] = None) -> bytes:
    if secret is not None:
        if isinstance(secret, str):
            secret = secret.encode("utf-8")
        if len(secret) < _MIN_SECRET_BYTES:
            raise EnvelopeError(
                "ADF secure_envelope shared secret is too short "
                "(>= %d bytes required)" % _MIN_SECRET_BYTES
            )
        return secret
    raw = os.environ.get(SECRET_ENV_VAR)
    if not raw:
        raise EnvelopeError(
            "%s environment variable is not set; refusing to wrap or "
            "unwrap network payloads (see SECURITY.md rotation runbook)"
            % SECRET_ENV_VAR
        )
    encoded = raw.encode("utf-8")
    if len(encoded) < _MIN_SECRET_BYTES:
        raise EnvelopeError(
            "%s is too short (>= %d bytes required)"
            % (SECRET_ENV_VAR, _MIN_SECRET_BYTES)
        )
    return encoded


def _canonical_bytes(obj: Any) -> bytes:
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _validate_schema(payload: Any, schema: Optional[Dict[str, Any]]) -> None:
    if schema is None:
        return
    if not _HAS_JSONSCHEMA:
        raise EnvelopeSchemaError(
            "jsonschema is required for schema-validated payloads"
        )
    try:
        jsonschema.validate(payload, schema)
    except jsonschema.ValidationError as e:  # type: ignore[attr-defined]
        raise EnvelopeSchemaError("payload failed schema: %s" % e.message) from e


def _purge_seen(now: int) -> None:
    cutoff = now - _REPLAY_WINDOW_SEC
    stale = [n for n, t in _seen_nonces.items() if t < cutoff]
    for n in stale:
        del _seen_nonces[n]


def wrap(
    payload: Dict[str, Any],
    schema: Optional[Dict[str, Any]] = None,
    secret: Optional[bytes] = None,
) -> bytes:
    """Serialize ``payload`` as a signed JSON envelope.

    ``payload`` MUST be a JSON-serializable dict.  ``schema``, if supplied,
    is enforced via ``jsonschema.validate``.  ``secret`` overrides the
    ``ADF_FRAMEWORK_SECRET`` environment variable (intended for tests).
    """
    if not isinstance(payload, dict):
        raise EnvelopeSchemaError("payload must be a dict")
    _validate_schema(payload, schema)
    key = _get_secret(secret)
    body = {
        "v": ENVELOPE_VERSION,
        "ts": int(time.time()),
        "nonce": secrets.token_hex(NONCE_BYTES),
        "payload": payload,
    }
    body_bytes = _canonical_bytes(body)
    sig = hmac.new(key, body_bytes, hashlib.sha256).hexdigest()
    return _canonical_bytes({"alg": HMAC_ALGO, "sig": sig, "body": body})


def unwrap(
    data: bytes,
    schema: Optional[Dict[str, Any]] = None,
    max_age: int = DEFAULT_MAX_AGE_SEC,
    secret: Optional[bytes] = None,
) -> Dict[str, Any]:
    """Verify and decode a signed envelope; return the payload dict.

    Raises a subclass of :class:`EnvelopeError` on any integrity,
    freshness, replay, or schema failure.  Callers MUST treat any
    :class:`EnvelopeError` as a hostile input and drop the connection.
    """
    if isinstance(data, (bytes, bytearray, memoryview)):
        try:
            text = bytes(data).decode("utf-8")
        except UnicodeDecodeError as e:
            raise EnvelopeError("envelope is not valid UTF-8") from e
    elif isinstance(data, str):
        text = data
    else:
        raise EnvelopeError("envelope must be bytes or str")
    try:
        envelope = json.loads(text)
    except (json.JSONDecodeError, ValueError) as e:
        raise EnvelopeError("envelope is not valid JSON") from e
    if not isinstance(envelope, dict):
        raise EnvelopeError("envelope must be a JSON object")
    if envelope.get("alg") != HMAC_ALGO:
        raise EnvelopeAuthError(
            "unsupported envelope alg: %r" % envelope.get("alg")
        )
    body = envelope.get("body")
    sig = envelope.get("sig")
    if not isinstance(body, dict) or not isinstance(sig, str):
        raise EnvelopeAuthError("envelope missing body or sig")
    key = _get_secret(secret)
    expected = hmac.new(key, _canonical_bytes(body), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, sig):
        raise EnvelopeAuthError("HMAC verification failed")
    if body.get("v") != ENVELOPE_VERSION:
        raise EnvelopeError(
            "unsupported envelope version: %r" % body.get("v")
        )
    ts = body.get("ts")
    if not isinstance(ts, int):
        raise EnvelopeError("envelope ts missing or not an int")
    now = int(time.time())
    if abs(now - ts) > max_age:
        raise EnvelopeStaleError(
            "envelope ts %d outside +/- %ds of now (%d)" % (ts, max_age, now)
        )
    nonce = body.get("nonce")
    if not isinstance(nonce, str) or len(nonce) != NONCE_BYTES * 2:
        raise EnvelopeError("envelope nonce missing or malformed")
    _purge_seen(now)
    if nonce in _seen_nonces:
        raise EnvelopeReplayError("envelope nonce already seen")
    _seen_nonces[nonce] = now
    payload = body.get("payload")
    if not isinstance(payload, dict):
        raise EnvelopeSchemaError("payload must be a dict")
    _validate_schema(payload, schema)
    return payload


# ---------------------------------------------------------------------------
# Event helpers
# ---------------------------------------------------------------------------

# JSON schema for the wire form of an ``adf.event.Event``.  The payload
# ``data`` dict is left open by design: per-plugin schemas can be layered
# on top by calling code that already knows the event semantics.
EVENT_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "required": ["name", "path", "sync", "data"],
    "additionalProperties": False,
    "properties": {
        "name": {"type": "string", "maxLength": 256},
        "path": {
            "type": "array",
            "items": {"type": "string", "maxLength": 256},
            "maxItems": 1024,
        },
        "sync": {"type": "boolean"},
        "data": {"type": "object"},
    },
}


def event_to_payload(event: Any) -> Dict[str, Any]:
    """Project an ``adf.event.Event`` instance to a JSON-safe dict."""
    return {
        "name": str(event.name),
        "path": [str(p) for p in event.path],
        "sync": bool(event.sync),
        "data": event.data(),
    }


def payload_to_event(payload: Dict[str, Any]) -> Any:
    """Materialize an ``adf.event.Event`` from an unwrapped payload."""
    from .event import Event  # local import to avoid circular dependency
    e = Event(payload["name"], sync=bool(payload["sync"]))
    e.path = [str(p) for p in payload.get("path", [])]
    data = payload.get("data") or {}
    if data:
        e.update(data)
    return e


def wrap_event(event: Any, secret: Optional[bytes] = None) -> bytes:
    """Convenience wrapper: ``adf.event.Event`` -> signed envelope bytes."""
    return wrap(event_to_payload(event), schema=EVENT_SCHEMA, secret=secret)


def unwrap_event(data: bytes, secret: Optional[bytes] = None) -> Any:
    """Convenience wrapper: signed envelope bytes -> ``adf.event.Event``."""
    return payload_to_event(unwrap(data, schema=EVENT_SCHEMA, secret=secret))
