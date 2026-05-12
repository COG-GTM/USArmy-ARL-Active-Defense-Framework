"""Security gates centralised so the same env-var policy applies everywhere.

These gates are quick-win mitigations for finding F-001 / F-003 / F-004 / F-005
in the security audit (`docs/security-audit/SECURITY_AUDIT_REPORT.md`).

The full structural fixes (replacing the pickle wire format, removing the
``exec`` control command, swapping ``eval`` for a restricted DSL) are tracked
under the F-*-FOLLOWUP Jira sub-tasks of Epic UF-209.
"""

from __future__ import annotations

import logging
import os
import threading

# 64 MiB upper bound on the length-prefixed payload that Listener/Channel will
# accept from a network peer (F-017). Operators can raise it via env var when
# they know what they're doing.
DEFAULT_MAX_PAYLOAD_BYTES = 64 * 1024 * 1024


_logger = logging.getLogger('adf.security')
_warned_pickle_net = False
_warned_exec = False
_warn_lock = threading.Lock()


def _env_truthy(name: str) -> bool:
    """Return ``True`` if ``$name`` is set to an opt-in value."""
    val = os.environ.get(name, '').strip().lower()
    return val in ('1', 'true', 'yes', 'on')


def allow_pickle_net() -> bool:
    """Return ``True`` if untrusted-pickle deserialisation over the network is
    explicitly enabled by the operator.

    Default is ``False``. When ``True``, the audit-relevant gate emits a one-
    time WARN log so a SIEM can capture the opt-in (NIST AU-2). Mitigates
    finding F-001 / F-023 / F-030.
    """
    enabled = _env_truthy('ADF_ALLOW_PICKLE_NET')
    if enabled:
        global _warned_pickle_net
        with _warn_lock:
            if not _warned_pickle_net:
                _logger.warning(
                    'ADF_ALLOW_PICKLE_NET=1: network-driven pickle.loads '
                    'is enabled. This exposes the framework to '
                    'unauthenticated remote code execution from any peer '
                    'reaching the Listener/Channel/IBP sockets. Use only '
                    'on isolated networks. See Jira UF-209 / F-001.')
                _warned_pickle_net = True
    return enabled


def allow_exec() -> bool:
    """Return ``True`` if dynamic ``exec``/``eval`` of operator-supplied
    plugin code is explicitly enabled.

    Default is ``False``. Mitigates F-004 / F-005 / F-027.
    """
    enabled = _env_truthy('ADF_ALLOW_EXEC')
    if enabled:
        global _warned_exec
        with _warn_lock:
            if not _warned_exec:
                _logger.warning(
                    'ADF_ALLOW_EXEC=1: dynamic exec/eval of operator-'
                    'supplied plugin code is enabled. Anyone with access '
                    'to the control plane can now execute arbitrary '
                    'Python in the framework process. See Jira UF-209 / '
                    'F-004 and F-005.')
                _warned_exec = True
    return enabled


def max_payload_bytes() -> int:
    """Return the configured maximum length-prefixed payload size in bytes."""
    raw = os.environ.get('ADF_MAX_PAYLOAD_BYTES')
    if raw:
        try:
            return int(raw)
        except ValueError:
            _logger.warning(
                'ignoring non-integer ADF_MAX_PAYLOAD_BYTES=%r', raw)
    return DEFAULT_MAX_PAYLOAD_BYTES


def ensure_state_file_safe(path: str) -> None:
    """Refuse to load a state file that is group- or world-writable.

    Mitigates F-002. Quick-win complement to the full state-format migration
    tracked in F-002-FOLLOWUP.
    """
    try:
        st = os.stat(path)
    except OSError:
        return  # caller will see the failure when it tries to open
    if st.st_mode & 0o022:
        raise PermissionError(
            "refusing to load state file with group/world-writable "
            "permissions (mode=0o%o): %s" % (st.st_mode & 0o777, path))


def secure_state_file_after_write(path: str) -> None:
    """Tighten state-file permissions to owner read/write only (F-002)."""
    try:
        os.chmod(path, 0o600)
    except OSError as exc:
        _logger.warning('could not chmod state file %s: %s', path, exc)


__all__ = (
    'DEFAULT_MAX_PAYLOAD_BYTES',
    'allow_exec',
    'allow_pickle_net',
    'ensure_state_file_safe',
    'max_payload_bytes',
    'secure_state_file_after_write',
)
