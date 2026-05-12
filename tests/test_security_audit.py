"""Regression tests for the quick-win security remediations shipped in
UF-209 (DISA STIG V5R3 / NIST 800-53 r5 audit).

Each test pins a single behavioural property of the quick-win so a
future refactor that re-introduces the vulnerable pattern fails CI.
"""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
PY_ROOT = REPO_ROOT / "src" / "python"
sys.path.insert(0, str(PY_ROOT))

from adf import _security as security  # noqa: E402
from adf.event import Event  # noqa: E402


@pytest.fixture(autouse=True)
def clear_security_env(monkeypatch):
    monkeypatch.delenv("ADF_ALLOW_PICKLE_NET", raising=False)
    monkeypatch.delenv("ADF_ALLOW_EXEC", raising=False)
    monkeypatch.delenv("ADF_MAX_PAYLOAD_BYTES", raising=False)
    yield


# ---------------------------------------------------------------------------
# F-001 / F-003 / F-004 / F-005 / F-017: env-var security gates
# ---------------------------------------------------------------------------

def test_f001_pickle_gate_default_off():
    """F-001: pickle.loads of network bytes is refused unless the operator
    opted in via ``ADF_ALLOW_PICKLE_NET=1``."""
    assert security.allow_pickle_net() is False


def test_f001_pickle_gate_on_when_enabled(monkeypatch):
    monkeypatch.setenv("ADF_ALLOW_PICKLE_NET", "1")
    assert security.allow_pickle_net() is True


def test_f004_exec_gate_default_off():
    """F-004 / F-005: dynamic exec/eval refused unless ADF_ALLOW_EXEC=1."""
    assert security.allow_exec() is False


def test_f004_exec_gate_on_when_enabled(monkeypatch):
    monkeypatch.setenv("ADF_ALLOW_EXEC", "1")
    assert security.allow_exec() is True


def test_f017_max_payload_default_is_64_mib():
    """F-017: incoming length-prefixed payload is clamped to 64 MiB
    unless the operator overrides it."""
    assert security.max_payload_bytes() == 64 * 1024 * 1024


def test_f017_max_payload_override(monkeypatch):
    monkeypatch.setenv("ADF_MAX_PAYLOAD_BYTES", "1048576")
    assert security.max_payload_bytes() == 1024 * 1024


def test_f005_event_eval_refused_by_default():
    """F-005: ``Event.eval`` returns None instead of evaluating an
    operator-supplied expression when ADF_ALLOW_EXEC is unset."""
    e = Event("t", value=2)
    assert e.eval("value + 1") is None


def test_f005_event_eval_runs_when_explicitly_enabled(monkeypatch):
    monkeypatch.setenv("ADF_ALLOW_EXEC", "1")
    e = Event("t", value=2)
    assert e.eval("value + 1") == 3


# ---------------------------------------------------------------------------
# F-002: state-file permissions
# ---------------------------------------------------------------------------

def test_f002_world_writable_state_file_refused(tmp_path):
    """F-002: ``ensure_state_file_safe`` raises PermissionError when the
    state file is world-writable (matches what framework.load_state does
    before unpickling)."""
    p = tmp_path / "state.pkl"
    p.write_bytes(b"x")
    p.chmod(0o666)
    with pytest.raises(PermissionError):
        security.ensure_state_file_safe(str(p))


def test_f002_secure_state_file_after_write(tmp_path):
    p = tmp_path / "state.pkl"
    p.write_bytes(b"x")
    p.chmod(0o644)
    security.secure_state_file_after_write(str(p))
    mode = p.stat().st_mode & 0o777
    assert mode == 0o600, "state file must be 0o600 after save (F-002)"


# ---------------------------------------------------------------------------
# F-003: dynamic ``eval('self.'+method)`` removed in IPC dispatch
# ---------------------------------------------------------------------------

def test_f003_no_eval_self_in_ipc_dispatch():
    """F-003: framework.py and plugin.py must not call
    ``eval('self.'+...)`` for IPC dispatch."""
    bad = re.compile(r"eval\(\s*['\"]self\.['\"]\s*\+")
    for fname in ("framework.py", "plugin.py"):
        text = (PY_ROOT / "adf" / fname).read_text()
        non_comment = "\n".join(
            ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))
        assert not bad.search(non_comment), (
            f"{fname}: eval('self.'+...) IPC dispatch must be replaced "
            "with getattr (F-003)")


# ---------------------------------------------------------------------------
# F-006 / F-021: subprocess shell=False everywhere we still spawn
# ---------------------------------------------------------------------------

def test_f006_canbus_does_not_use_os_system():
    """F-006: the CAN test harness must not use ``os.system``."""
    text = (PY_ROOT / "adf" / "canbus" / "__init__.py").read_text()
    non_comment = "\n".join(
        ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))
    assert "os.system(" not in non_comment, (
        "canbus/__init__.py: os.system( reintroduced (F-006)")
    assert "subprocess.run(" in text


def test_f021_setup_uses_shell_false():
    """F-021: ``setup.py`` must build bpf_tap with ``shell=False``."""
    text = (REPO_ROOT / "setup.py").read_text()
    assert "shell=True" not in text, "F-021: shell=True reintroduced"
    assert "shell=False" in text


# ---------------------------------------------------------------------------
# F-007: bpf_tap command allowlist
# ---------------------------------------------------------------------------

def test_f007_bpf_tap_command_allowlisted():
    text = (PY_ROOT / "adf" / "plugins" / "bpf_tap.py").read_text()
    assert "_BPF_TAP_COMMAND_ALLOWLIST" in text
    assert "shell=False" in text


# ---------------------------------------------------------------------------
# F-008: TLS defaults (CERT_REQUIRED + TLSv1.2 minimum)
# ---------------------------------------------------------------------------

def test_f008_event_listener_tls_defaults():
    text = (PY_ROOT / "adf" / "event.py").read_text()
    assert "ssl.CERT_REQUIRED" in text, (
        "F-008: Event listener/sender must default to ssl.CERT_REQUIRED")
    assert "TLSVersion.TLSv1_2" in text, (
        "F-008: Event listener/sender must default to TLSv1_2 minimum")


def test_f008_framework_control_tls_defaults():
    text = (PY_ROOT / "adf" / "framework.py").read_text()
    assert "ssl.CERT_REQUIRED" in text
    assert "TLSVersion.TLSv1_2" in text


# ---------------------------------------------------------------------------
# F-009: MQTT TLS + auth knobs
# ---------------------------------------------------------------------------

def test_f009_mqtt_has_tls_and_auth_knobs():
    text = (PY_ROOT / "adf" / "canbus" / "mqtt.py").read_text()
    assert "tls_set(" in text, "F-009: MQTT must call tls_set() when tls=1"
    assert "username_pw_set" in text, (
        "F-009: MQTT must call username_pw_set when username configured")
    # warning when running without TLS
    assert "without TLS" in text


# ---------------------------------------------------------------------------
# F-011: CSPRNG for TCP ISN
# ---------------------------------------------------------------------------

def test_f011_tcp_isn_uses_secrets():
    text = (PY_ROOT / "adf" / "plugins" / "tcp.py").read_text()
    assert "import secrets" in text
    assert "random.randint" not in text, (
        "F-011: random.randint must not be used for TCP ISN")
    assert "secrets.randbelow" in text


# ---------------------------------------------------------------------------
# F-012 / F-013 / F-014 / F-015: C memory-safety
# ---------------------------------------------------------------------------

C_SRC = (REPO_ROOT / "src" / "bpf_tap.c").read_text()


def test_f012_no_strcpy_in_c():
    """F-012/13/14: strcpy must be replaced with bounded strncpy."""
    assert "strcpy(" not in C_SRC, (
        "F-012: strcpy(...) found in bpf_tap.c; use strncpy + NUL term")


def test_f013_strncpy_has_explicit_nul_termination():
    """F-013: each strncpy site explicitly NUL-terminates the buffer."""
    nul_term_count = C_SRC.count("[IFNAMSIZ - 1] = '\\0'")
    nul_term_count += C_SRC.count("[sizeof(filter_file) - 1] = '\\0'")
    assert nul_term_count >= 2, (
        "F-013/14: every strncpy site must explicitly NUL-terminate "
        "(found %d)" % nul_term_count)


def test_f015_calloc_and_fread_returns_checked():
    """F-015: calloc and fread return values must be checked in
    read_file()."""
    assert "if (!*buffer)" in C_SRC
    assert "fread(*buffer, size, 1, fp) != 1" in C_SRC


# ---------------------------------------------------------------------------
# F-018: bare ``except:`` narrowed in security-sensitive sites
# ---------------------------------------------------------------------------

def test_f018_event_listener_narrowed_excepts():
    """F-018: the network handlers in event.py must not use bare
    ``except:`` (they would swallow injection / deserialization errors)."""
    text = (PY_ROOT / "adf" / "event.py").read_text()
    in_listener = False
    in_handler = False
    bad_lines = []
    for i, line in enumerate(text.splitlines(), start=1):
        if "class Listener" in line:
            in_listener = True
        if "class Sender" in line or "class Channel" in line:
            in_listener = False
        if in_listener and "def handle" in line:
            in_handler = True
        if in_listener and in_handler and re.search(r"^\s+except:\s*$", line):
            bad_lines.append(i)
    assert not bad_lines, (
        "F-018: bare except: still present in Listener handlers at: %s"
        % bad_lines)


# ---------------------------------------------------------------------------
# F-019: Sender propagates socket timeout
# ---------------------------------------------------------------------------

def test_f019_sender_propagates_timeout():
    text = (PY_ROOT / "adf" / "event.py").read_text()
    assert "settimeout(self.timeout)" in text, (
        "F-019: Sender must propagate self.timeout onto its socket")


# ---------------------------------------------------------------------------
# F-025: diskcache version floor
# ---------------------------------------------------------------------------

def test_f025_diskcache_min_version_floor():
    text = (REPO_ROOT / "setup.py").read_text()
    assert "diskcache>=5.6.4" in text, (
        "F-025: diskcache>=5.6.4 floor missing from setup.py")
