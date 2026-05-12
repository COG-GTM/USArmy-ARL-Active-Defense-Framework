"""DISA STIG V5R3 + NIST 800-53 r5 compliance assertions for the
USArmy-ARL Active-Defense Framework.

These tests run a static codebase scan to confirm we have not
re-introduced the patterns we audited away in UF-209. Each test maps to
a STIG/NIST control. Tests are deliberately fast and dependency-free so
they can run on every CI commit.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
PY_ROOT = REPO_ROOT / "src" / "python"


def _python_files():
    return [
        p for p in PY_ROOT.rglob("*.py")
        if not p.name.startswith("__pycache__")
    ]


def _read(p):
    return p.read_text()


PY_FILES = _python_files()


# ---------------------------------------------------------------------------
# IA-5 / V-222575: no hardcoded credentials, tokens, private keys
# ---------------------------------------------------------------------------

HARDCODED_PATTERNS = [
    re.compile(r"password\s*=\s*['\"][^'\"]{4,}['\"]", re.IGNORECASE),
    re.compile(r"api[_-]?key\s*=\s*['\"][^'\"]{8,}['\"]", re.IGNORECASE),
    re.compile(r"secret\s*=\s*['\"][^'\"]{8,}['\"]", re.IGNORECASE),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
]


def test_ia5_no_hardcoded_credentials():
    """IA-5 / V-222575: scan repo for hardcoded creds / private keys."""
    hits = []
    for p in PY_FILES:
        text = _read(p)
        # tolerate the canonical "password = None" plugin-config default
        text_for_scan = re.sub(
            r"password\s*=\s*None", "", text, flags=re.IGNORECASE)
        for pat in HARDCODED_PATTERNS:
            for m in pat.finditer(text_for_scan):
                hits.append((str(p.relative_to(REPO_ROOT)), m.group(0)))
    assert not hits, (
        "IA-5: hardcoded credential pattern detected: %s" % hits)


# ---------------------------------------------------------------------------
# SI-10 / V-222607: no unguarded eval('self.'+...) dynamic dispatch
# ---------------------------------------------------------------------------

def test_si10_no_dynamic_self_dispatch_eval():
    """SI-10: must not use ``eval('self.'+method)`` for IPC dispatch
    (use ``getattr`` instead, F-003)."""
    bad = re.compile(r"eval\(\s*['\"]self\.['\"]\s*\+")
    hits = []
    for p in PY_FILES:
        for line_no, line in enumerate(_read(p).splitlines(), start=1):
            stripped = line.lstrip()
            if stripped.startswith("#"):
                continue  # explanatory comments may quote the bad pattern
            if bad.search(line):
                hits.append("%s:%d" % (p.relative_to(REPO_ROOT), line_no))
    assert not hits, (
        "SI-10/F-003: eval('self.'+method) reintroduced at %s" % hits)


# ---------------------------------------------------------------------------
# AC-3 / V-222609: no ``shell=True`` subprocess invocation
# ---------------------------------------------------------------------------

def test_ac3_no_shell_true_subprocess():
    """AC-3 / V-222609: every subprocess.{run,Popen,call,check_output}
    must use ``shell=False`` to prevent shell injection."""
    bad = re.compile(r"shell\s*=\s*True")
    hits = []
    files_to_check = list(PY_FILES) + [REPO_ROOT / "setup.py"]
    for p in files_to_check:
        if not p.exists():
            continue
        for line_no, line in enumerate(_read(p).splitlines(), start=1):
            stripped = line.lstrip()
            if stripped.startswith("#"):
                continue
            if bad.search(line):
                hits.append("%s:%d" % (p.relative_to(REPO_ROOT), line_no))
    assert not hits, "AC-3: shell=True reintroduced at %s" % hits


# ---------------------------------------------------------------------------
# AC-3 / V-222609: no ``os.system`` calls
# ---------------------------------------------------------------------------

def test_ac3_no_os_system_calls():
    """AC-3 / V-222609: ``os.system`` provides direct shell access and
    must not be used."""
    bad = re.compile(r"\bos\.system\s*\(")
    hits = []
    for p in PY_FILES:
        for line_no, line in enumerate(_read(p).splitlines(), start=1):
            stripped = line.lstrip()
            if stripped.startswith("#"):
                continue
            if bad.search(line):
                hits.append("%s:%d" % (p.relative_to(REPO_ROOT), line_no))
    assert not hits, "AC-3: os.system reintroduced at %s" % hits


# ---------------------------------------------------------------------------
# SC-8 / V-222563: TLS verification + TLS 1.2 minimum
# ---------------------------------------------------------------------------

def test_sc8_event_module_defaults_to_cert_required():
    """SC-8 / V-222563: any ssl.SSLContext we hand to the event listener,
    sender, or control server must default to ``CERT_REQUIRED`` and
    ``TLSv1_2`` minimum (F-008)."""
    for name in ("event.py", "framework.py"):
        text = _read(PY_ROOT / "adf" / name)
        assert "ssl.CERT_REQUIRED" in text, (
            "SC-8/F-008: %s does not pin CERT_REQUIRED" % name)
        assert "TLSv1_2" in text, (
            "SC-8/F-008: %s does not pin TLSv1.2 minimum" % name)


# ---------------------------------------------------------------------------
# SC-13 / V-222542: no MD5/SHA1 hashes used for security
# ---------------------------------------------------------------------------

def test_sc13_no_md5_sha1_for_security():
    """SC-13: any MD5/SHA1 usage in non-security contexts must explicitly
    pass ``usedforsecurity=False`` (FIPS-mode safe)."""
    bad = re.compile(r"hashlib\.(md5|sha1)\(")
    safe = re.compile(r"hashlib\.(md5|sha1)\([^)]*usedforsecurity\s*=\s*False")
    hits = []
    for p in PY_FILES:
        for line_no, line in enumerate(_read(p).splitlines(), start=1):
            if bad.search(line) and not safe.search(line):
                hits.append("%s:%d" % (p.relative_to(REPO_ROOT), line_no))
    assert not hits, (
        "SC-13: MD5/SHA1 used without usedforsecurity=False at %s" % hits)


# ---------------------------------------------------------------------------
# SI-10 / V-222608: pickle.loads of network bytes must be gated
# ---------------------------------------------------------------------------

def test_si10_pickle_loads_is_gated_in_network_paths():
    """SI-10: every pickle.loads(...) call against bytes coming off the
    wire must be guarded by ``security.allow_pickle_net()``
    (F-001 gate)."""
    network_modules = [
        PY_ROOT / "adf" / "event.py",
        PY_ROOT / "adf" / "canbus" / "IBP.py",
    ]
    for p in network_modules:
        text = _read(p)
        if "pickle.loads(" not in text:
            continue
        assert "allow_pickle_net" in text, (
            "SI-10/F-001: %s loads pickle from the network without "
            "guarding it with security.allow_pickle_net()" % p)


# ---------------------------------------------------------------------------
# SI-10 / V-222608: exec/eval refused unless ADF_ALLOW_EXEC=1
# ---------------------------------------------------------------------------

def test_si10_exec_eval_paths_are_gated():
    """SI-10/F-004: ``exec_plugin``, ``eval_packet``, ``exec_packet``,
    and ``Event.eval`` must all consult the ``security.allow_exec()``
    gate before running operator-supplied code."""
    text = _read(PY_ROOT / "adf" / "framework.py")
    assert "allow_exec" in text, (
        "F-004: exec_plugin must consult security.allow_exec()")
    text = _read(PY_ROOT / "adf" / "plugin.py")
    assert text.count("allow_exec") >= 2, (
        "F-004/F-005: eval_packet AND exec_packet must consult "
        "security.allow_exec()")
    text = _read(PY_ROOT / "adf" / "event.py")
    assert "allow_exec" in text, (
        "F-005: Event.eval must consult security.allow_exec()")


# ---------------------------------------------------------------------------
# SC-7 / V-222428: MQTT control channel supports TLS + auth
# ---------------------------------------------------------------------------

def test_sc7_mqtt_supports_tls_auth_knobs():
    """SC-7 / F-009: the MQTT plugins expose ``tls`` and ``username``
    configuration so an operator can run them with TLS + auth."""
    text = _read(PY_ROOT / "adf" / "canbus" / "mqtt.py")
    assert "tls_set(" in text
    assert "username_pw_set" in text


# ---------------------------------------------------------------------------
# AU-2 / V-222423: warning log emitted when running with gates open
# ---------------------------------------------------------------------------

def test_au2_security_warnings_logged():
    """AU-2: when an operator opens a security gate, the framework logs
    a WARNING line so the open posture is auditable."""
    text = _read(PY_ROOT / "adf" / "_security.py")
    assert ".warning(" in text
    assert "ADF_ALLOW_PICKLE_NET" in text
    assert "ADF_ALLOW_EXEC" in text


# ---------------------------------------------------------------------------
# CM-6 / V-222394: state file refuses world-writable mode
# ---------------------------------------------------------------------------

def test_cm6_state_file_refuses_world_writable(tmp_path):
    """CM-6 / F-002: refuse to load a pickled state file that is
    world- or group-writable."""
    import sys
    sys.path.insert(0, str(PY_ROOT))
    from adf import _security as security
    p = tmp_path / "state.pkl"
    p.write_bytes(b"x")
    p.chmod(0o646)
    with pytest.raises(PermissionError):
        security.ensure_state_file_safe(str(p))


# ---------------------------------------------------------------------------
# SC-12 / V-222575: CSPRNG used for TCP ISN
# ---------------------------------------------------------------------------

def test_sc12_csprng_used_for_tcp_isn():
    """SC-12 / F-011: the fake TCP stack must use a CSPRNG (``secrets``
    module) for its initial sequence number."""
    text = _read(PY_ROOT / "adf" / "plugins" / "tcp.py")
    assert "import secrets" in text
    assert "secrets.randbelow" in text
    assert "random.randint" not in text


# ---------------------------------------------------------------------------
# SI-11 / V-222594: no bare ``except:`` in network handlers
# ---------------------------------------------------------------------------

def test_si11_no_bare_except_in_listener_handlers():
    """SI-11: bare ``except:`` in security-sensitive network code paths
    would swallow deserialization / injection errors and prevent the
    audit log from recording them (F-018)."""
    text = _read(PY_ROOT / "adf" / "event.py")
    # Listener.main + SSL handler + Channel.flush should not have bare
    # except: any longer.
    in_listener = False
    in_handler = False
    bad_lines = []
    for i, line in enumerate(text.splitlines(), start=1):
        if "class Listener" in line:
            in_listener = True
        if "class Sender" in line:
            in_listener = False
        if in_listener and "def main" in line:
            in_handler = True
        if in_listener and in_handler and re.search(r"^\s+except:\s*$", line):
            bad_lines.append(i)
    assert not bad_lines, (
        "SI-11/F-018: bare except: in Listener handlers at %s" % bad_lines)


# ---------------------------------------------------------------------------
# AC-7 / SC-7: control server warns when run without TLS on non-loopback
# ---------------------------------------------------------------------------

def test_ac7_control_server_warns_when_no_tls_on_non_loopback():
    """AC-7 / F-010: framework.start_control must warn when it binds a
    non-loopback address without TLS so operators don't accidentally
    expose an unauthenticated control plane."""
    text = _read(PY_ROOT / "adf" / "framework.py")
    assert "without TLS" in text, (
        "F-010: start_control must warn when binding non-loopback "
        "without TLS")


# ---------------------------------------------------------------------------
# SA-22: dependency floor for vulnerable diskcache transitive
# ---------------------------------------------------------------------------

def test_sa22_diskcache_floor_pinned():
    """SA-22 / F-025: setup.py pins ``diskcache>=5.6.4`` to keep clear
    of the vulnerable transitive version pulled by ``cantools``."""
    text = (REPO_ROOT / "setup.py").read_text()
    assert "diskcache>=5.6.4" in text


# ---------------------------------------------------------------------------
# SI-10: C buffers bounded
# ---------------------------------------------------------------------------

def test_si10_c_no_strcpy():
    """SI-10 / F-012-14: the C BPF tap must not use strcpy (use
    strncpy + explicit NUL termination)."""
    src = (REPO_ROOT / "src" / "bpf_tap.c").read_text()
    assert "strcpy(" not in src


def test_si10_c_calloc_and_fread_checked():
    """SI-10 / F-015: ``read_file`` must validate calloc and fread."""
    src = (REPO_ROOT / "src" / "bpf_tap.c").read_text()
    assert "if (!*buffer)" in src
    assert "fread(*buffer, size, 1, fp) != 1" in src


# ---------------------------------------------------------------------------
# SI-10 / V-222607: oversized incoming payloads dropped
# ---------------------------------------------------------------------------

def test_si10_payload_size_enforced_in_event_listener():
    """SI-10 / F-017: the Event listener must clamp incoming
    length-prefixed payloads to ``security.max_payload_bytes()`` before
    reading further bytes."""
    text = _read(PY_ROOT / "adf" / "event.py")
    assert "max_payload_bytes" in text, (
        "F-017: Listener must clamp incoming payload size")


def test_si10_payload_size_enforced_in_ibp():
    """SI-10 / F-017: the IBP CAN-over-IP handler must drop oversized
    reassembled payloads before unpickling."""
    text = _read(PY_ROOT / "adf" / "canbus" / "IBP.py")
    assert "max_payload_bytes" in text


# ---------------------------------------------------------------------------
# CM-6: BPF allowlist enforced for spawned commands
# ---------------------------------------------------------------------------

def test_cm6_bpf_tap_allowlist_enforced():
    """CM-6 / F-007: the bpf_tap plugin allowlists the helper command
    it spawns rather than execing whatever string the operator wrote."""
    text = _read(PY_ROOT / "adf" / "plugins" / "bpf_tap.py")
    assert "_BPF_TAP_COMMAND_ALLOWLIST" in text
    assert "shell=False" in text


# ---------------------------------------------------------------------------
# AU-9: docs/security-audit reports shipped with the codebase
# ---------------------------------------------------------------------------

def test_au9_audit_reports_present():
    """AU-9: SECURITY_AUDIT_REPORT.md + TRIAGE_REPORT.md are checked in
    so future contributors can see why each guard exists."""
    base = REPO_ROOT / "docs" / "security-audit"
    assert (base / "SECURITY_AUDIT_REPORT.md").exists()
    assert (base / "TRIAGE_REPORT.md").exists()
