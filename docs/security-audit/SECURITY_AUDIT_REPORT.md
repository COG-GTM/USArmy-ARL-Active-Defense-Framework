# Security Audit Report — US Army ARL Active Defense Framework (ADF)

| | |
|---|---|
| **Repository** | [`COG-GTM/USArmy-ARL-Active-Defense-Framework`](https://github.com/COG-GTM/USArmy-ARL-Active-Defense-Framework) |
| **Audit branch** | `devin/1778601139-security-audit` |
| **Audit date** | 2026-05-12 |
| **Compliance scope** | DISA ASD STIG V5R3 + NIST 800-53 r5 |
| **Languages audited** | Python (~6,677 LOC), C (311 LOC `src/bpf_tap.c`) |
| **Playbook** | `fed_security_audit` (Cognition GTM US-Federal) |
| **Parent Devin session** | https://app.devin.ai/sessions/38c740426ca94dc1bc67333853ded7b1 |
| **Jira Epic** | _(filed in Phase 4 — see TRIAGE_REPORT.md)_ |
| **PR** | _(opened in Phase 7 — see PR description for shipped vs deferred split)_ |

## 1. Methodology

Audit executed under playbook `fed_security_audit` (Phase 2 multi-agent orchestration):

- **Child A** — Language-native SAST/SCA/Lint: `bandit`, `pip-audit`, `pylint`, `ruff`, `cppcheck`, `flawfinder`, `clang-tidy`.
- **Child B** — Universal/cross-language SAST + SCA + secrets: `semgrep` (p/owasp-top-ten, p/r2c-security-audit, p/python, p/c), `trivy fs`, `osv-scanner`, `gitleaks`, SonarQube MCP (`analyze_code_snippet`) on high-risk files when reachable.
- **Child C** — Agentic STIG V5R3 / NIST 800-53 r5 manual code review against the playbook control checklist.

Multi-Devin orchestration was attempted via `devin_session_create`; child session creation was pending org approval at the time of consolidation, so the parent session ran the **equivalent tool stack locally** (per playbook section *MCP availability* — *do NOT block the audit waiting for credentials*). Raw tool output is under `docs/security-audit/evidence/`. Findings cite the tool(s) that detected them so the same evidence base would have been produced regardless of orchestration mode.

## 2. Severity counts

| Severity | Count |
|---|---:|
| **Critical** | 7 |
| **High** | 9 |
| **Medium** | 8 |
| **Low** | 6 |
| **Info** | 2 |
| **TOTAL** | **32** |

## 3. Tool execution matrix

| Tool | Scope | Findings raised |
|---|---|---:|
| bandit 1.9.4 | Python SAST | 82 total (1 H / 16 M / 65 L) |
| semgrep (4 rule packs) | Multi-lang SAST | 23 |
| flawfinder 2.0.19 | C SAST | 9 |
| cppcheck (--enable=all) | C SAST | informational style notes only |
| pylint | Python lint/quality | many quality issues (non-security) |
| ruff (S,E,F) | Python lint/security | dup of bandit |
| pip-audit | Python SCA | 1 (`diskcache 5.6.3` CVE-2025-69872, transitive of `cantools`) |
| osv-scanner | Multi-eco SCA | 0 (no lockfile) |
| trivy fs | SCA/secret/IaC | 0 (no Dockerfile, no IaC) |
| gitleaks | Secrets | 0 |
| SonarQube MCP | Cross-lang SAST | _project not registered; analyze_code_snippet attempted on 10 high-risk files; evidence merged_ |

## 4. Findings (de-duplicated across all tools)

> Convention: `[tool1 + tool2]` after each finding lists the scanners that flagged it. STIG control ids reference DISA ASD V5R3; NIST controls reference 800-53 r5.

### F-001 — Untrusted-pickle RCE on TCP/SSL `Listener.handle` and `Channel.flush` (Critical)
**Location:** `src/python/adf/event.py:84,99,252` and `src/python/adf/canbus/IBP.py:217`
**CWE:** CWE-502 (Deserialization of Untrusted Data) · **STIG:** V-222607, V-222609 · **NIST:** SI-10, SC-8
**Tools:** bandit B301 + semgrep `python.lang.security.deserialization.pickle.avoid-pickle` + manual review

```python
# event.py:83-84  (TCP-no-TLS path)
l = struct.unpack('!L', self.request.recv(4))[0]
event = pickle.loads(self.request.recv(l))  # <-- network-driven pickle.loads → arbitrary code execution
```

**Impact:** Any attacker who can reach the Listener's TCP port (default `localhost:42224`, but operators can bind 0.0.0.0) — or who can spoof the UDP `Channel` broadcast (default port 42223), or who can inject CAN-over-IP packets (`IBP`) — gets unauthenticated remote code execution at the privilege level of the framework process (which runs as root for packet I/O). The TLS path on line 84 is no better: `verify=CERT_NONE` is the default (see F-008), so any TLS endpoint can connect and trigger `pickle.loads`.
**Recommended fix:** Replace `pickle` with a length-bounded JSON or msgpack envelope plus an HMAC over the body (rekeyed via deployment-managed secret); refuse messages from peers without a matching HMAC. This is an architectural change — DEFERRED to a follow-up Jira ticket (`F-001-FOLLOWUP`). In the PR, ship a hardening guard: refuse `pickle.loads` unless an explicit opt-in env var `ADF_ALLOW_PICKLE_NET=1` is set, and emit a `WARNING` log every time the guard is bypassed (so operators see the risk in audit logs).

---

### F-002 — Untrusted-pickle RCE on framework state load (Critical)
**Location:** `src/python/adf/framework.py:706` (and the corresponding `pickle.dump` on line 768)
**CWE:** CWE-502 · **STIG:** V-222575 (secret/state mgmt), V-222607 · **NIST:** SI-10, SC-28
**Tools:** bandit B301 + semgrep + manual review

```python
with open(state_file, 'rb') as state_fh:
    state = pickle.load(state_fh)   # <-- arbitrary code execution if state file is tampered
```

**Impact:** Anyone who can write to the framework's state-save file (often a shared NFS/filesystem path) gets RCE at next framework start/restart. Framework runs as root.
**Recommended fix:** DEFER replacement of pickle with JSON-state-shape + HMAC to follow-up. In the PR, set the state file `os.chmod(state_file, 0o600)` after writing and refuse to load a state file whose stat info shows world- or group-writable bits.

---

### F-003 — `eval()` of network-supplied log/config strings (Critical)
**Location:** `src/python/adf/framework.py:159, 238, 358`
**CWE:** CWE-95 (Eval Injection) · **STIG:** V-222609 · **NIST:** SI-10, AC-3
**Tools:** bandit B307 + semgrep `python.lang.security.audit.eval-detected.eval-detected` + manual review

```python
# framework.py:159 (IPC loop)
f = eval('self.'+method)   # <-- method comes from IPC queue, which is fed by the TCP control server
# framework.py:238 (log directive from control channel)
log_config = eval(' '.join(cmd[1:]))   # <-- arbitrary string from control client
```

**Impact:** The TCP control server (`framework.start_control`) parses every line received from a TCP client as a config command. Three of those command paths (`log`, IPC dispatch, and dict-arg parsing) call `eval()` on caller-controlled strings. The control server has **no authentication** unless an SSL config dict is passed at start (and even then, SSL verify defaults to `CERT_NONE` — see F-008). This is RCE-as-a-feature in the current design.
**Recommended fix:** DEFER the structural change (whitelisted dispatch table for control commands; `ast.literal_eval` for dict args) to follow-up Jira ticket `F-003-FOLLOWUP`. In the PR: (a) replace `eval('self.'+method)` with `getattr(self, method)` (this is the IPC dispatch site and `method` is always a method name, so `getattr` is a drop-in) and (b) replace `eval(' '.join(cmd[1:]))` for the `log` dict path with `ast.literal_eval` — `ast.literal_eval` is a drop-in for the documented "dictionary for loading modules" usage and rejects code execution.

---

### F-004 — `exec()` of network-supplied plugin code (Critical)
**Location:** `src/python/adf/framework.py:532` (`exec_plugin`) and `src/python/adf/plugin.py:324` (`exec_packet`)
**CWE:** CWE-94 (Code Injection) · **STIG:** V-222609 · **NIST:** SI-10, AC-3
**Tools:** bandit B102 + semgrep + manual review

```python
# framework.py:529-532
def exec_plugin(self, *code):
    '''Execute code in this context ...'''
    return exec(' '.join(code), globals(), self.__plugins)   # <-- arbitrary Python from control client
```

**Impact:** The `exec <code>` control-server command is documented in `__main__.py` usage as a feature — but for any operator running ADF as a sensor on a non-trusted network, this is unauthenticated RCE. Same observation for `Plugin.exec_packet`, which executes a per-plugin `filter`/`exec` string against incoming packets; if the plugin config is sourced from a network config endpoint, the same risk applies.
**Recommended fix:** DEFER removal-or-gating of the `exec` control command (this is an architecture change and breaks documented behaviour) to follow-up Jira ticket `F-004-FOLLOWUP`. In the PR: gate `exec_plugin` and `Plugin.exec_packet` behind an explicit env var `ADF_ALLOW_EXEC=1` and emit a WARNING log every time it is invoked, so operators see exec-injection events in audit trails (NIST AU-2).

---

### F-005 — `eval()` of attacker-controlled CAN-bus expressions (Critical)
**Location:** `src/python/adf/canbus/j1939.py:264, 285` and `src/python/adf/canbus/profile.py:150`
**CWE:** CWE-95 · **STIG:** V-222609 · **NIST:** SI-10
**Tools:** bandit B307/B102 + semgrep + manual review

```python
# j1939.py:264
p.update(eval(x, globals(), {'data': data}))   # <-- x sourced from J1939 SPN config
# profile.py:150
r = eval(expr, self.__config_cache, stats)     # <-- expr from "*"-keyed config dict
```

**Impact:** If the J1939/profile config can be set or amended via the TCP control plane (`config <plugin> key=value`), an attacker with control-plane access executes arbitrary Python in the plugin process.
**Recommended fix:** Same as F-003: defer the move to `ast.literal_eval` + restricted expression language to follow-up; in the PR add the `ADF_ALLOW_EXEC` gate around `eval_packet`/`exec_packet`/J1939/profile eval sites.

---

### F-006 — `os.system('cansend '+can_if+ ...)` command injection (Critical)
**Location:** `src/python/adf/canbus/__init__.py:264`
**CWE:** CWE-78 (OS Command Injection) · **STIG:** V-222609 · **NIST:** SI-10
**Tools:** bandit B605

```python
for v in range(16):
    system('cansend '+can_if+' %03x' % v+'#%04x' % v)   # <-- can_if is the function arg, joined into a shell command
```

**Impact:** `can_if` (the CAN-bus device name) is concatenated into a shell string. The function is documented as a test harness but the import is unconditional and the function is exported in `__all__`, so any caller passing `"can0; rm -rf ~"` gets command injection. Severity = Critical because `cansend` is normally run as root.
**Recommended fix:** Ship in PR — replace `os.system(...)` with `subprocess.run(['cansend', can_if, '%03x#%04x' % (v, v)], check=False)` (no shell, args as list).

---

### F-007 — `subprocess.Popen(self.command.split())` runs operator-config command (Critical)
**Location:** `src/python/adf/plugins/bpf_tap.py:85`
**CWE:** CWE-78 (Argument Injection) · **STIG:** V-222609 · **NIST:** SI-10
**Tools:** bandit B603

```python
command = 'pkill -HUP bpf_tap'   # default
...
p = subprocess.Popen(self.command.split())   # <-- whatever the operator set in self.command
```

**Impact:** Operator-supplied (and possibly remotely-injected via control plane) `command` is split on whitespace and passed to `subprocess.Popen`. No shell metachar interpretation, but if `command` is fed by attacker-controlled config, arbitrary binaries can be run. Plugin reload is triggered every BPF rule update.
**Recommended fix:** Ship in PR — refuse to run if `self.command` is not equal to a small allowlist of literal commands (default `['pkill', '-HUP', 'bpf_tap']`); log and ignore otherwise.

---

### F-008 — SSL/TLS contexts default to `verify_mode=CERT_NONE` (High)
**Location:** `src/python/adf/event.py:120, 167` (Listener/Sender) and the equivalent block in `src/python/adf/framework.py` control server (`start_control` block)
**CWE:** CWE-295 (Improper Certificate Validation) · **STIG:** V-222563 · **NIST:** SC-8, SC-13
**Tools:** manual review

```python
ctx.verify_mode = self.ssl.get('verify', ssl.VerifyMode.CERT_NONE)
```

**Impact:** Even when the operator enables TLS for the event channel or the control server, peer certificates are not verified unless the operator explicitly sets `verify=CERT_REQUIRED` in the config dict — meaning the documented "TLS mode" provides only confidentiality, not authentication. Combined with F-001 (pickle on the same channel), this makes TLS materially worse than its branding suggests.
**Recommended fix:** Ship in PR — change defaults to `ssl.CERT_REQUIRED` and `ctx.minimum_version = ssl.TLSVersion.TLSv1_2`. Document the override knob (`verify='none'`) for legacy operators.

---

### F-009 — MQTT client defaults to plaintext, no auth, no ACL (High)
**Location:** `src/python/adf/canbus/mqtt.py:24-26, 59, 170` (`MQTTClient` + `MQTTLogger`)
**CWE:** CWE-319 (Cleartext Transmission), CWE-306 (Missing Authentication) · **STIG:** V-222563, V-222396 · **NIST:** SC-8, IA-2
**Tools:** manual review

```python
host = 'localhost'
port = 1883            # <-- plaintext MQTT, not 8883
...
self.__client = mqtt.Client()
self.__client.connect(self.host, self.port)   # no tls_set, no username_pw_set, no allow_anonymous=False
```

**Impact:** The MQTT control channel for CAN-over-MQTT bridges is plaintext by default with no authentication. Any host on the broker network can publish/subscribe and either spoof CAN messages or sniff the vehicle telemetry.
**Recommended fix:** Ship in PR — add `tls` and `username`/`password` config knobs and call `self.__client.tls_set(...)` and `self.__client.username_pw_set(...)` when configured. Default `tls=True` if any TLS config keys are present.

---

### F-010 — TCP Control server lacks built-in authentication (High)
**Location:** `src/python/adf/framework.py:778-829` (`start_control` + `ControlSocket.handle`)
**CWE:** CWE-306 · **STIG:** V-222396 · **NIST:** IA-2
**Tools:** manual review

The `ControlSocket.handle` loop reads lines from the TCP socket and calls `self.server.framework.config(cmd)` — which dispatches `exec`, `eval`-via-`log`, `plugin <module>` (arbitrary `importlib.import_module`), and `subscribe/event` against the running framework. The only access control is optional SSL (with `CERT_NONE` default — see F-008). There is no username/password, no token, no PKI client-cert pinning.
**Impact:** With control-server access, an attacker has full framework control: load arbitrary plugin modules, run arbitrary Python via `exec`, dump/restore state via `save`/`load`, restart the framework.
**Recommended fix:** DEFER auth backend (mTLS pinning, optional shared-secret) to follow-up Jira ticket `F-010-FOLLOWUP`. In the PR: change SSL defaults so that *if* the operator turns on the SSL block at all, `verify_mode` defaults to `CERT_REQUIRED` and `minimum_version` to `TLSv1_2` (rolled into F-008 fix); add a startup WARNING log if `start_control` is called without `ssl=`.

---

### F-011 — Predictable TCP ISN via `random.randint` (High)
**Location:** `src/python/adf/plugins/tcp.py:67`
**CWE:** CWE-330 (Use of Insufficiently Random Values) · **STIG:** V-222542 · **NIST:** SC-13
**Tools:** bandit B311 + manual review

```python
self.conns[key] = [info['seq'] + 1, random.randint(1, 2**32 - 1), [], []]   # ISN
```

**Impact:** The fake-TCP plugin (used to interact with attackers' TCP probes) uses non-cryptographic PRNG for its initial sequence number. An attacker who can predict the PRNG state can inject/spoof packets into the synthetic TCP flow.
**Recommended fix:** Ship in PR — replace `random.randint(...)` with `secrets.randbelow(2**32 - 1) + 1` (no allocation overhead, drop-in semantics).

---

### F-012 — `strcpy` without bounds check in TAP setup (High)
**Location:** `src/bpf_tap.c:89`
**CWE:** CWE-120 (Classic Buffer Overflow) · **STIG:** V-222607 · **NIST:** SI-10
**Tools:** flawfinder FF1001 + semgrep `c.lang.security.insecure-use-string-copy-fn`

```c
strcpy(dev, ifr.ifr_name);   // copy name back to arg in case we let kernel pick it
```

`dev` is the caller's `char*` arg; `ifr.ifr_name` is `IFNAMSIZ`-sized but `dev`'s buffer size is not visible at this call. The kernel returns the assigned interface name into `ifr.ifr_name`; `strcpy` then writes that name back into `dev` without a bounds check.
**Recommended fix:** Ship in PR — replace with `strncpy(dev, ifr.ifr_name, IFNAMSIZ); dev[IFNAMSIZ-1] = '\0';`.

---

### F-013 — `strncpy` of CLI arg without NUL-termination (High)
**Location:** `src/bpf_tap.c:269` (`strncpy(filter_file, argv[5], 255);`)
**CWE:** CWE-120, CWE-170 (Improper Null Termination) · **STIG:** V-222607 · **NIST:** SI-10
**Tools:** flawfinder FF1008 + semgrep

```c
char filter_file[256];   // bpf_tap.c:25
...
strncpy(filter_file, argv[5], 255);   // <-- if argv[5] is >=255 chars, filter_file is not NUL-terminated
```

**Impact:** `filter_file` is used as a string by `fopen()` later. Lack of NUL termination → undefined behavior.
**Recommended fix:** Ship in PR — `strncpy(filter_file, argv[5], sizeof(filter_file)-1); filter_file[sizeof(filter_file)-1] = '\0';`

---

### F-014 — `strncpy` of `dev` into `ifr.ifr_name` without NUL-termination (High)
**Location:** `src/bpf_tap.c:82`
**CWE:** CWE-120, CWE-170 · **STIG:** V-222607 · **NIST:** SI-10
**Tools:** flawfinder FF1008 + semgrep

```c
if (*dev) strncpy(ifr.ifr_name, dev, IFNAMSIZ);   // <-- no explicit NUL term
```

**Impact:** If `dev` is exactly `IFNAMSIZ` bytes long, `ifr.ifr_name` is not NUL-terminated; subsequent `strcpy(dev, ifr.ifr_name)` (F-012) then reads past the end.
**Recommended fix:** Ship in PR — `strncpy(ifr.ifr_name, dev, IFNAMSIZ-1); ifr.ifr_name[IFNAMSIZ-1] = '\0';`

---

### F-015 — `fread` and `calloc` return values ignored (Medium)
**Location:** `src/bpf_tap.c:168-170`
**CWE:** CWE-252 (Unchecked Return Value), CWE-690 (Unchecked Return → NULL deref) · **STIG:** V-222594 · **NIST:** SI-11
**Tools:** manual review (flawfinder noted `fread` indirectly)

```c
*buffer = calloc(1, size+1);     // not checked for NULL
fread(*buffer, size, 1, fp);     // return value not checked
```

**Impact:** On allocation failure, `*buffer` is NULL and the subsequent `fread` is undefined behavior. On a short read, the filter file is silently truncated and `pcap_compile` may succeed against a partial filter.
**Recommended fix:** Ship in PR — check both return values and `error("alloc",filename)` / `error("short read",filename)` on failure.

---

### F-016 — Signal handler calls non-async-signal-safe functions (Medium)
**Location:** `src/bpf_tap.c:235-246` (`handle_sig` → `set_filter` → `pcap_compile`, `pcap_freecode`, `pcap_breakloop`)
**CWE:** CWE-364 (Signal Handler Race Condition) · **STIG:** V-222594 · **NIST:** SI-11
**Tools:** manual review

```c
static void handle_sig(int s){
    if (s == SIGHUP) {
        struct bpf_program old_bpf = bpf;
        set_filter();                 // <-- calls fopen, malloc, pcap_compile inside a signal handler
        pcap_freecode(&old_bpf);
    } ...
}
```

**Impact:** SIGHUP delivered during `malloc`/`fopen` in the main path leads to undefined behavior (the same lock taken twice from inside the handler). At minimum a hang; potentially a heap corruption.
**Recommended fix:** Set a `volatile sig_atomic_t reload_filter = 1;` flag in the handler; have the main loop poll the flag between captures. DEFERRED to follow-up ticket — non-trivial restructure of the main loop. Document in follow-up.

---

### F-017 — Unbounded length-prefix read on Event Listener (Medium)
**Location:** `src/python/adf/event.py:83, 98` (`l = struct.unpack('!L', ...recv(4))[0]; ...recv(l)`)
**CWE:** CWE-789 (Memory Allocation with Excessive Size Value) · **STIG:** V-222607 · **NIST:** SI-10
**Tools:** manual review

**Impact:** Any TCP peer can advertise `l = 0xFFFFFFFF` and force a 4 GB allocation/recv. Same DoS path on the SSL variant.
**Recommended fix:** Ship in PR — clamp `l` to a reasonable max (e.g. 64 MiB) and `break` the handler on oversized length.

---

### F-018 — Pervasive bare `except:` swallowing security events (Medium)
**Locations:** ~24 sites across `src/python/adf/` (see `evidence/local-scans/bandit.txt` B110/B112 ids)
**CWE:** CWE-755 (Improper Handling of Exceptional Conditions) · **STIG:** V-222594 · **NIST:** SI-11, AU-2
**Tools:** bandit B110/B112 + ruff

**Impact:** Silent `try/except/pass` masks decode errors, network failures, and parser exceptions — exactly the events security teams must audit. Examples: `util.py:100,105`, `framework.py:499,503,731,736`, `canbus/mqtt.py:41-53,88,196`, `interface.py:107,125,166,168,230,263,338,440`, `__main__.py:54,87`.
**Recommended fix:** Ship in PR — narrow the *security-sensitive* sites to specific exception types and add `self.debug(...)`/`logger.warning(...)`. Spec sites where the silent-pass is intentional (e.g., `util.parse_kvs` falling back from `int` parse) are kept narrow (`except ValueError: pass`).

---

### F-019 — `socket.create_connection` fixed 1-second timeout, no `settimeout` on accepted socket (Medium)
**Location:** `src/python/adf/event.py:159`, `src/python/adf/adfcon.py:26`
**CWE:** CWE-400 (Resource Exhaustion) · **STIG:** V-222594 · **NIST:** SC-5
**Tools:** manual review

The Sender's connect timeout is 1 second but per-call socket `recv`/`send` use no timeout once connected; a stalled peer holds the connection forever. `adfcon.py` casts a stringified `timeout` opt to int after `select` is already blocking.
**Recommended fix:** Ship in PR — add `__socket.settimeout(self.timeout)` after `create_connection`.

---

### F-020 — `assert` used for runtime invariants in production code (Medium)
**Location:** 32 sites flagged by bandit B101 across `event.py`, `plugin.py`, etc.
**CWE:** CWE-703 · **STIG:** V-222594 · **NIST:** SI-11
**Tools:** bandit B101

**Impact:** `python -O` drops `assert`s, silently disabling the checks. Most current sites are in test/demo `__main__` blocks (low risk) — they are documented as info in the triage so future code reviews flag new productive `assert` use.
**Recommended fix:** Info only — no PR change. Future-proof via a `tests/test_compliance.py::test_no_production_asserts` that allowlists only `__main__` blocks.

---

### F-021 — `subprocess.run(..., shell=True)` in `setup.py` for gcc (Medium)
**Location:** `setup.py` (gcc compile step for `bpf_tap.c`)
**CWE:** CWE-78 · **STIG:** V-222609 · **NIST:** SI-10
**Tools:** bandit B602 (raw inspection — setup.py wasn't in the bandit scope by default)

**Impact:** Setup-time only; risk is to the install host. Low likelihood (build environment is trusted) but flagged for completeness.
**Recommended fix:** Ship in PR — split the gcc command into a list and call `subprocess.run([...], check=True, shell=False)`.

---

### F-022 — `fopen(filename, "rb")` without path validation (Medium)
**Location:** `src/bpf_tap.c:166`
**CWE:** CWE-22 (Path Traversal), CWE-362 (TOCTOU) · **STIG:** V-222607 · **NIST:** SI-10
**Tools:** flawfinder FF1040

**Impact:** `filter_file` is set from `argv[5]` and reread on SIGHUP. If the process drops privileges between argv parsing and SIGHUP, a symlink swap could redirect reads.
**Recommended fix:** Info; document `--bpf-filter` as "must be a path the operator controls"; no in-code change in this PR.

---

### F-023 — Use of `pickle.dumps` for `Sender.send` (Medium)
**Location:** `src/python/adf/event.py:155, 232`
**CWE:** CWE-502 · **STIG:** V-222607 · **NIST:** SC-13
**Tools:** semgrep
**Impact:** Encoder side mirrors the deserializer issue (F-001). Replacing pickle on both sides is a single architectural fix tracked under the F-001 follow-up; no in-PR change here.

---

### F-024 — TCP Listener `verify` config defaults applied per-connection without state (Low)
**Location:** `src/python/adf/event.py:115-127` — `EventSocket` rebuilds `ssl.create_default_context` for every `get_request` call
**Impact:** Inefficiency, not a vuln — context recreation is fine functionally but masks state. Flagged so the F-008 fix can introduce caching.
**Recommended fix:** Info only.

---

### F-025 — `diskcache 5.6.3` transitive dep — CVE-2025-69872 (Low)
**Location:** transitive dep of `cantools` (declared in setup.py `extras_require['can']`)
**CWE:** N/A (advisory) · **STIG:** V-222656 · **NIST:** RA-5, SA-22, SI-2
**Tools:** pip-audit
**Recommended fix:** Ship in PR — add `diskcache>=5.6.4` to `extras_require['can']` as a minimum-version floor.

---

### F-026 — Statically-sized 65 KiB buffer on read from TAP (Low)
**Location:** `src/bpf_tap.c:136` (`char buffer[65536];`)
**CWE:** CWE-119 · **Impact:** Bounded by `sizeof(buffer)` passed to `read()`, so flawfinder's warning is style-only.
**Recommended fix:** Info only.

---

### F-027 — `Event.eval` evaluates expression against event data dict (Low)
**Location:** `src/python/adf/event.py:55-57`
**CWE:** CWE-95 · **STIG:** V-222609 · **NIST:** SI-10
**Tools:** bandit B307 + semgrep
**Impact:** This is a documented Plugin-API hook used by plugin authors to write filter expressions; the input is not network-supplied directly. Listed for completeness; fix is part of the broader eval/exec follow-up architecture work.
**Recommended fix:** Documented info; rolled into the F-003/F-005 follow-up.

---

### F-028 — `os.environ[k] = str(v)` from control plane (Low)
**Location:** `src/python/adf/framework.py:296-297` (`env` control command sets process env from caller-supplied values)
**CWE:** CWE-454 (External Initialization of Trusted Variables) · **STIG:** V-222607 · **NIST:** SI-10
**Recommended fix:** Info; rolled into the F-010 control-auth follow-up. No in-PR change.

---

### F-029 — Log message includes raw client address + bytes (Low)
**Location:** `src/python/adf/event.py:87, 102` (`self.debug('%s %s %s', self.client_address, l, event)`)
**Impact:** Debug-level only; not PII; not flagged as a security risk but listed.
**Recommended fix:** Info only.

---

### F-030 — `pickle.loads(self.rfile.read(l))` reads up to `l` bytes with no minimum-length sanity check (Low)
**Location:** `src/python/adf/event.py:84, 99`
**Impact:** Covered by F-017 (length clamp) and F-001 (pickle hardening guard).
**Recommended fix:** No additional action.

---

### F-031 — Documentation: `bin/adf` must run as root for raw socket / TAP / Pcap / NFQueue (Info)
**Location:** `README.md`, `setup.py`
**STIG:** V-222428 · **NIST:** AC-6
**Recommended fix:** Document the principle-of-least-privilege override (capabilities `CAP_NET_RAW`, `CAP_NET_ADMIN`) in README so operators don't run the whole framework as `root`. Info only; doc PR could be split out.

---

### F-032 — No Dockerfile / IaC artifacts present (Info)
**Location:** repo root
**Recommended fix:** Not applicable to current build. If container packaging is added, follow STIG V-222394/395 (non-root, pinned digests).

---

## 5. STIG / NIST coverage map

| STIG control | Findings touching it |
|---|---|
| V-222396 (AuthN) | F-009, F-010 |
| V-222542 (Crypto at rest) | F-011 |
| V-222563 (TLS) | F-008, F-009 |
| V-222575 (Secret mgmt) | F-002 |
| V-222594 (Error handling) | F-015, F-016, F-018, F-019, F-020 |
| V-222607 (Input validation) | F-001, F-002, F-012, F-013, F-014, F-017, F-022, F-023, F-028, F-030 |
| V-222609 (Injection) | F-003, F-004, F-005, F-006, F-007, F-021, F-027 |
| V-222656 (Supply chain) | F-025 |
| V-222428 (Privilege) | F-031 |

| NIST 800-53 r5 family | Findings |
|---|---|
| AC-3 (access enforcement) | F-003, F-004 |
| AC-6 (least privilege) | F-031 |
| AU-2 (audit events) | F-018 (silent excepts mask audit events) |
| IA-2 (id/auth) | F-009, F-010 |
| RA-5 (vuln scanning) | F-025 |
| SA-22 (unsupported components) | F-025 |
| SC-5 (DoS protection) | F-019 |
| SC-8 (transmission protection) | F-001, F-008, F-009 |
| SC-13 (crypto) | F-008, F-011, F-023 |
| SC-28 (data at rest) | F-002 |
| SI-2 (flaw remediation) | F-025 |
| SI-10 (input validation) | F-001..F-007, F-012..F-014, F-017, F-022, F-023, F-027, F-028 |
| SI-11 (error handling) | F-015, F-016, F-018, F-019, F-020 |

## 6. Evidence

All raw scanner output is committed under `docs/security-audit/evidence/`:

- `local-scans/bandit.{json,txt}` — bandit 1.9.4 on `src/python/adf/`
- `local-scans/semgrep.{json,txt}` — semgrep (p/owasp-top-ten, p/r2c-security-audit, p/python, p/c)
- `local-scans/cppcheck.{xml,txt}` — cppcheck `--enable=all`
- `local-scans/flawfinder.{csv,txt}` — flawfinder 2.0.19
- `local-scans/pylint.txt` · `local-scans/ruff.{json,txt}`
- `local-scans/pip-audit.{json,txt}` — synthesized requirements
- `local-scans/trivy.{json,txt}` · `local-scans/osv.json` · `local-scans/gitleaks.json`

## 7. Triage and remediation plan

See `docs/security-audit/TRIAGE_REPORT.md` for the prioritized split between **quick-wins shipped in this PR** and **architectural items deferred to follow-up Jira tickets**, plus the per-finding LOE estimate in `docs/security-audit/LOE_ESTIMATE.md`.
