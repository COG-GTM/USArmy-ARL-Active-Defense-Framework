# Triage Report — US Army ARL Active Defense Framework

Companion to `SECURITY_AUDIT_REPORT.md`. Splits the 32 findings into priority tiers, sets per-finding effort, and explicitly marks which findings ship in **this PR** vs which are **deferred** to follow-up Jira sub-tasks (architectural changes per playbook rule).

> **Authority for this PR:** *quick-wins only* (per user instruction and playbook Phase 6). Anything that requires public-API change, an auth backend, a wire-format change, or an architectural restructure is deferred to a follow-up ticket — tracked in Jira, **not** auto-PR'd.

## Priority groups

| Priority | Window | Findings |
|---|---|---|
| **P1 — Immediate (in this PR)** | now | F-006, F-007, F-008, F-009 (partial: TLS + auth knobs), F-011, F-012, F-013, F-014 |
| **P1 — Immediate (in this PR)** | now | F-003, F-004, F-005 (in-PR: guard rails + ast.literal_eval where safe) |
| **P1 — Immediate (in this PR)** | now | F-015, F-017, F-018 (narrow excepts, no behaviour change), F-019, F-021, F-025 |
| **P1 — Immediate (in this PR)** | now | F-001, F-002 (in-PR: hardening guards + state-file `chmod 0600`) |
| **P2 — Short-term (follow-up)** | ≤30 days | F-001-FOLLOWUP, F-002-FOLLOWUP, F-003-FOLLOWUP, F-004-FOLLOWUP, F-005-FOLLOWUP, F-010-FOLLOWUP, F-016 |
| **P3 — Medium-term** | ≤90 days | F-023 (rolled into F-001 follow-up) |
| **P4 — Long-term / info** | track in Confluence | F-020, F-022, F-024, F-026, F-027, F-028, F-029, F-030, F-031, F-032 |

## Per-finding triage table

> Effort: **L** ≤ 30 LOC + 1 unit test · **M** ≤ 150 LOC across ≤3 files · **H** > 150 LOC or any public-API change.

| ID | Severity | Status in PR | Effort | Notes |
|---|---|---|---|---|
| F-001 | Critical | **In PR** (hardening guard `ADF_ALLOW_PICKLE_NET`) + **F-001-FOLLOWUP** (replace pickle wire format) | L (in-PR), H (follow-up) | Guard + WARNING log lands here; full wire-format change deferred |
| F-002 | Critical | **In PR** (`os.chmod 0600` + refuse world-writable) + **F-002-FOLLOWUP** (replace pickle state file) | L (in-PR), M (follow-up) | |
| F-003 | Critical | **In PR** (`getattr` for IPC, `ast.literal_eval` for log-dict) + **F-003-FOLLOWUP** (control-command whitelist) | L (in-PR), M (follow-up) | IPC and log paths fixed; full whitelist deferred |
| F-004 | Critical | **In PR** (env-var gate + WARN log) + **F-004-FOLLOWUP** (remove/restrict `exec` command) | L (in-PR), M (follow-up) | |
| F-005 | Critical | **In PR** (same env-var gate as F-004 covers j1939/profile eval/exec sites) + **F-005-FOLLOWUP** (replace with restricted DSL) | L (in-PR), H (follow-up) | |
| F-006 | Critical | **In PR** (drop `os.system`, use `subprocess.run(..., shell=False)`) | L | |
| F-007 | Critical | **In PR** (allowlist command head) | L | |
| F-008 | High | **In PR** (`CERT_REQUIRED` + `TLSv1_2` defaults; opt-out doc'd) | L | |
| F-009 | High | **In PR** (`tls_set` + `username_pw_set` config knobs) | L | |
| F-010 | High | **F-010-FOLLOWUP** (auth backend) + **In PR** (WARNING log if `start_control` runs without `ssl=`) | L (in-PR), H (follow-up) | |
| F-011 | High | **In PR** (`secrets.randbelow`) | L | |
| F-012 | High | **In PR** (replace `strcpy` with bounded `strncpy` + explicit NUL) | L | |
| F-013 | High | **In PR** (size-1, NUL term) | L | |
| F-014 | High | **In PR** (size-1, NUL term) | L | |
| F-015 | Medium | **In PR** (check `calloc`/`fread` returns) | L | |
| F-016 | Medium | **F-016-FOLLOWUP** (async-signal-safe handler) | M | non-trivial; deferred |
| F-017 | Medium | **In PR** (clamp `l` to 64 MiB) | L | |
| F-018 | Medium | **In PR** (narrow ~12 critical sites; leave benign `util.parse_kvs` excepts alone but typed) | M | Audited each narrowed site for None-path regressions |
| F-019 | Medium | **In PR** (`__socket.settimeout(self.timeout)`) | L | |
| F-020 | Medium | **Info / track** (no production `assert` sites today; covered by `tests/test_compliance.py`) | L | |
| F-021 | Medium | **In PR** (gcc shell=False) | L | |
| F-022 | Info | track | L | docs/configuration |
| F-023 | Medium | rolled into F-001 follow-up | — | |
| F-024 | Low | info | — | |
| F-025 | Low | **In PR** (min-version floor `diskcache>=5.6.4`) | L | |
| F-026 | Low | info | — | |
| F-027 | Low | rolled into F-005 follow-up | — | |
| F-028 | Low | rolled into F-010 follow-up | — | |
| F-029 | Low | info | — | |
| F-030 | Low | covered by F-017 + F-001 fixes | — | |
| F-031 | Info | doc-only follow-up | L | |
| F-032 | Info | n/a | — | |

## Quick-wins shipped in this PR (summary)

1. **`getattr` replaces `eval('self.'+method)`** in `Framework.__ipc_loop` and `Plugin.__main` — drops two `eval` call sites without behaviour change. *(F-003)*
2. **`ast.literal_eval` replaces `eval()` for the log-dict config path** — preserves documented dict-load behaviour, refuses arbitrary code. *(F-003)*
3. **`ADF_ALLOW_PICKLE_NET` env-var gate** on `Listener`/`Channel`/`Sender` and `IBP` `pickle.loads` sites — refuses by default with a single-line operator override and emits a WARNING log every time pickle-on-the-wire is enabled. *(F-001, F-023, F-030)*
4. **State file `chmod 0o600` on save** + refuse to `pickle.load` a state file with non-owner-writable permissions. *(F-002)*
5. **`ADF_ALLOW_EXEC` env-var gate** around `Framework.exec_plugin`, `Plugin.exec_packet`, J1939 eval/exec, and profile eval — refuses by default; emits a WARNING log when the operator opts in. *(F-004, F-005)*
6. **`os.system → subprocess.run([...], check=False, shell=False)`** in `canbus/__init__.py::test` and `setup.py` gcc step. *(F-006, F-021)*
7. **`subprocess.Popen` command allowlist** in `plugins/bpf_tap.py` — must match `('pkill','-HUP','bpf_tap')` head or refuses. *(F-007)*
8. **SSL defaults** flipped to `ssl.CERT_REQUIRED` + `ctx.minimum_version = ssl.TLSVersion.TLSv1_2` on Listener / Sender / Control server SSL paths. *(F-008)*
9. **MQTT TLS + auth config knobs** added to `canbus/mqtt.py` (`tls`, `tls_cafile`, `username`, `password`) — `tls_set` + `username_pw_set` invoked when set. *(F-009)*
10. **`secrets.randbelow`** replaces `random.randint` for TCP ISN. *(F-011)*
11. **C: bounded `strncpy` + explicit NUL termination** at `bpf_tap.c:82, 89, 269`. *(F-012, F-013, F-014)*
12. **C: `calloc` / `fread` return checks** at `bpf_tap.c:168-170`. *(F-015)*
13. **`recv` length-prefix clamped to 64 MiB** in `event.py` Listener. *(F-017)*
14. **Bare `except:` narrowed at 12 security-sensitive sites** in `event.py`, `framework.py`, `interface.py`, `canbus/mqtt.py`, `canbus/IBP.py`. Each narrowed site audited for `None`-path regressions. *(F-018)*
15. **Sender connect timeout** propagated to in-flight socket via `settimeout(self.timeout)`. *(F-019)*
16. **WARNING log on `start_control` without `ssl=`**. *(F-010, partial)*
17. **`diskcache>=5.6.4`** min-version floor added to `setup.py::extras_require['can']`. *(F-025)*

## Deferred to follow-up Jira tickets

- **F-001-FOLLOWUP** — Replace `pickle` wire format on Event Listener/Sender/Channel + CANoverIP with a length-bounded JSON / msgpack envelope and HMAC-SHA256 over the body (deployment-managed secret). Requires public-API change for plugin authors using event data; ~400 LOC.
- **F-002-FOLLOWUP** — Replace pickle state file with versioned JSON state (with `dataclasses.asdict` per plugin) + HMAC. ~250 LOC.
- **F-003-FOLLOWUP** — Control-server command dispatch becomes a whitelisted method table; remove `eval` from any remaining control-channel path. ~300 LOC.
- **F-004-FOLLOWUP** — Remove the `exec` control-server command outright (or make it a build-time opt-in). ~80 LOC.
- **F-005-FOLLOWUP** — Replace plugin `filter`/`exec` user expressions with a restricted DSL (e.g. `simpleeval`-style) that prohibits attribute access and import. ~250 LOC.
- **F-010-FOLLOWUP** — Add a proper auth backend to the TCP control server (mTLS pinning + optional shared-token); restrict by default to `127.0.0.1`. ~200 LOC.
- **F-016-FOLLOWUP** — Move signal-handler work in `bpf_tap.c` into the main loop via `sig_atomic_t` flag. ~80 LOC C.

LOE for each follow-up is itemized in `LOE_ESTIMATE.md`.

## Risk after this PR

- The four Critical findings tied to dynamic-code execution (F-001, F-003, F-004, F-005) are **mitigated but not eliminated** in this PR — operators can still opt in via the two `ADF_ALLOW_*` env vars. The follow-up tickets close the residual risk by changing the design.
- All High C findings (F-012, F-013, F-014) are eliminated in this PR.
- Crypto/TLS defaults (F-008, F-009) are eliminated for new deployments; existing operators must rotate their TLS config.
- Supply-chain finding F-025 is eliminated once `pip install -U` is performed against the new floor.
