# Level-of-Effort estimate — full remediation

**Repo:** `COG-GTM/USArmy-ARL-Active-Defense-Framework`
**Epic:** [UF-209](https://cog-gtm.atlassian.net/browse/UF-209)
**Scope of this document:** every finding NOT shipped in the current PR, and what it
would take to close it end-to-end (code, tests, review, rollout).

This estimate assumes Devin (or another agent / engineer of comparable throughput)
executes each PR with the same playbook discipline used for the quick-win PR
(plan → implement → test → CI → review). ACU = "agentic compute unit" billed at the
session level; one ACU is roughly one focused Devin hour of work (research +
implementation + verification combined).

---

## Summary

| Bucket          | Findings                                                        | LOC delta (est.) | ACUs (est.) | Wall-clock (est.)            |
|-----------------|------------------------------------------------------------------|------------------|-------------|------------------------------|
| Architectural   | F-001-FOLLOWUP, F-002-FOLLOWUP, F-003-FOLLOWUP, F-004-FOLLOWUP, F-005-FOLLOWUP | ~1,900 added / ~600 removed | **22** | 4 weeks (2 PRs in flight at a time) |
| Hardening       | F-010-FOLLOWUP, F-016-FOLLOWUP                                  | ~700 added / ~120 removed  | **8**  | 1.5 weeks                       |
| Hygiene         | F-020, F-026, F-027, F-028, F-029, F-030                        | ~450 added / ~80 removed   | **6**  | 1 week                          |
| **Total**       | 14 follow-up items                                              | **~3,050 added / ~800 removed** | **~36 ACUs** | **~6 weeks calendar** |

> The quick-win PR (this session) shipped at ~6 ACUs spread across discovery,
> remediation, compliance suite, dashboard, and Jira hygiene.

---

## Suggested PR slicing

The work fans out into 5 PRs grouped by area + reviewer load. Each PR has one
focused subject so a defense-side reviewer can sign off on it independently.

### PR-A — Network framing replacement (pickle → typed envelope)
**Finding(s):** F-001-FOLLOWUP, F-002-FOLLOWUP
**Estimate:** ~900 LOC added / ~250 removed · **10 ACUs** · ~2 weeks
**Why these together:** the on-the-wire framing and the on-disk state file both use
`pickle` for the same historical reason. Replacing both in one PR keeps the encode /
decode helpers in one place and avoids version-skew between Listener / Sender / Migrate.
**Acceptance criteria:**
- New `adf/_wire.py` exposes `encode(event) -> bytes`, `decode(bytes) -> Event` using
  a typed JSON / msgpack envelope with HMAC-SHA256 keyed by a shared secret.
- Listener / Sender / Channel / Migrate all route through `_wire`.
- State file format becomes versioned JSON + HMAC.
- Compatibility shim: `ADF_ALLOW_PICKLE_NET=1` still accepted for one minor version
  and emits a deprecation WARNING.
- Compliance assertion: `pickle.loads(` not allowed anywhere outside the shim.

### PR-B — Typed IPC method registry
**Finding(s):** F-003-FOLLOWUP
**Estimate:** ~500 LOC added / ~150 removed · **5 ACUs** · ~1 week
**Acceptance criteria:**
- `Plugin._ipc_methods` registry of explicitly decorated callables (`@ipc_method`).
- `framework._ipc_dispatch` and `plugin._ipc_dispatch` route through the registry
  with no `getattr` fallback.
- Compliance assertion: `getattr(self, method)` against unfiltered user input no
  longer appears in IPC dispatch paths.

### PR-C — Remove `exec_plugin` + per-plugin eval/exec; ship restricted DSL
**Finding(s):** F-004-FOLLOWUP, F-005-FOLLOWUP
**Estimate:** ~600 LOC added / ~250 removed · **7 ACUs** · ~1.5 weeks
**Acceptance criteria:**
- Drop `Framework.exec_plugin`, `Plugin.eval_packet`, `Plugin.exec_packet`,
  `Event.eval`, and the j1939 / profile `eval`+`exec` paths.
- New `adf/_dsl.py` exposes a small AST-walking interpreter that supports
  arithmetic + comparisons + a fixed set of safe builtins (`int`, `float`, `len`,
  `bool`). Plugin / event / J1939 / profile expressions evaluate through that.
- Migration guide in `docs/security-audit/` walking operator configs.
- Compliance assertion: no `eval(`, `exec(`, `compile(` anywhere in `src/python`.

### PR-D — Plugin allow-list + signed manifest
**Finding(s):** F-010-FOLLOWUP, F-016
**Estimate:** ~500 LOC added / ~100 removed · **5 ACUs** · ~1 week
**Acceptance criteria:**
- `framework.start_plugin` consults a signed manifest at startup.
- Refuse to load plugins not on the allow-list; one-time WARNING.
- Compliance assertion: `importlib.import_module` not invoked against unfiltered
  operator input.

### PR-E — Logging redaction + dependency hygiene
**Finding(s):** F-020, F-026, F-027, F-028, F-029, F-030
**Estimate:** ~450 LOC added / ~80 removed · **6 ACUs** · ~1 week
**Acceptance criteria:**
- Structured logging adapter that redacts known credential / token / address fields.
- `pyproject.toml` migration with pinned floors for `dpkt`, `cantools`, `diskcache`.
- BPF tap defaults narrowed to opt-in interfaces.
- `SBOM.json` generated in CI via `trivy fs --format cyclonedx`.
- `SECURITY.md` + `CODEOWNERS` checked in.

---

## Cross-cutting overhead (already included in totals)

- **Compliance test maintenance:** ~3 ACUs across all PRs (extend
  `tests/test_compliance.py` per new control, keep ≥45 assertions passing).
- **Devin Review iteration:** ~2 ACUs across all PRs (Devin Review opens a fresh
  review on each PR, see playbook Phase 7 note).
- **Documentation / dashboard refresh:** ~1 ACU (re-run `docs/security-audit/`
  generation after each PR merges).

---

## Risks & dependencies

- **Operator opt-in compatibility window.** PR-A and PR-C both retire env-var gates
  introduced in the quick-win PR. Sequence them at least one minor release apart so
  operators have a deprecation window.
- **CAN bus regression coverage.** The J1939 / profile `eval` removal in PR-C lands
  inside the data-path; the maintainers need to confirm their hardware-in-the-loop
  test rig still passes before merge.
- **Reviewer bandwidth.** Each PR carries 1–2 days of reviewer time on the defense
  side; sequence with the maintainers' sprint cadence.

---

## Recommendation

Schedule **PR-A first** (biggest user-visible behaviour change), gate operator
opt-in for one minor release, then ship **PR-B → PR-C → PR-D → PR-E** in
parallel pairs. Total wall-clock with two PRs in flight at a time: **~6 weeks**.
