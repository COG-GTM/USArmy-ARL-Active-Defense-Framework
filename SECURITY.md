# Security policy

This repository ships a network-facing event framework that processes packets,
parses bus protocols, and can run operator-supplied plugins. We take vulnerability
reports seriously.

## Supported versions

| Branch  | Supported |
|---------|-----------|
| `main`  | Yes       |
| Tagged releases ≥ 1.0 | Yes |
| Pre-1.0 / experimental branches | Best-effort |

## Reporting a vulnerability

- Email: please coordinate with the maintainers via the issue tracker for an
  out-of-band channel (do **not** open a public issue for security bugs).
- Provide: affected branch / commit, reproduction steps, the impact you observed,
  and any proposed mitigation.
- We aim to acknowledge reports within 5 business days.

## Threat model summary

The framework is designed to run on operator-controlled hosts inside a trusted
LAN segment. The Listener (TCP / SSL), the MQTT control channel, and the
control server are all considered "between trusted endpoints" by default.

Defense-in-depth posture for **untrusted** inputs is configured via env vars:

| Variable                  | Default | Effect when set to `1` |
|---------------------------|---------|--------------------------|
| `ADF_ALLOW_PICKLE_NET`    | unset   | Enable `pickle.loads()` of network-supplied bytes (Listener, CAN-over-IP). One-time WARNING logged. |
| `ADF_ALLOW_EXEC`          | unset   | Enable dynamic `eval`/`exec` of operator-supplied expressions (J1939, profile, packet hooks). One-time WARNING logged. |
| `ADF_MAX_PAYLOAD_BYTES`   | 67108864 (64 MiB) | Upper bound on length-prefixed network payloads before drop. |

Operators running with any gate flipped on are expected to assume their network
is trusted and to capture the WARNING log line for audit purposes.

## Compliance posture

The framework is audited against DISA STIG (ASD V5R3) and NIST 800-53 r5. The
current audit report and STIG/NIST cross-reference is at:

- `docs/security-audit/SECURITY_AUDIT_REPORT.md`
- `docs/security-audit/TRIAGE_REPORT.md`
- `docs/security-audit/LOE_ESTIMATE.md`
- `docs/security-audit/executive-dashboard.html`

CI gates the security regressions via `.github/workflows/security-audit-ci.yml`:

```bash
pytest tests/ -v
```

The compliance suite runs on every push and pull request and must stay at 0
failures.
