# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 3.x     | :white_check_mark: |
| < 3.x   | :x:                |

## Reporting a Vulnerability

The Active Defense Framework (ADF) is developed and released by the US Army
Research Laboratory. If you discover a security vulnerability in this code:

1. **Do not open a public GitHub issue.**
2. Email a description of the issue, reproduction steps, and impact to the
   maintainers via the address published in the repository `README.md`.
3. Expect an acknowledgement within **5 business days**. We will work with
   reporters to coordinate disclosure timing and, where appropriate,
   credit reporters in the release notes.

For vulnerabilities affecting production federal deployments, please also
notify your local ISSO so a POA&M entry can be opened. Artifacts produced by
the DSOP shift-left pipeline (OSCAL POA&M, SCAP results, SBOM, SARIF) can be
attached to the same report.

## Known Hardening Gaps (tracked in the DSOP POA&M)

The following gaps are documented publicly to encourage patches and to
establish a shared threat model. Remediation is tracked in the accompanying
compliance bundle under `oscal/poam.json`.

- Event bus (`src/python/adf/event.py`) and CAN-over-IP transport
  (`src/python/adf/canbus/IBP.py`) accept `pickle`-encoded payloads from the
  network. Pickle deserialization of untrusted input is unsafe by design
  (CWE-502).
- Framework control port (`src/python/adf/framework.py`) and plugin IPC
  (`src/python/adf/plugin.py`) call `eval()` / `exec()` on received command
  payloads (CWE-95 / CWE-78). Bind the control port to `127.0.0.1` until a
  method-allowlist refactor lands.
- TLS wrappers in `event.py` and `framework.py` use default cipher/version
  selection; operators should pin `minimum_version=TLSv1_2` and an explicit
  cipher list per DISA STIG V-220634 when running in an IL4+ enclave.

## NIST 800-53 & STIG References

Key controls: SI-10, SI-11, SC-8, SC-13, SC-28, AU-2, AU-3, IA-5, CM-2, CM-7,
SA-10, SA-11, SA-15, RA-5.

Key STIG rules: V-220631, V-220632, V-220633, V-220634, V-220635, V-222430.
