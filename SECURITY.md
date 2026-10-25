# Rivis security policy

## Reporting a vulnerability

Report suspected vulnerabilities privately to the Rivis maintainers through the organisation's approved
security-reporting channel. Do not open a public issue and do not attach captures, HAR files, sessions,
tokens, certificates, or customer data. Include the Rivis and mitmproxy versions, operating system, impact,
and minimal reproduction steps using synthetic data. Run `rivis bug-report` when diagnostics are useful; its
bundle is redacted and intentionally excludes captured flows and UI tokens. Review the bundle before sharing it.

Maintainers should acknowledge the report, reproduce it on disposable state and random ports, assign severity,
prepare regression tests with the fix, and coordinate disclosure only after affected builds can be replaced.
Never ask a reporter to reproduce against a production system.

## Supported security baseline

Rivis is a local developer/QA interception tool. Its proxy and web UI bind to loopback; device support is limited
to simulators/emulators unless the operator starts it with `--lan`, which also binds the proxy (never the web UI) to
the workstation's own Wi-Fi/Ethernet address and refuses every client until it is allowed on the workstation; state is owner-only; rules and scripts are trusted local code. Captured requests can
contain credentials and personal data, so sessions, collections, mocks, composer variables, logs, and bug reports
must be handled as sensitive workstation data. The UI session grants rule and script control and is therefore
equivalent to local code execution by design.

The threat model covers malicious websites, other local users, hostile traffic content, untrusted shared rule
files, compromised installers/mirrors, and accidental disclosure by operators. The detailed STRIDE analysis,
reproduction evidence, and remediation tracking are maintained in:

- Internal security audit, round A (kept outside this repository)
- Internal security audit, round B (kept outside this repository)
- [`SECURITY-FIXLIST.md`](../SECURITY-FIXLIST.md)

Re-run the audit and the full test suite for every mitmproxy upgrade or material change to listeners, authentication,
file access, certificate handling, script execution, or installer trust.
