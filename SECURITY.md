# Security Policy

## Scope of Use

H4ACKBAR is a defensive security research and education tool. It is intended
for use **only** on:

- Systems you own.
- Systems you have **explicit written authorization** to test (e.g. signed
  penetration-testing engagement letter, bug-bounty program in-scope target,
  CTF challenge, lab VM).

Unauthorized use against third-party systems may violate:
- **US** — Computer Fraud and Abuse Act (CFAA, 18 U.S.C. § 1030)
- **UK** — Computer Misuse Act 1990
- **EU** — Directive 2013/40/EU on attacks against information systems
- Equivalent legislation in your jurisdiction

The authors and contributors **accept zero liability** for misuse.

## Reporting a Vulnerability in H4ACKBAR

If you discover a security issue **in the H4ACKBAR tool itself** (e.g. code
execution via a malicious session file, dependency CVE), report it privately:

1. Do **not** open a public GitHub issue.
2. Open a private security advisory:
   `https://github.com/YOUR_USER/H4ACKBAR/security/advisories/new`
3. Include: version, OS, reproduction steps, impact assessment.

We aim to acknowledge within **72 hours** and issue a patch within **14 days**
for high/critical issues.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.0.x   | ✅        |
| < 1.0   | ❌        |

## Threat Model of the Tool Itself

- **Trust boundary**: user-provided URL → sender module. TLS verify defaults on.
- **Session files**: JSON, plain-text — do **not** commit them (see `.gitignore`).
- **No auto-scan**: every request requires explicit user click.
- **No credential storage**: tool holds no secrets by design.
