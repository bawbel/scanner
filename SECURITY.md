# Security Policy — Bawbel Scanner

---

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Public disclosure before a fix is available puts users at risk.

### Contact

**Email:** bawbel.io@gmail.com
**Subject:** `SECURITY: bawbel-scanner [brief description]`

We aim to respond within **48 hours** and issue a fix within **7 days** for
confirmed vulnerabilities.

---

## Supported Versions

| Version | Supported |
|---|---|
| 0.1.x (latest) | ✅ Yes |
| < 0.1.0 | ❌ No |

---

## What to Include in Your Report

- Description of the vulnerability
- Steps to reproduce
- Impact — what an attacker could achieve
- Suggested fix (optional but appreciated)

---

## Scope

### In scope

- Vulnerabilities in `scanner/`, `config/`, `cli.py` source code
- Security issues in the Dockerfile or container configuration
- Issues where scanning a malicious file could compromise the scanner host
- Bypasses of the path traversal, symlink, or file size protections
- Information exposure — scanner leaking internal paths, secrets, or stack traces

### Out of scope

- Vulnerabilities in detection rules not finding something (false negatives)
- Theoretical vulnerabilities with no practical exploit path
- Vulnerabilities in third-party dependencies — report directly to the dependency maintainer
- Issues requiring physical access to the machine running the scanner

---

## Our Security Commitments

**The scanner itself must not be exploitable by the files it scans.**

We follow these practices to protect users:

- All file paths validated and resolved before use
- Symlinks rejected before `resolve()` to prevent symlink attacks
- Files over 10MB rejected to prevent memory exhaustion
- No exception details exposed to users — only stable E-codes
- No file content or match strings in logs at WARNING or above
- All subprocess calls use list arguments — never `shell=True`
- Non-root Docker user with read-only volume mounts
- `no-new-privileges:true` in container security options
- Dependencies audited with `pip-audit` on every release

---

## Disclosure Policy

1. You report the vulnerability to us privately
2. We confirm receipt within 48 hours
3. We investigate and develop a fix
4. We release a patched version
5. We credit you in the release notes (unless you prefer anonymity)
6. You may publicly disclose after the fix is released

We ask for a **90-day embargo** before public disclosure to give users time to
update. We will work to fix confirmed vulnerabilities much faster than this.

---

## Hall of Fame

Security researchers who have responsibly disclosed vulnerabilities:

*None yet — be the first.*

---

## PGP Key

For sensitive reports, email bawbel.io@gmail.com and request our PGP key.
