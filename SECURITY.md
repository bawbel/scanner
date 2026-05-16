# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| 1.2.x | Active |
| 1.1.x | Security fixes only |
| < 1.1 | Not supported |

---

## Reporting a vulnerability in Bawbel Scanner

**Do not open a public GitHub issue.**

Email: **bawbel.io@gmail.com**
Subject: `SECURITY: bawbel-scanner [brief description]`

We will acknowledge within 48 hours and coordinate disclosure.

---

## Reporting a new agentic vulnerability (AVE submission)

If you found a vulnerability in an MCP server, skill file, or other agentic
component, that is a candidate for a new AVE record.

See [github.com/bawbel/ave/CONTRIBUTING.md](https://github.com/bawbel/ave/CONTRIBUTING.md)

---

## Scope

This policy covers:

- `bawbel-scanner` PyPI package
- `github.com/bawbel/scanner` source repository
- `api.piranha.bawbel.io` API
- `bawbel.io` website

---

## Security design principles

Bawbel Scanner is itself a security tool and must not be exploitable.

**Never execute scanned content.** The scanner reads files as text. It never
evaluates, imports, or runs any content it scans. This is intentional and must
be preserved in all contributions.

**No shell=True.** All subprocess calls use list args. Never pass user input
to a shell.

**No network calls during scan.** The scanner fetches AVE records at startup
and caches them locally. Scan-time network calls are prohibited.

**Sandboxed LLM engine.** The LLM engine sends file content to a remote API.
It must never send credentials, environment variables, or system paths.
