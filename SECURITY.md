# Security Policy

## Supported Versions

Security fixes are applied to:

| Version | Supported |
| --- | --- |
| `0.2.x` | Yes |
| `main` | Yes |
| `< 0.2.0` | No |

## Reporting a Vulnerability

Prefer GitHub private vulnerability reporting for anything that could let an attacker:

- bypass constitutional validation
- forge or replay mesh votes
- corrupt settlement persistence
- exfiltrate prompts, artifacts, or private model state
- abuse the WebSocket transport path

If private vulnerability reporting is enabled in the GitHub repo settings, use that.

If it is not enabled yet, email the maintainer listed in `pyproject.toml` or open a private coordination channel with the repo owner before publishing details.

Do not open a public GitHub issue for a live security bug.

## What to Include

Please include:

- affected version or commit SHA
- exact file and function involved
- reproduction steps
- proof-of-concept payload or request, if safe to share privately
- expected impact and attacker prerequisites

Good reports are concrete. File, line, request shape, observed behavior.

## Response Expectations

- initial triage target: within 5 business days
- confirmed issues get a remediation plan and patch target
- coordinated disclosure is preferred once a fix is available

## Scope Notes

This repo ships a Python package and research/paper assets. Security reports should focus on shipped runtime behavior, build/release pipeline integrity, and exposed transport or persistence paths. Formatting issues in paper sources are out of scope unless they create a release or supply-chain risk.
