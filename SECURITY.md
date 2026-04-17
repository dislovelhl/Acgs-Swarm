# Security Policy

## Supported versions

Security fixes are prioritized for the latest published release line and the current `main` branch.

| Version | Supported |
| ------- | --------- |
| Latest release | :white_check_mark: |
| Older releases | :x: |
| `main` | Best effort |

## Reporting a vulnerability

For suspected vulnerabilities, please use GitHub private vulnerability reporting for this repository when it is available:

- <https://github.com/dislovelhl/Acgs-Swarm/security/advisories/new>

If you cannot access that flow, contact the maintainers at `hello@acgs.dev` with:

- a description of the issue and affected component
- reproduction steps or a proof of concept
- impact assessment
- any suggested mitigations

Please do not open public issues for unpatched vulnerabilities.

## Response expectations

We aim to:

- acknowledge new reports within 5 business days
- provide an initial severity and triage update within 10 business days
- coordinate disclosure after a fix or mitigation is available

## Scope

This policy covers:

- the published Python package and source distribution
- GitHub Actions workflows that build, test, or publish artifacts
- release automation and package metadata in this repository

Third-party services and dependencies are handled according to their own security policies, though we still appreciate coordinated reports when they affect this package.
