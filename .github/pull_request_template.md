## Summary

- Describe the change.
- Link the issue, discussion, or release driver when relevant.

## Validation

- [ ] `python -m ruff check src/`
- [ ] `python -m pytest tests/ --import-mode=importlib -q`
- [ ] `python -m build --wheel --sdist`
- [ ] Other relevant validation:

## Package and release impact

- [ ] No package-facing change
- [ ] Public API changed
- [ ] Dependency or packaging metadata changed
- [ ] Release notes / changelog update needed

Version or release notes details:

## Paper and docs impact

- [ ] No paper or docs changes
- [ ] `README.md` updated
- [ ] `CHANGELOG.md` updated
- [ ] `paper/` or `papers/` artifacts updated
- [ ] Other docs updated

## Security and operations

- [ ] No security-sensitive change
- [ ] Touches authentication, signatures, transport, or release automation
- [ ] Requires follow-up GitHub settings or environment changes

Follow-up notes:
