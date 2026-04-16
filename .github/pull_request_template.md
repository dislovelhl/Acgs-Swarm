## Summary

- What changed?
- Why does it matter to the package user?
- Anything intentionally left out?

## Test Evidence

- [ ] `python -m pytest tests/ --import-mode=importlib -q`
- [ ] targeted tests for changed paths
- [ ] `python -m build`

Paste the actual command output or a short result summary.

## Release Impact

- [ ] package API changed
- [ ] dependency set changed
- [ ] version bump required
- [ ] changelog updated

If the package API changed, name the public symbols or behavior that changed.

## Security / Safety Check

- [ ] no new trust boundary without validation
- [ ] no generated artifacts or local state files included by accident
- [ ] no secrets, tokens, or private credentials in the diff

## Papers / Research Assets

- [ ] not applicable
- [ ] paper source changed
- [ ] paper build assets changed

If paper files changed, note whether the LaTeX sources were rebuilt locally.

## Checklist

- [ ] CI should pass on this branch
- [ ] docs match shipped behavior
- [ ] reviewers know the highest-risk area of the diff
