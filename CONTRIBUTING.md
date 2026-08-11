# Contributing

Thanks for helping improve `agent-repo-guard`. Bug reports, minimized false-positive fixtures, documentation corrections, and focused rule proposals are welcome.

## Development setup

The test suite uses only the Python standard library:

```bash
python -m unittest discover -s tests -v
PYTHONPATH=src python -m agent_repo_guard . --fail-on high
```

## Rule proposals

A new rule should include:

1. A concrete threat and affected trust boundary.
2. At least one positive and one negative test.
3. A stable rule ID, severity, explanation, and actionable remediation.
4. Evidence that the pattern is narrow enough for review workflows.

Do not add telemetry or network access. Test fixtures must not contain live credentials or private repository content.

## Pull requests

- Keep changes focused and explain the security trade-off.
- Add tests for behavior changes.
- Update the README and threat model when scope changes.
- Confirm the repository self-scan is clean at the high threshold.

By contributing, you agree that your contribution is licensed under the MIT License.
