# agent-repo-guard

[![CI](https://github.com/hejr/agent-repo-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/hejr/agent-repo-guard/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

`agent-repo-guard` is a small, zero-runtime-dependency security linter for repositories that use AI coding agents and GitHub Actions. It looks for risky instructions, mutable action references, dangerous shell patterns, possible embedded credentials, and workflows that combine untrusted pull requests with write permissions.

The project is in an early alpha stage. Its rules are intentionally narrow and review-oriented; a finding is a prompt for human investigation, not proof that a repository is compromised.

## Why this exists

Agent instruction files such as `AGENTS.md`, `CLAUDE.md`, `SKILL.md`, and repository-specific editor rules can influence tools with access to source code and developer environments. At the same time, CI workflows often hold trusted tokens. These surfaces deserve lightweight checks that are easy to run locally and in code scanning.

## Current checks

| Rule | Detects | Severity |
|---|---|---|
| `ARG001` | Instruction override language in agent-control files | High |
| `ARG002` | Instructions requesting secrets or private machine data | Critical |
| `ARG003` | Remote content piped directly to an interpreter | High |
| `ARG004` | Broad recursive destructive commands | High |
| `ARG005` | World-writable file modes | Medium |
| `ARG006` | GitHub Actions not pinned to full commit SHAs | Medium |
| `ARG007` | `pull_request_target` combined with write permissions | Critical |
| `ARG008` | Common private-key or service-credential shapes | Critical |
| `ARG009` | Network commands that appear to transmit workflow secrets | Critical |

## Install

Python 3.10 or newer is required.

```bash
python -m pip install git+https://github.com/hejr/agent-repo-guard.git
```

For local development:

```bash
git clone https://github.com/hejr/agent-repo-guard.git
cd agent-repo-guard
python -m pip install -e .
```

## Use

Scan the current repository:

```bash
agent-repo-guard .
```

Generate SARIF for code scanning:

```bash
agent-repo-guard . --format sarif --output agent-repo-guard.sarif
```

Fail CI on medium-or-higher findings:

```bash
agent-repo-guard . --fail-on medium
```

Ignore generated paths in `.argignore`:

```gitignore
fixtures/generated/**
docs/vendor/**
```

Suppress a reviewed line with `# agent-repo-guard: ignore`. Suppressions should include a nearby explanation in production repositories.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Scan completed below the configured failure threshold |
| `2` | At least one finding met the failure threshold |

## Security model and limitations

The scanner never executes repository content and has no network integration. It reads bounded-size text files and reports deterministic pattern matches. It does not replace secret rotation, dependency review, sandboxing, CodeQL, or a professional security assessment. See [the threat model](docs/threat-model.md) for trust boundaries and known limitations.

## Project status

The first milestone is a stable, explainable ruleset with low-noise SARIF output. Adoption metrics are not claimed. Feedback should be filed as a reproducible issue, preferably with a minimized public fixture.

## Contributing and security reports

See [CONTRIBUTING.md](CONTRIBUTING.md) for development instructions. Please use GitHub's private vulnerability reporting flow for sensitive reports as described in [SECURITY.md](SECURITY.md).

## License

MIT © 2026 Serina James.
