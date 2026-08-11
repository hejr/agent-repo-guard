# Threat model

## Scope

`agent-repo-guard` treats every scanned repository as untrusted input. The scanner is designed to identify a focused set of risks in agent-control files, shell automation, and GitHub Actions workflows without executing repository code.

## Assets

- Source code and unpublished changes on a maintainer workstation.
- Repository and organization tokens exposed to CI jobs.
- Developer credentials available to local coding tools.
- The integrity of automated review, release, and maintenance workflows.

## Adversaries

- A contributor who can modify an instruction or workflow file through a pull request.
- A compromised third-party GitHub Action or mutable action tag.
- Accidental inclusion of a credential or unsafe installation command.
- Malicious repository content opened by a coding agent with broad permissions.

## Trust boundaries

The scanner reads files from paths explicitly supplied by the user. It does not:

- execute files or shell commands from the target repository;
- resolve links or fetch remote content;
- access environment variables, credential stores, or Git metadata;
- parse or expand GitHub Actions expressions;
- claim that a pattern match proves malicious intent.

Symlinks encountered during directory traversal are resolved only when they remain inside the requested scan root. An explicitly supplied file path is still honored even when it sits outside the current working directory.

## Known limitations

- Pattern matching can produce false positives and false negatives.
- Multiline data flows and encoded payloads are not analyzed.
- YAML is inspected textually, so anchors and expression semantics are not fully modeled.
- Secret patterns cover a small set of recognizable formats.
- A clean report does not establish that a repository is secure.

## Security objectives

1. Never execute or import code from a scanned repository.
2. Bound memory use by skipping files over the configured size.
3. Produce deterministic, reviewable findings with source locations.
4. Keep the default rules narrow enough to be useful in pull requests.
5. Publish backward-compatible rule identifiers for SARIF consumers.
