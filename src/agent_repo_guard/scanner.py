"""Repository traversal and security rule evaluation."""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Iterator

from .models import Finding
from .rules import (
    ACTION_USE,
    DESTRUCTIVE_REMOVE,
    FULL_SHA,
    INSTRUCTION_OVERRIDE,
    REMOTE_PIPE,
    RULES,
    SECRET_EXFIL,
    SECRET_PATTERNS,
    SENSITIVE_INSTRUCTION,
    WORLD_WRITABLE,
    WRITE_PERMISSION,
)


DEFAULT_EXCLUDES = (
    ".git/**",
    ".venv/**",
    "venv/**",
    "node_modules/**",
    "dist/**",
    "build/**",
    "*.egg-info/**",
    "__pycache__/**",
)
TEXT_SUFFIXES = {
    ".bash",
    ".conf",
    ".ini",
    ".json",
    ".md",
    ".mdc",
    ".py",
    ".sh",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
    ".zsh",
}
TEXT_NAMES = {"Dockerfile", "Makefile", "AGENTS.md", "CLAUDE.md", "SKILL.md"}
INSTRUCTION_NAMES = {"AGENTS.md", "CLAUDE.md", "SKILL.md", "copilot-instructions.md"}
SUPPRESSION = "agent-repo-guard: ignore"


@dataclass(slots=True)
class ScanOptions:
    max_file_size: int = 1_000_000
    excludes: list[str] = field(default_factory=list)


def _relative(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.resolve().as_posix()


def _load_ignore_file(root: Path) -> list[str]:
    ignore_file = root / ".argignore"
    if not ignore_file.is_file():
        return []
    return [
        line.strip()
        for line in ignore_file.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def _is_excluded(relative: str, patterns: Iterable[str]) -> bool:
    parts = relative.split("/")
    return any(
        fnmatch.fnmatch(relative, pattern)
        or fnmatch.fnmatch(Path(relative).name, pattern)
        or any(fnmatch.fnmatch(part, pattern.rstrip("/**")) for part in parts)
        for pattern in patterns
    )


def _is_text_candidate(path: Path) -> bool:
    return path.name in TEXT_NAMES or path.suffix.lower() in TEXT_SUFFIXES


def _iter_files(paths: Iterable[Path], root: Path, patterns: Iterable[str]) -> Iterator[Path]:
    seen: set[Path] = set()
    for raw_path in paths:
        path = raw_path.resolve()
        traversal_root = path if path.is_dir() else path.parent
        candidates = path.rglob("*") if path.is_dir() else (path,)
        for candidate in candidates:
            if not candidate.is_file() or not _is_text_candidate(candidate):
                continue
            resolved_candidate = candidate.resolve()
            if candidate.is_symlink() and not resolved_candidate.is_relative_to(traversal_root):
                continue
            relative = _relative(candidate, root)
            if _is_excluded(relative, patterns) or resolved_candidate in seen:
                continue
            seen.add(resolved_candidate)
            yield resolved_candidate


def _finding(rule_id: str, path: str, line: int, snippet: str, message: str | None = None) -> Finding:
    rule = RULES[rule_id]
    return Finding(
        rule_id=rule.rule_id,
        title=rule.title,
        severity=rule.severity,
        path=path,
        line=line,
        message=message or rule.description,
        recommendation=rule.recommendation,
        snippet=snippet.strip()[:240],
    )


def _is_instruction_file(relative: str) -> bool:
    path = Path(relative)
    return path.name in INSTRUCTION_NAMES or ".cursor/rules/" in relative


def _is_shell_or_workflow(relative: str) -> bool:
    path = Path(relative)
    return (
        path.suffix.lower() in {".sh", ".bash", ".zsh"}
        or path.name in {"Dockerfile", "Makefile"}
        or relative.startswith(".github/workflows/")
    )


def _scan_lines(relative: str, lines: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    instruction_file = _is_instruction_file(relative)
    shell_or_workflow = _is_shell_or_workflow(relative)

    for number, line in enumerate(lines, start=1):
        if SUPPRESSION in line:
            continue
        if instruction_file and INSTRUCTION_OVERRIDE.search(line):
            findings.append(_finding("ARG001", relative, number, line))
        if instruction_file and SENSITIVE_INSTRUCTION.search(line):
            findings.append(_finding("ARG002", relative, number, line))
        if shell_or_workflow and REMOTE_PIPE.search(line):
            findings.append(_finding("ARG003", relative, number, line))
        if shell_or_workflow and DESTRUCTIVE_REMOVE.search(line):
            findings.append(_finding("ARG004", relative, number, line))
        if shell_or_workflow and WORLD_WRITABLE.search(line):
            findings.append(_finding("ARG005", relative, number, line))
        if relative.startswith(".github/workflows/"):
            action_match = ACTION_USE.search(line)
            if action_match:
                reference = action_match.group(1)
                if not reference.startswith("./") and "@" in reference:
                    _, revision = reference.rsplit("@", 1)
                    if not FULL_SHA.fullmatch(revision):
                        findings.append(
                            _finding(
                                "ARG006",
                                relative,
                                number,
                                line,
                                f"Action reference '{reference}' is not pinned to a full commit SHA.",
                            )
                        )
            if SECRET_EXFIL.search(line):
                findings.append(_finding("ARG009", relative, number, line))
        if any(pattern.search(line) for pattern in SECRET_PATTERNS):
            findings.append(_finding("ARG008", relative, number, line))

    if relative.startswith(".github/workflows/") and any(
        "pull_request_target" in line for line in lines
    ):
        for number, line in enumerate(lines, start=1):
            if WRITE_PERMISSION.search(line) and SUPPRESSION not in line:
                findings.append(_finding("ARG007", relative, number, line))
    return findings


def scan_paths(
    paths: Iterable[str | Path],
    *,
    root: str | Path | None = None,
    options: ScanOptions | None = None,
) -> list[Finding]:
    """Scan files or directories and return findings in stable source order."""

    resolved_paths = [Path(path) for path in paths]
    if not resolved_paths:
        resolved_paths = [Path.cwd()]
    scan_root = Path(root).resolve() if root else Path.cwd().resolve()
    settings = options or ScanOptions()
    patterns = [*DEFAULT_EXCLUDES, *_load_ignore_file(scan_root), *settings.excludes]
    findings: list[Finding] = []

    for path in _iter_files(resolved_paths, scan_root, patterns):
        try:
            if path.stat().st_size > settings.max_file_size:
                continue
            raw = path.read_bytes()
        except OSError:
            continue
        if b"\x00" in raw[:4096]:
            continue
        text = raw.decode("utf-8", errors="replace")
        findings.extend(_scan_lines(_relative(path, scan_root), text.splitlines()))

    return sorted(findings, key=lambda item: (item.path, item.line, item.rule_id))
