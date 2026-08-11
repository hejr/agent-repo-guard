"""Rule metadata and narrowly scoped detection patterns."""

from __future__ import annotations

import re
from dataclasses import dataclass

from .models import Severity


@dataclass(frozen=True, slots=True)
class Rule:
    rule_id: str
    title: str
    severity: Severity
    description: str
    recommendation: str


RULES: dict[str, Rule] = {
    "ARG001": Rule(
        "ARG001",
        "Instruction override pattern",
        Severity.HIGH,
        "An agent instruction attempts to override higher-priority guidance.",
        "Remove the override and document the intended behavior as a scoped repository rule.",
    ),
    "ARG002": Rule(
        "ARG002",
        "Sensitive-data instruction",
        Severity.CRITICAL,
        "An agent instruction requests secrets, credentials, or private machine data.",
        "Remove the instruction and use an explicit, least-privilege secret integration instead.",
    ),
    "ARG003": Rule(
        "ARG003",
        "Remote code execution pipeline",
        Severity.HIGH,
        "A remote response is piped directly into an interpreter.",
        "Download a versioned artifact, verify its checksum or signature, then execute it separately.",
    ),
    "ARG004": Rule(
        "ARG004",
        "Destructive shell command",
        Severity.HIGH,
        "A recursive destructive command can remove a broad path.",
        "Use an explicit validated target and a recoverable operation where possible.",
    ),
    "ARG005": Rule(
        "ARG005",
        "Overly permissive file mode",
        Severity.MEDIUM,
        "World-writable permissions weaken repository or runtime integrity.",
        "Grant only the owner/group permissions required by the workflow.",
    ),
    "ARG006": Rule(
        "ARG006",
        "Unpinned GitHub Action",
        Severity.MEDIUM,
        "A GitHub Action reference is mutable because it is not pinned to a commit SHA.",
        "Pin the action to a reviewed full commit SHA and retain the release tag in a comment.",
    ),
    "ARG007": Rule(
        "ARG007",
        "Privileged pull_request_target workflow",
        Severity.CRITICAL,
        "A pull_request_target workflow combines untrusted PR context with write permissions.",
        "Use pull_request with read-only permissions or isolate privileged work from untrusted code.",
    ),
    "ARG008": Rule(
        "ARG008",
        "Possible embedded credential",
        Severity.CRITICAL,
        "A line resembles a private key or service credential.",
        "Revoke and remove the credential, then load secrets through the platform secret store.",
    ),
    "ARG009": Rule(
        "ARG009",
        "Possible secret exfiltration",
        Severity.CRITICAL,
        "A network command appears to transmit a workflow secret or token.",
        "Remove the transmission and restrict tokens to the minimum permissions and destinations.",
    ),
}


INSTRUCTION_OVERRIDE = re.compile(
    r"\b(ignore|disregard|override)\b.{0,60}\b(previous|prior|system|developer|instructions?)\b",
    re.IGNORECASE,
)
SENSITIVE_INSTRUCTION = re.compile(
    r"\b(read|collect|copy|upload|send|post|transmit|reveal)\b.{0,100}"
    r"\b(secret|token|credential|password|private[ -]?key|\.ssh|keychain|environment variable)\b",
    re.IGNORECASE,
)
REMOTE_PIPE = re.compile(
    r"\b(curl|wget)\b[^\n|]{0,240}\|\s*(sudo\s+)?(sh|bash|zsh|python(?:3)?|node)\b",
    re.IGNORECASE,
)
DESTRUCTIVE_REMOVE = re.compile(
    r"\brm\s+(?:-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*|-[a-zA-Z]*f[a-zA-Z]*r[a-zA-Z]*)\s+"
    r"(?:/|~|\$HOME|\$\{HOME\}|\*)",
)
WORLD_WRITABLE = re.compile(r"\bchmod\s+(?:-R\s+)?777\b")
ACTION_USE = re.compile(r"^\s*-?\s*uses:\s*([^\s#]+)", re.IGNORECASE)
FULL_SHA = re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE)
WRITE_PERMISSION = re.compile(
    r"^\s*(permissions\s*:\s*write-all|(?:contents|pull-requests|issues|actions|id-token)\s*:\s*write)\s*$",
    re.IGNORECASE,
)
SECRET_EXFIL = re.compile(
    r"\b(curl|wget)\b.{0,240}(\$\{\{\s*secrets\.|\$\{?(?:TOKEN|API_KEY|PASSWORD|SECRET)\}?)",
    re.IGNORECASE,
)

# These definitions are suppressed during self-scans because they intentionally
# contain credential shapes. agent-repo-guard: ignore
SECRET_PATTERNS = (
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),  # agent-repo-guard: ignore
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),  # agent-repo-guard: ignore
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),  # agent-repo-guard: ignore
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),  # agent-repo-guard: ignore
)
