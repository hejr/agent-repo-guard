"""Data types shared by the scanner and report formatters."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import IntEnum


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> "Severity":
        try:
            return cls[value.strip().upper()]
        except KeyError as exc:
            choices = ", ".join(item.name.lower() for item in cls)
            raise ValueError(f"severity must be one of: {choices}") from exc

    def label(self) -> str:
        return self.name.lower()


@dataclass(frozen=True, slots=True)
class Finding:
    rule_id: str
    title: str
    severity: Severity
    path: str
    line: int
    message: str
    recommendation: str
    snippet: str = ""

    def to_dict(self) -> dict[str, object]:
        result = asdict(self)
        result["severity"] = self.severity.label()
        return result
