"""Text, JSON, and SARIF report generation."""

from __future__ import annotations

import json
from collections import Counter
from typing import Iterable

from .models import Finding
from .rules import RULES


def render_text(findings: Iterable[Finding]) -> str:
    items = list(findings)
    if not items:
        return "No findings."
    lines: list[str] = []
    for item in items:
        lines.append(
            f"{item.path}:{item.line}: {item.severity.label()} {item.rule_id} "
            f"{item.title} — {item.message}"
        )
        if item.snippet:
            lines.append(f"  {item.snippet}")
        lines.append(f"  Fix: {item.recommendation}")
    counts = Counter(item.severity.label() for item in items)
    summary = ", ".join(f"{level}={counts[level]}" for level in sorted(counts))
    lines.append(f"\n{len(items)} finding(s): {summary}")
    return "\n".join(lines)


def render_json(findings: Iterable[Finding]) -> str:
    items = list(findings)
    return json.dumps(
        {"findings": [item.to_dict() for item in items], "total": len(items)},
        indent=2,
        ensure_ascii=False,
    )


def render_sarif(findings: Iterable[Finding]) -> str:
    items = list(findings)
    used_rule_ids = sorted({item.rule_id for item in items})
    rules = []
    for rule_id in used_rule_ids:
        rule = RULES[rule_id]
        rules.append(
            {
                "id": rule.rule_id,
                "name": rule.title.replace(" ", ""),
                "shortDescription": {"text": rule.title},
                "fullDescription": {"text": rule.description},
                "help": {"text": rule.recommendation},
                "defaultConfiguration": {"level": _sarif_level(rule.severity.label())},
            }
        )
    results = []
    for item in items:
        results.append(
            {
                "ruleId": item.rule_id,
                "level": _sarif_level(item.severity.label()),
                "message": {"text": item.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": item.path},
                            "region": {"startLine": item.line},
                        }
                    }
                ],
            }
        )
    report = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "agent-repo-guard",
                        "informationUri": "https://github.com/hejr/agent-repo-guard",
                        "rules": rules,
                        "version": "0.1.0",
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(report, indent=2, ensure_ascii=False)


def _sarif_level(severity: str) -> str:
    return {"low": "note", "medium": "warning", "high": "error", "critical": "error"}[severity]
