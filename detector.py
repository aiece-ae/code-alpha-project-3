"""Offline-first signature detector for network event records.

The tool analyses JSON Lines input exported by an authorised network monitor. It
does not capture traffic itself, which makes demonstrations repeatable and
avoids requiring elevated privileges.
"""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True)
class Alert:
    rule_id: str
    title: str
    severity: str
    source: str
    destination: str
    protocol: str
    timestamp: str
    evidence: str


@dataclass(frozen=True)
class Rule:
    rule_id: str
    title: str
    severity: str
    expression: re.Pattern[str]


RULES = (
    Rule("WEB-001", "Path traversal pattern", "high", re.compile(r"(?:\.\./|%2e%2e%2f)", re.I)),
    Rule("WEB-002", "Possible SQL injection keyword", "medium", re.compile(r"\b(?:union\s+select|or\s+1\s*=\s*1)\b", re.I)),
    Rule("WEB-003", "Known automated scanner user agent", "medium", re.compile(r"user-agent:\s*(?:nikto|sqlmap|nmap)", re.I)),
    Rule("SYS-001", "Command interpreter reference", "high", re.compile(r"(?:/bin/(?:sh|bash)|cmd\.exe)", re.I)),
)


def _safe_evidence(payload: str, match: re.Match[str]) -> str:
    """Return a bounded, one-line context fragment for analyst triage."""
    start = max(0, match.start() - 28)
    end = min(len(payload), match.end() + 28)
    return " ".join(payload[start:end].split())[:100]


def inspect_event(event: dict[str, object]) -> list[Alert]:
    """Run all signatures against one validated event mapping."""
    payload = event.get("payload", "")
    if not isinstance(payload, str):
        return []

    common = {
        "source": str(event.get("source", "unknown")),
        "destination": str(event.get("destination", "unknown")),
        "protocol": str(event.get("protocol", "unknown")).upper(),
        "timestamp": str(event.get("timestamp", "unknown")),
    }
    alerts: list[Alert] = []
    for rule in RULES:
        match = rule.expression.search(payload)
        if match:
            alerts.append(Alert(
                rule_id=rule.rule_id,
                title=rule.title,
                severity=rule.severity,
                evidence=_safe_evidence(payload, match),
                **common,
            ))
    return alerts


def load_events(path: Path) -> Iterable[dict[str, object]]:
    """Yield valid JSON objects from a JSON Lines file with useful line errors."""
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON on line {number}: {exc.msg}") from exc
        if not isinstance(value, dict):
            raise ValueError(f"Line {number} must contain a JSON object.")
        yield value


def display_alert(alert: Alert) -> str:
    return (
        f"[{alert.severity.upper():6}] {alert.rule_id} — {alert.title}\n"
        f"  {alert.timestamp} | {alert.source} → {alert.destination} ({alert.protocol})\n"
        f"  Evidence: {alert.evidence}"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyse authorised network-event exports with IDS signatures.")
    parser.add_argument("input", type=Path, help="Path to a JSON Lines event file")
    parser.add_argument("--json", action="store_true", help="Print alerts as JSON")
    args = parser.parse_args()

    try:
        alerts = [alert for event in load_events(args.input) for alert in inspect_event(event)]
    except (OSError, ValueError) as error:
        parser.error(str(error))

    if args.json:
        print(json.dumps([asdict(alert) for alert in alerts], indent=2))
    elif alerts:
        print("\n\n".join(display_alert(alert) for alert in alerts))
    else:
        print("No signatures matched in the supplied event file.")

    print(f"\nSummary: {len(alerts)} alert(s) from {args.input.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
