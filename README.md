# CodeAlpha Task 3 — Signature-based IDS

An original, offline-first network intrusion detection project. Instead of
requiring privileged raw-packet capture, it examines JSON Lines events exported
from an authorised monitor and flags selected suspicious request patterns.

## Run the demonstration

```bash
python3 detector.py sample_data/events.jsonl
```

Expected result: two alerts, for path traversal and an automated-scanner user
agent.

## Run tests

```bash
python3 -m unittest -v
```

## Detection rules

| Rule | Signal | Severity |
| --- | --- | --- |
| WEB-001 | Path traversal syntax | High |
| WEB-002 | Common SQL-injection keywords | Medium |
| WEB-003 | Known scanner user agents | Medium |
| SYS-001 | Command-interpreter reference | High |

Use this only with logs or network data you are authorised to analyse. These
rules are simple detection signals, not proof of malicious activity.
