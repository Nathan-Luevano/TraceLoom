# Problems:
`I split this project into. I have taken a liking to LeetCode and whilst solving some I have choosen to split this project into Leetcode Style problems. Below find all the problems.`

---

## Problem 1: Join Attack Labels to Audit Events
### Difficulty: Medium
### Topic: File Parsing, dictionaries, streaming, malformed input

---

**Implement:**
```python
def load_labeled_events(
    log_path: str,
    labels_path: str
) -> list[dict]:
    ...
```

---

**The function receives:** (This is based off of the [Label Audit Logs](/russellmitchell_no-pcaps/labels/intranet_server/logs/audit/audit.log) and [Gather Audit Logs](/russellmitchell_no-pcaps/gather/intranet_server/logs/audit/audit.log))
1. A raw log file containing one event per line
2. A JSON-lines label file contain records like:
```json
{
  "line": 1860,
  "labels": ["attacker_change_user", "escalate"],
  "rules": {
    "attacker_change_user": ["attacker.escalate.audit.su.login"],
    "escalate": ["attacker.escalate.audit.su.login"]
  }
}
```
- Return only labeled events

---

**Requirements:**
- Do not load the entire raw audit log into memory (exception for label file)
- Preserve multiple labels assigned to one event
- Skip malformed labels