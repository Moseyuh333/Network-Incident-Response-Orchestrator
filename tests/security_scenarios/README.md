# N.I.R.O. Security Scenario Test Suite

A self-contained, dependency-free test harness for validating the N.I.R.O.
detection engine against realistic attack traffic. Runs entirely against the
local N.I.R.O. instance (no network calls), so you can use it offline.

## What this answers

- **Does the rule engine actually catch the attack patterns it's supposed to?**
- **Where are the detection gaps?**
- **Does the system raise false positives on legitimate traffic?**
- **How does the ML anomaly detector score various attack shapes?**

Each scenario is one Python file. A scenario ingests synthetic events through
the real ingestion pipeline, then compares what N.I.R.O. detected to what we
*expected* to be detected. The result is reported in one of three buckets:

| Bucket | Meaning |
|---|---|
| ✅ `detected` | N.I.R.O. found the attack — passes the test. |
| 🟡 `partial` | N.I.R.O. found *some* but not *all* of the expected signals. |
| 🔴 `missed` | N.I.R.O. found nothing for an attack it should have caught. |
| ⚪ `false_positive` | N.I.R.O. raised an alert on traffic we marked as legitimate. |
| 🟣 `known_gap` | The system intentionally cannot detect this yet — test pins the gap so it shows up in future reports. |

## Layout

```
tests/security_scenarios/
├── README.md           ← you are here
├── run_all.py          ← one-shot runner, prints a coverage report
├── expectations.py     ← data class describing a scenario + expected findings
├── base.py             ← Scenario base class, ScenarioResult, registry
├── helpers.py          ← event builders + IP allocators
├── scenarios/          ← one .py file per attack pattern
│   ├── s01_horizontal_port_scan.py
│   ├── s02_slow_port_scan.py
│   ├── ...
│   └── s22_video_streaming.py
└── results/            ← JSON reports from previous runs (gitignored)
```

## Running

From the project root:

```bash
python -m tests.security_scenarios.run_all
# or:
python tests/security_scenarios/run_all.py
```

The runner prints a per-scenario table, a coverage summary, and a final
verdict ("Detection coverage: 12/22 scenarios detected, 5 known gaps, 3
false positives suppressed"). The full report is also written to
`tests/security_scenarios/results/last_run.json`.

## Adding a new scenario

1. Drop a new file in `scenarios/`. File name convention: `sNN_short_name.py`.
2. Subclass `base.Scenario`, fill in `id`, `title`, `category`,
   `expected_findings`, and implement `build_events()`.
3. The runner picks it up automatically (registry scans the `scenarios/`
   folder).

```python
# scenarios/s99_my_attack.py
from tests.security_scenarios.base import Scenario, ScenarioCategory
from tests.security_scenarios.helpers import event

class MyAttack(Scenario):
    id = "s99"
    title = "My new attack"
    category = ScenarioCategory.KNOWN_GAP  # or DETECT, FALSE_POSITIVE
    expected_findings = ["Brute Force"]
    notes = "Why this is or isn't caught."

    def build_events(self, alloc):
        return [
            event(
                external_id=f"{self.id}-001",
                source_ip=alloc.unique_ip("attacker"),
                ...
            ),
            ...
        ]
```

`alloc.unique_ip(role)` hands out a fresh RFC5737 documentation IP per
scenario so parallel runs never collide with the existing demo data or
each other.
