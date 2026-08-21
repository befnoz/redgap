# RedGap rule scorecard

- Mode: **replay**
- Run: `replay`
- Generated: 2026-08-11T00:00:00+00:00
- Rules dir: `examples/my-sigma`

**3 rules loaded** (1 firing, 1 SILENT, 1 out-of-corpus) - 0 unevaluable - **1/51** techniques detected.

## FIRING (1)

- `aaaa1111-0000-4000-8000-000000000001` Local Account Enumeration via /etc/passwd - fired on T1087.001

## SILENT (1)

- `aaaa1111-0000-4000-8000-000000000002` OS Credential Dumping (mimikatz) - tagged to T1003.008 but never fired on real telemetry

## OUT-OF-CORPUS (1)

- `aaaa1111-0000-4000-8000-000000000003` Rundll32 Execution (Windows) - tagged to T1218.011 (no RedGap telemetry to exercise it)

## UNEVALUABLE (0)

- (none)
