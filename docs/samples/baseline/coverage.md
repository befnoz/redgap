# RedGap coverage report

- Mode: **replay**
- Run: `replay`
- Generated: 2026-08-11T00:00:00+00:00

**3 / 5 techniques detected.**

| # | ATT&CK | Technique | Tactic | Detected | Gap | Firing rule |
|---|--------|-----------|--------|----------|-----|-------------|
| 1 | T1087.001 | Account Discovery: Local Account | Discovery | yes | - | 7c1a9e10-1a2b-4c3d-8e4f-000000000087 |
| 2 | T1057 | Process Discovery | Discovery | no | base_rate | - |
| 3 | T1136.001 | Create Account: Local Account | Persistence | yes | - | 7c1a9e10-1a2b-4c3d-8e4f-000000000136 |
| 4 | T1548.001 | Abuse Elevation Control Mechanism: Setuid and Setgid | Privilege Escalation / Defense Evasion | yes | - | c21c4eaa-ba2e-419a-92b2-8371703cbe21 |
| 5 | T1070.006 | Indicator Removal: Timestomp | Defense Evasion | no | rule | - |

## Gaps

A gap is a finding, not an error — each names why detection did not fire:

- **T1057 Process Discovery** — base_rate: too noisy for a single-event rule; needs correlation (roadmap)
- **T1070.006 Indicator Removal: Timestomp** — rule: telemetry present, but no rule fired (closeable by writing a rule)

## Evidence

Every detection is traceable to a rule and the exact event fields it matched:

- **T1087.001** — rule `7c1a9e10-1a2b-4c3d-8e4f-000000000087` on event `ev_cf537b5c2d6309ee`: `CommandLine`='cat /etc/passwd', `Image`='/usr/bin/cat'
- **T1136.001** — rule `7c1a9e10-1a2b-4c3d-8e4f-000000000136` on event `ev_7a82c5de0c49e240`: `Image`='/usr/sbin/useradd'
- **T1548.001** — rule `c21c4eaa-ba2e-419a-92b2-8371703cbe21` on event `ev_8676a61a4976881c`: `CommandLine`="sh -c sh -c 'chown root /tmp/redgap_demo_suid && chmod u+s /tmp/redgap_demo_suid'"
- **T1548.001** — rule `c21c4eaa-ba2e-419a-92b2-8371703cbe21` on event `ev_54be21732e201e9c`: `CommandLine`='sh -c chown root /tmp/redgap_demo_suid && chmod u+s /tmp/redgap_demo_suid'
