# RedGap attack path (adaptive-heuristic, replay)

**Chain:** Discovery -> Reconnaissance -> Privilege Escalation -> Execution -> Persistence -> Defense Evasion -> Credential Access -> Collection -> Command and Control -> Exfiltration -> Impact

| # | Technique | ID | Tactic | Verdict | Rules | Why chosen (source) |
|---|-----------|----|--------|---------|-------|---------------------|
| 1 | Account Discovery: Local Account | T1087.001 | Discovery | detected | 7c1a9e10-1a2b-4c3d-8e4f-000000000087 | seed - first catalog technique (heuristic) |
| 2 | Gather Victim Host Information: Client Configurations | T1592.004 | Reconnaissance | detected | 0f79c4d2-4e1f-4683-9c36-b5469a665e06 | breadth - opens untouched tactic Reconnaissance (heuristic) |
| 3 | Scheduled Task/Job: At | T1053.002 | Privilege Escalation / Execution / Persistence | detected | d2d642d7-b393-43fe-bae4-e81ed5915c4b | breadth - opens untouched tactic Privilege Escalation (heuristic) |
| 4 | Obfuscated Files or Information | T1027 | Defense Evasion | detected | e2072cab-8c9a-459b-b63c-40ae79e27031 | breadth - opens untouched tactic Defense Evasion (heuristic) |
| 5 | OS Credential Dumping: /etc/passwd and /etc/shadow | T1003.008 | Credential Access | GAP (rule) | - | breadth - opens untouched tactic Credential Access (heuristic) |
| 6 | Data from Local System | T1005 | Collection | GAP (base_rate) | - | breadth - opens untouched tactic Collection (heuristic) |
| 7 | Application Layer Protocol: Web Protocols | T1071.001 | Command and Control | detected | b86d356d-6093-443d-971c-9b07db583c68 | breadth - opens untouched tactic Command and Control (heuristic) |
| 8 | Exfiltration Over Unencrypted Non-C2 Protocol | T1048.003 | Exfiltration | detected | 3f0f5957-04f8-4792-ad89-192b0303bde6 | breadth - opens untouched tactic Exfiltration (heuristic) |
| 9 | Data Destruction | T1485 | Impact | detected | 2953194b-e33c-4859-b9e8-05948c167447 | breadth - opens untouched tactic Impact (heuristic) |
| 10 | Unsecured Credentials: Credentials In Files | T1552.001 | Credential Access | detected | fa4aaed5-4fe0-498d-bbc0-08e3346387ba | gap-chase - Credential Access already shows a gap (heuristic) |
| 11 | Unsecured Credentials: Private Keys | T1552.004 | Credential Access | GAP (rule) | - | gap-chase - Credential Access already shows a gap (heuristic) |
| 12 | Archive Collected Data: Archive via Utility | T1560.001 | Collection | GAP (rule) | - | gap-chase - Collection already shows a gap (heuristic) |

## Gaps on this path

Techniques the chain surfaced as undetected - point `redgap audit` at your rules to see which are SILENT (tagged but never firing on real telemetry):

- **T1003.008 OS Credential Dumping: /etc/passwd and /etc/shadow** - rule gap
- **T1005 Data from Local System** - base_rate gap
- **T1552.004 Unsecured Credentials: Private Keys** - rule gap
- **T1560.001 Archive Collected Data: Archive via Utility** - rule gap

_Agent stopped: max_steps after 12 step(s). The verdict is engine-computed from (events, rules); the planner only ordered the chain and decided when to stop._
