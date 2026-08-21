# RedGap coverage report

- Mode: **replay**
- Run: `replay`
- Generated: 2026-08-11T00:00:00+00:00

**1 / 51 techniques detected.**

| # | ATT&CK | Technique | Tactic | Detected | Gap | Firing rule |
|---|--------|-----------|--------|----------|-----|-------------|
| 1 | T1087.001 | Account Discovery: Local Account | Discovery | yes | - | aaaa1111-0000-4000-8000-000000000001 |
| 2 | T1057 | Process Discovery | Discovery | no | base_rate | - |
| 3 | T1136.001 | Create Account: Local Account | Persistence | no | rule | - |
| 4 | T1548.001 | Abuse Elevation Control Mechanism: Setuid and Setgid | Privilege Escalation / Defense Evasion | no | rule | - |
| 5 | T1070.006 | Indicator Removal: Timestomp | Defense Evasion | no | rule | - |
| 6 | T1082 | System Information Discovery | Discovery | no | rule | - |
| 7 | T1016 | System Network Configuration Discovery | Discovery | no | rule | - |
| 8 | T1069.001 | Permission Groups Discovery: Local Groups | Discovery | no | rule | - |
| 9 | T1518.001 | Software Discovery: Security Software Discovery | Discovery | no | rule | - |
| 10 | T1083 | File and Directory Discovery | Discovery | no | rule | - |
| 11 | T1033 | System Owner/User Discovery | Discovery | no | base_rate | - |
| 12 | T1518 | Software Discovery | Discovery | no | rule | - |
| 13 | T1140 | Deobfuscate/Decode Files or Information | Defense Evasion | no | rule | - |
| 14 | T1222.002 | Linux and Mac File and Directory Permissions Modification | Defense Evasion | no | rule | - |
| 15 | T1070.004 | Indicator Removal: File Deletion | Defense Evasion | no | rule | - |
| 16 | T1497.001 | Virtualization/Sandbox Evasion: System Checks | Defense Evasion / Discovery | no | rule | - |
| 17 | T1059 | Command and Scripting Interpreter | Execution | no | rule | - |
| 18 | T1059.004 | Command and Scripting Interpreter: Unix Shell | Execution | no | rule | - |
| 19 | T1059.006 | Command and Scripting Interpreter: Python | Execution | no | base_rate | - |
| 20 | T1053.003 | Scheduled Task/Job: Cron | Execution / Persistence / Privilege Escalation | no | rule | - |
| 21 | T1053.002 | Scheduled Task/Job: At | Privilege Escalation / Execution / Persistence | no | rule | - |
| 22 | T1548 | Abuse Elevation Control Mechanism | Privilege Escalation / Defense Evasion | no | rule | - |
| 23 | T1546.004 | Event Triggered Execution: Unix Shell Configuration Modification | Persistence / Privilege Escalation | no | base_rate | - |
| 24 | T1098.004 | Account Manipulation: SSH Authorized Keys | Persistence / Privilege Escalation | no | rule | - |
| 25 | T1552.001 | Unsecured Credentials: Credentials In Files | Credential Access | no | rule | - |
| 26 | T1003.008 | OS Credential Dumping: /etc/passwd and /etc/shadow | Credential Access | no | rule | - |
| 27 | T1552.004 | Unsecured Credentials: Private Keys | Credential Access | no | rule | - |
| 28 | T1560.001 | Archive Collected Data: Archive via Utility | Collection | no | rule | - |
| 29 | T1005 | Data from Local System | Collection | no | base_rate | - |
| 30 | T1071.001 | Application Layer Protocol: Web Protocols | Command and Control | no | rule | - |
| 31 | T1090 | Proxy | Command and Control | no | rule | - |
| 32 | T1567 | Exfiltration Over Web Service | Exfiltration | no | rule | - |
| 33 | T1048.003 | Exfiltration Over Unencrypted Non-C2 Protocol | Exfiltration | no | rule | - |
| 34 | T1485 | Data Destruction | Impact | no | rule | - |
| 35 | T1489 | Service Stop | Impact | no | rule | - |
| 36 | T1653 | Power Settings | Persistence | no | rule | - |
| 37 | T1565.001 | Data Manipulation: Stored Data Manipulation | Impact | no | rule | - |
| 38 | T1592.004 | Gather Victim Host Information: Client Configurations | Reconnaissance | no | rule | - |
| 39 | T1007 | System Service Discovery | Discovery | no | rule | - |
| 40 | T1049 | System Network Connections Discovery | Discovery | no | rule | - |
| 41 | T1027 | Obfuscated Files or Information | Defense Evasion | no | rule | - |
| 42 | T1036 | Masquerading | Defense Evasion | no | rule | - |
| 43 | T1055.009 | Process Injection: Proc Memory | Defense Evasion / Privilege Escalation | no | rule | - |
| 44 | T1070 | Indicator Removal | Defense Evasion | no | rule | - |
| 45 | T1105 | Ingress Tool Transfer | Command and Control | no | rule | - |
| 46 | T1531 | Account Access Removal | Impact | no | rule | - |
| 47 | T1201 | Password Policy Discovery | Discovery | no | rule | - |
| 48 | T1614.001 | System Location Discovery: System Language Discovery | Discovery | no | rule | - |
| 49 | T1613 | Container and Resource Discovery | Discovery | no | rule | - |
| 50 | T1070.003 | Indicator Removal: Clear Command History | Defense Evasion | no | rule | - |
| 51 | T1543.002 | Create or Modify System Process: Systemd Service | Persistence / Privilege Escalation | no | rule | - |

## Gaps

A gap is a finding, not an error - each names why detection did not fire:

- **T1057 Process Discovery** - uncovered: telemetry present, but none of your rules fired (write a rule to close it)
- **T1136.001 Create Account: Local Account** - uncovered: telemetry present, but none of your rules fired (write a rule to close it)
- **T1548.001 Abuse Elevation Control Mechanism: Setuid and Setgid** - uncovered: telemetry present, but none of your rules fired (write a rule to close it)
- **T1070.006 Indicator Removal: Timestomp** - uncovered: telemetry present, but none of your rules fired (write a rule to close it)
- **T1082 System Information Discovery** - uncovered: telemetry present, but none of your rules fired (write a rule to close it)
- **T1016 System Network Configuration Discovery** - uncovered: telemetry present, but none of your rules fired (write a rule to close it)
- **T1069.001 Permission Groups Discovery: Local Groups** - uncovered: telemetry present, but none of your rules fired (write a rule to close it)
- **T1518.001 Software Discovery: Security Software Discovery** - uncovered: telemetry present, but none of your rules fired (write a rule to close it)
- **T1083 File and Directory Discovery** - uncovered: telemetry present, but none of your rules fired (write a rule to close it)
- **T1033 System Owner/User Discovery** - uncovered: telemetry present, but none of your rules fired (write a rule to close it)
- **T1518 Software Discovery** - uncovered: telemetry present, but none of your rules fired (write a rule to close it)
- **T1140 Deobfuscate/Decode Files or Information** - uncovered: telemetry present, but none of your rules fired (write a rule to close it)
- **T1222.002 Linux and Mac File and Directory Permissions Modification** - uncovered: telemetry present, but none of your rules fired (write a rule to close it)
- **T1070.004 Indicator Removal: File Deletion** - uncovered: telemetry present, but none of your rules fired (write a rule to close it)
- **T1497.001 Virtualization/Sandbox Evasion: System Checks** - uncovered: telemetry present, but none of your rules fired (write a rule to close it)
- **T1059 Command and Scripting Interpreter** - uncovered: telemetry present, but none of your rules fired (write a rule to close it)
- **T1059.004 Command and Scripting Interpreter: Unix Shell** - uncovered: telemetry present, but none of your rules fired (write a rule to close it)
- **T1059.006 Command and Scripting Interpreter: Python** - uncovered: telemetry present, but none of your rules fired (write a rule to close it)
- **T1053.003 Scheduled Task/Job: Cron** - uncovered: telemetry present, but none of your rules fired (write a rule to close it)
- **T1053.002 Scheduled Task/Job: At** - uncovered: telemetry present, but none of your rules fired (write a rule to close it)
- **T1548 Abuse Elevation Control Mechanism** - uncovered: telemetry present, but none of your rules fired (write a rule to close it)
- **T1546.004 Event Triggered Execution: Unix Shell Configuration Modification** - uncovered: telemetry present, but none of your rules fired (write a rule to close it)
- **T1098.004 Account Manipulation: SSH Authorized Keys** - uncovered: telemetry present, but none of your rules fired (write a rule to close it)
- **T1552.001 Unsecured Credentials: Credentials In Files** - uncovered: telemetry present, but none of your rules fired (write a rule to close it)
- **T1003.008 OS Credential Dumping: /etc/passwd and /etc/shadow** - uncovered: telemetry present, but none of your rules fired (write a rule to close it)
- **T1552.004 Unsecured Credentials: Private Keys** - uncovered: telemetry present, but none of your rules fired (write a rule to close it)
- **T1560.001 Archive Collected Data: Archive via Utility** - uncovered: telemetry present, but none of your rules fired (write a rule to close it)
- **T1005 Data from Local System** - uncovered: telemetry present, but none of your rules fired (write a rule to close it)
- **T1071.001 Application Layer Protocol: Web Protocols** - uncovered: telemetry present, but none of your rules fired (write a rule to close it)
- **T1090 Proxy** - uncovered: telemetry present, but none of your rules fired (write a rule to close it)
- **T1567 Exfiltration Over Web Service** - uncovered: telemetry present, but none of your rules fired (write a rule to close it)
- **T1048.003 Exfiltration Over Unencrypted Non-C2 Protocol** - uncovered: telemetry present, but none of your rules fired (write a rule to close it)
- **T1485 Data Destruction** - uncovered: telemetry present, but none of your rules fired (write a rule to close it)
- **T1489 Service Stop** - uncovered: telemetry present, but none of your rules fired (write a rule to close it)
- **T1653 Power Settings** - uncovered: telemetry present, but none of your rules fired (write a rule to close it)
- **T1565.001 Data Manipulation: Stored Data Manipulation** - uncovered: telemetry present, but none of your rules fired (write a rule to close it)
- **T1592.004 Gather Victim Host Information: Client Configurations** - uncovered: telemetry present, but none of your rules fired (write a rule to close it)
- **T1007 System Service Discovery** - uncovered: telemetry present, but none of your rules fired (write a rule to close it)
- **T1049 System Network Connections Discovery** - uncovered: telemetry present, but none of your rules fired (write a rule to close it)
- **T1027 Obfuscated Files or Information** - uncovered: telemetry present, but none of your rules fired (write a rule to close it)
- **T1036 Masquerading** - uncovered: telemetry present, but none of your rules fired (write a rule to close it)
- **T1055.009 Process Injection: Proc Memory** - uncovered: telemetry present, but none of your rules fired (write a rule to close it)
- **T1070 Indicator Removal** - uncovered: telemetry present, but none of your rules fired (write a rule to close it)
- **T1105 Ingress Tool Transfer** - uncovered: telemetry present, but none of your rules fired (write a rule to close it)
- **T1531 Account Access Removal** - uncovered: telemetry present, but none of your rules fired (write a rule to close it)
- **T1201 Password Policy Discovery** - uncovered: telemetry present, but none of your rules fired (write a rule to close it)
- **T1614.001 System Location Discovery: System Language Discovery** - uncovered: telemetry present, but none of your rules fired (write a rule to close it)
- **T1613 Container and Resource Discovery** - uncovered: telemetry present, but none of your rules fired (write a rule to close it)
- **T1070.003 Indicator Removal: Clear Command History** - uncovered: telemetry present, but none of your rules fired (write a rule to close it)
- **T1543.002 Create or Modify System Process: Systemd Service** - uncovered: telemetry present, but none of your rules fired (write a rule to close it)

## Evidence

Every detection is traceable to a rule and the exact event fields it matched:

- **T1087.001** - rule `aaaa1111-0000-4000-8000-000000000001` on event `ev_8cc32953659d6a0f`: `CommandLine`='cat /etc/passwd', `Image`='/usr/bin/cat'
