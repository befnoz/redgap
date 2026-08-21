# RedGap rule scorecard

- Mode: **replay**
- Run: `replay`
- Generated: 2026-08-11T00:00:00+00:00
- Rules dir: `tests/corpus/sigmahq_linux_process_creation`

**122 rules loaded** (34 firing, 50 SILENT, 38 out-of-corpus) - 0 unevaluable - **33/51** techniques detected.

## FIRING (34)

- `00b90cc1-17ec-402c-96ad-3a8117d7a582` Suspicious Curl File Upload - Linux - fired on T1567
- `0f79c4d2-4e1f-4683-9c36-b5469a665e06` Access of Sudoers File Content - fired on T1592.004
- `2953194b-e33c-4859-b9e8-05948c167447` DD File Overwrite - fired on T1485
- `30aed7b6-d2c1-4eaf-9382-b6bc43e50c57` File Deletion - fired on T1070.004
- `312b42b1-bded-4441-8b58-163a3af58775` Potentially Suspicious Execution From Tmp Folder - fired on T1036
- `34979410-e4b5-4e5d-8cfb-389fdff05c12` Remove Immutable File Attribute - fired on T1222.002
- `3f0f5957-04f8-4792-ad89-192b0303bde6` Python WebServer Execution - Linux - fired on T1048.003
- `403ed92c-b7ec-4edd-9947-5b535ee12d46` Crontab Enumeration - fired on T1007
- `42df45e7-e6e9-43b5-8f26-bec5b39cc239` System Information Discovery - fired on T1082
- `4c519226-f0cd-4471-bd2f-6fbb2bb68a79` System Network Connections Discovery - Linux - fired on T1049
- `4cad6c64-d6df-42d6-8dae-eb78defdc415` Potential Linux Process Code Injection Via DD Utility - fired on T1055.009
- `676381a6-15ca-4d73-a9c8-6a22e970b90d` Local Groups Discovery - Linux - fired on T1069.001
- `6b14bac8-3e3a-4324-8109-42f0546a347f` Scheduled Cron Task/Job - Linux - fired on T1053.003
- `72f4ab3f-787d-495d-a55d-68c2ff46cf4c` Connection Proxy - fired on T1090
- `86157017-c2b1-4d4a-8c33-93b8e67e4af4` Potential Suspicious Change To Sensitive/Critical Files - fired on T1565.001
- `880973f3-9708-491c-a77b-2a35a1921158` Linux Shell Pipe to Shell - fired on T1140
- `8a46f16c-8c4c-82d1-b121-0fdd3ba70a84` Group Has Been Deleted Via Groupdel - fired on T1531
- `8c1a5675-cb85-452f-a298-b01b22a51856` Suspicious Invocation of Shell via AWK - Linux - fired on T1059
- `95d61234-7f56-465c-6f2d-b562c6fedbc4` Linux Package Uninstall - fired on T1070
- `b45e3d6f-42c6-47d8-a478-df6bd6cf534c` Local System Accounts Discovery - Linux - fired on T1087.001
- `b86d356d-6093-443d-971c-9b07db583c68` Suspicious Curl Change User Agents - Linux - fired on T1071.001
- `ba592c6d-6888-43c3-b8c6-689b8fe47337` Linux Base64 Encoded Pipe to Shell - fired on T1140
- `bed978f8-7f3a-432b-82c5-9286a9b3031a` Shell Invocation via Env Command - Linux - fired on T1059.004
- `c172b7b5-f3a1-4af2-90b7-822c63df86cb` Mask System Power Settings Via Systemctl - fired on T1653
- `c21c4eaa-ba2e-419a-92b2-8371703cbe21` Setuid and Setgid - fired on T1548.001
- `c9d8b7fd-78e4-44fe-88f6-599135d46d60` Security Software Discovery - Linux - fired on T1518.001
- `d2d642d7-b393-43fe-bae4-e81ed5915c4b` Scheduled Task/Job At - fired on T1053.002
- `d3feb4ee-ff1d-4d3d-bd10-5b28a238cc72` File and Directory Discovery - Linux - fired on T1083
- `de25eeb8-3655-4643-ac3a-b662d3f26b6b` Disable Or Stop Services - fired on T1489
- `e2072cab-8c9a-459b-b63c-40ae79e27031` Decode Base64 Encoded Text - fired on T1027
- `e7bd1cfa-b446-4c88-8afb-403bcd79e3fa` System Network Discovery - Linux - fired on T1016
- `ea34fb97-e2c4-4afb-810f-785e4459b194` Curl Usage on Linux - fired on T1105
- `ed447910-bc30-4575-a598-3a2e49516a7a` Linux Setuid Capability Set on a Binary via Setcap Utility - fired on T1548
- `fa4aaed5-4fe0-498d-bbc0-08e3346387ba` Copy Passwd Or Shadow From TMP Path - fired on T1552.001

## SILENT (50)

- `067d8238-7127-451c-a9ec-fa78045b618b` Linux Doas Tool Execution - tagged to T1548 but never fired on real telemetry
- `08f26069-6f80-474b-8d1f-d971c6fedea0` User Has Been Deleted Via Userdel - tagged to T1531 but never fired on real telemetry
- `093d68c7-762a-42f4-9f46-95e79142571a` Shell Execution via Nice - Linux - tagged to T1083 but never fired on real telemetry
- `0cf7a157-8879-41a2-8f55-388dd23746b7` Linux Recon Indicators - tagged to T1552.001, T1592.004 but never fired on real telemetry
- `11701de9-d5a5-44aa-8238-84252f131895` Docker Container Discovery Via Dockerenv Listing - tagged to T1082 but never fired on real telemetry
- `1182f3b3-e716-4efa-99ab-d2685d04360f` History File Deletion - tagged to T1565.001 but never fired on real telemetry
- `297241f3-8108-4b3a-8c15-2dda9f844594` Suspicious Invocation of Shell via Rsync - tagged to T1059 but never fired on real telemetry
- `2992ac4d-31e9-4325-99f2-b18a73221bb2` ESXi VM Kill Via ESXCLI - tagged to T1059 but never fired on real telemetry
- `2d2f44ff-4611-4778-a8fc-323a0e9850cc` Inline Python Execution - Spawn Shell Via OS System Library - tagged to T1059 but never fired on real telemetry
- `31545105-3444-4584-bebf-c466353230d2` Touch Suspicious Service File - tagged to T1070, T1070.006 but never fired on real telemetry
- `33e814e0-1f00-4e43-9c34-31fb7ae2b174` ESXi Network Configuration Discovery Via ESXCLI - tagged to T1007, T1033, T1059 but never fired on real telemetry
- `38eb1dbb-011f-40b1-a126-cf03a0210563` ESXi Syslog Configuration Change Via ESXCLI - tagged to T1059 but never fired on real telemetry
- `3a716279-c18c-4488-83be-f9ececbfb9fc` Linux Setgid Capability Set on a Binary via Setcap Utility - tagged to T1548 but never fired on real telemetry
- `43e26eb5-cd58-48d1-8ce9-a273f5d298d8` Potential Container Discovery Via Inodes Listing - tagged to T1082 but never fired on real telemetry
- `47b3bbd4-1bf7-48cc-84ab-995362aaa75a` Shell Execution via Git - Linux - tagged to T1059 but never fired on real telemetry
- `4b09c71e-4269-4111-9cdd-107d8867f0cc` Shell Execution via Flock - Linux - tagged to T1083 but never fired on real telemetry
- `4e25af4b-246d-44ea-8563-e42aacab006b` Potential Xterm Reverse Shell - tagged to T1059 but never fired on real telemetry
- `55e862a8-dd9c-4651-807a-f21fcad56716` Python One-Liners with Base64 Decoding - Linux - tagged to T1027, T1059, T1059.006 but never fired on real telemetry
- `5cd16c8f-44a6-4654-81e7-a84d6db507d4` Process Execution From Shared Memory Directory - tagged to T1027 but never fired on real telemetry
- `5f1573a7-363b-4114-9208-ad7a61de46eb` ESXi VM List Discovery Via ESXCLI - tagged to T1007, T1033, T1059 but never fired on real telemetry
- `6419afd1-3742-47a5-a7e6-b50386cd15f8` Chmod Targeting Sensitive Directories - tagged to T1222.002 but never fired on real telemetry
- `6adfbf8f-52be-4444-9bac-81b539624146` Shell Execution via Find - Linux - tagged to T1083 but never fired on real telemetry
- `746c86fb-ccda-4816-8997-01386263acc4` Container Residence Discovery Via Proc Virtual FS - tagged to T1082 but never fired on real telemetry
- `7ab8f73a-fcff-428b-84aa-6a5ff7877dea` Vim GTFOBin Abuse - Linux - tagged to T1059, T1083 but never fired on real telemetry
- `7f734ed0-4f47-46c0-837f-6ee62505abd9` Potential Netcat Reverse Shell Execution - tagged to T1059 but never fired on real telemetry
- `8344c0e5-5783-47cc-9cf9-a0f7fd03e6cf` Potential Discovery Activity Using Find - Linux - tagged to T1083 but never fired on real telemetry
- `8737b7f6-8df3-4bb7-b1da-06019b99b687` Shell Invocation Via Ssh - Linux - tagged to T1059 but never fired on real telemetry
- `9691f58d-92c1-4416-8bf3-2edd753ec9cf` ESXi Admin Permission Assigned To Account Via ESXCLI - tagged to T1059 but never fired on real telemetry
- `9b5de532-a757-4d70-946c-1f3e44f48b4d` Shell Execution GCC  - Linux - tagged to T1083 but never fired on real telemetry
- `a2d9e2f3-0f43-4c7a-bcd9-9acfc0d723aa` Suspicious Download and Execute Pattern via Curl/Wget - tagged to T1059, T1059.004 but never fired on real telemetry
- `b28e4eb3-8bbc-4f0c-819f-edfe8e2f25db` ESXi Account Creation Via ESXCLI - tagged to T1059 but never fired on real telemetry
- `bb382fd5-b454-47ea-a264-1828e4c766d6` Shell Invocation via Apt - Linux - tagged to T1083 but never fired on real telemetry
- `c4042d54-110d-45dd-a0e1-05c47822c937` Python Spawning Pretty TTY Via PTY Module - tagged to T1059 but never fired on real telemetry
- `cf610c15-ed71-46e1-bdf8-2bd1a99de6c4` Download File To Potentially Suspicious Directory Via Wget - tagged to T1105 but never fired on real telemetry
- `d27ab432-2199-483f-a297-03633c05bae6` OS Architecture Discovery Via Grep - tagged to T1082 but never fired on real telemetry
- `d292e0af-9a18-420c-9525-ec0ac3936892` Suspicious Java Children Processes - tagged to T1059 but never fired on real telemetry
- `d54c2f06-aca9-4e2b-81c9-5317858f4b79` ESXi VSAN Information Discovery Via ESXCLI - tagged to T1007, T1033, T1059 but never fired on real telemetry
- `d7821ff1-4527-4e33-9f84-d0d57fa2fb66` Print History File Contents - tagged to T1592.004 but never fired on real telemetry
- `d7a650c4-226c-451e-948f-cc490db506aa` PUA - TruffleHog Execution - Linux - tagged to T1083, T1552.001 but never fired on real telemetry
- `d8d97d51-122d-4cdd-9e2f-01b4b4933530` Capabilities Discovery - Linux - tagged to T1083 but never fired on real telemetry
- `db1ac3be-f606-4e3a-89e0-9607cbe6b98a` Capsh Shell Invocation - Linux - tagged to T1059 but never fired on real telemetry
- `e2326866-609f-4015-aea9-7ec634e8aa04` Shell Execution via Rsync - Linux - tagged to T1059 but never fired on real telemetry
- `e34cfa0c-0a50-4210-9cb3-5632d08eb041` Potential GobRAT File Discovery Via Grep - tagged to T1082 but never fired on real telemetry
- `e4ffe466-6ff8-48d4-94bd-e32d1a6061e2` Nohup Execution - tagged to T1059, T1059.004 but never fired on real telemetry
- `e80273e1-9faf-40bc-bd85-dbaff104c4e9` ESXi System Information Discovery Via ESXCLI - tagged to T1007, T1033, T1059 but never fired on real telemetry
- `ea3ecad2-db86-4a89-ad0b-132a10d2db55` Interactive Bash Suspicious Children - tagged to T1036, T1059, T1059.004 but never fired on real telemetry
- `f0025a69-e1b7-4dda-a53c-db21fa2d4071` Script Interpreter Spawning Credential Scanner - Linux - tagged to T1005, T1059, T1059.004 but never fired on real telemetry
- `f41dada5-3f56-4232-8503-3fb7f9cf2d60` ESXi Storage Information Discovery Via ESXCLI - tagged to T1007, T1033, T1059 but never fired on real telemetry
- `f8341cb2-ee25-43fa-a975-d8a5a9714b39` BPFtrace Unsafe Option Usage - tagged to T1059, T1059.004 but never fired on real telemetry
- `fe2f9663-41cb-47e2-b954-8a228f3b9dff` Linux Base64 Encoded Shebang In CLI - tagged to T1140 but never fired on real telemetry

## OUT-OF-CORPUS (38)

- `0326c3c8-7803-4a0f-8c5c-368f747f7c3e` Triple Cross eBPF Rootkit Execve Hijack - tagged to no ATT&CK technique (no RedGap telemetry to exercise it)
- `11063ec2-de63-4153-935e-b1a8b9e616f1` Linux Remote System Discovery - tagged to T1018 (no RedGap telemetry to exercise it)
- `1f6b8cd4-3e60-47cc-b282-5aa1cbc9182d` Remote Access Tool - Team Viewer Session Started On Linux Host - tagged to T1133 (no RedGap telemetry to exercise it)
- `21541900-27a9-4454-9c4c-3f0a4240344a` OMIGOD SCX RunAsProvider ExecuteShellCommand - tagged to T1068, T1190, T1203 (no RedGap telemetry to exercise it)
- `22236d75-d5a0-4287-bf06-c93b1770860f` Triple Cross eBPF Rootkit Install Commands - tagged to T1014 (no RedGap telemetry to exercise it)
- `259df6bc-003f-4306-9f54-4ff1a08fa38e` Potential Perl Reverse Shell Execution - tagged to no ATT&CK technique (no RedGap telemetry to exercise it)
- `2fade0b6-7423-4835-9d4f-335b39b83867` Shell Execution Of Process Located In Tmp Directory - tagged to no ATT&CK technique (no RedGap telemetry to exercise it)
- `30bcce26-51c5-49f2-99c8-7b59e3af36c7` Execution Of Script Located In Potentially Suspicious Directory - tagged to no ATT&CK technique (no RedGap telemetry to exercise it)
- `32e62bc7-3de0-4bb1-90af-532978fe42c0` Python Reverse Shell Execution Via PTY And Socket Modules - tagged to no ATT&CK technique (no RedGap telemetry to exercise it)
- `36388120-b3f1-4ce9-b50b-280d9a7f4c04` Kaspersky Endpoint Security Stopped Via CommandLine - Linux - tagged to T1685 (no RedGap telemetry to exercise it)
- `3be619f4-d9ec-4ea8-a173-18fdd01996ab` Flush Iptables Ufw Chain - tagged to T1686 (no RedGap telemetry to exercise it)
- `3e102cd9-a70d-4a7a-9508-403963092f31` Linux Network Service Scanning Tools Execution - tagged to T1046 (no RedGap telemetry to exercise it)
- `3fcc9b35-39e4-44c0-a2ad-9e82b6902b31` Syslog Clearing or Removal Via System Utilities - tagged to T1685.006 (no RedGap telemetry to exercise it)
- `457df417-8b9d-4912-85f3-9dbda39c3645` Suspicious Nohup Execution - tagged to no ATT&CK technique (no RedGap telemetry to exercise it)
- `6104e693-a7d6-4891-86cb-49a258523559` Bash Interactive Shell - tagged to no ATT&CK technique (no RedGap telemetry to exercise it)
- `6a50f16c-3b7b-42d1-b081-0fdd3ba70a73` User Added To Root/Sudoers Group Using Usermod - tagged to no ATT&CK technique (no RedGap telemetry to exercise it)
- `6eea1bf6-f8d2-488a-a742-e6ef6c1b67db` OMIGOD SCX RunAsProvider ExecuteScript - tagged to T1068, T1190, T1203 (no RedGap telemetry to exercise it)
- `700fb7e8-2981-401c-8430-be58e189e741` Suspicious Package Installed - Linux - tagged to T1553.004 (no RedGap telemetry to exercise it)
- `7692f583-bd30-4008-8615-75dab3f08a99` Enable BPF Kprobes Tracing - tagged to no ATT&CK technique (no RedGap telemetry to exercise it)
- `78a80655-a51e-4669-bc6b-e9d206a462ee` Install Root Certificate - tagged to T1553.004 (no RedGap telemetry to exercise it)
- `80915f59-9b56-4616-9de0-fd0dea6c12fe` Linux Logs Clearing Attempts - tagged to T1685.006 (no RedGap telemetry to exercise it)
- `818f7b24-0fba-4c49-a073-8b755573b9c7` Linux Webshell Indicators - tagged to T1505.003 (no RedGap telemetry to exercise it)
- `84c9e83c-599a-458a-a0cb-0ecce44e807a` UFW Disable Attempt - tagged to T1686 (no RedGap telemetry to exercise it)
- `9069ea3c-b213-4c52-be13-86506a227ab1` Linux Crypto Mining Indicators - tagged to T1496 (no RedGap telemetry to exercise it)
- `97de11cd-4b67-4abf-9a8b-1020e670aa9e` Pnscan Binary Data Transmission Activity - tagged to T1046 (no RedGap telemetry to exercise it)
- `999c3b12-0a8c-40b6-8e13-dd7d62b75c7a` Potentially Suspicious Named Pipe Created Via Mkfifo - tagged to no ATT&CK technique (no RedGap telemetry to exercise it)
- `9d779ce8-5256-4b13-8b6f-b91c602b43f4` Named Pipe Created Via Mkfifo - tagged to no ATT&CK technique (no RedGap telemetry to exercise it)
- `a015e032-146d-4717-8944-7a1884122111` Linux HackTool Execution - tagged to T1587 (no RedGap telemetry to exercise it)
- `b8bdac18-c06e-4016-ac30-221553e74f59` Potential Ruby Reverse Shell - tagged to no ATT&CK technique (no RedGap telemetry to exercise it)
- `bed26dea-4525-47f4-b24a-76e30e44ffb0` Audit Rules Deleted Via Auditctl - tagged to T1685.004 (no RedGap telemetry to exercise it)
- `c2e234de-03a3-41e1-b39a-1e56dc17ba67` Remove Scheduled Cron Task/Job - tagged to no ATT&CK technique (no RedGap telemetry to exercise it)
- `c6714a24-d7d5-4283-a36b-3ffd091d5f7e` Potential PHP Reverse Shell - tagged to no ATT&CK technique (no RedGap telemetry to exercise it)
- `cfec9d29-64ec-4a0f-9ffe-0fdb856d5446` Suspicious Git Clone - Linux - tagged to T1593.003 (no RedGap telemetry to exercise it)
- `e3a8a052-111f-4606-9aee-f28ebeb76776` Disabling Security Tools - tagged to T1686 (no RedGap telemetry to exercise it)
- `ec127035-a636-4b9a-8555-0efd4e59f316` Clipboard Collection with Xclip Tool - tagged to T1115 (no RedGap telemetry to exercise it)
- `ec52985a-d024-41e3-8ff6-14169039a0b3` Mount Execution With Hidepid Parameter - tagged to T1564 (no RedGap telemetry to exercise it)
- `f2bed782-994e-4f40-9cd5-518198cb3fba` Linux Sudo Chroot Execution - tagged to T1068 (no RedGap telemetry to exercise it)
- `f9b3edc5-3322-4fc7-8aa3-245d646cc4b7` Potential Linux Amazon SSM Agent Hijacking - tagged to T1219.002 (no RedGap telemetry to exercise it)

## UNEVALUABLE (0)

- (none)
