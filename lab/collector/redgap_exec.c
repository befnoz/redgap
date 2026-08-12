/*
 * RedGap execve collector — a ~40-line LD_PRELOAD constructor.
 *
 * Loaded system-wide in the disposable lab container via /etc/ld.so.preload, this
 * runs once inside EVERY new dynamically-linked process (before its main) and records
 * that process's OWN execution to a log file, in the exact tab-delimited format
 * redgap.telemetry.snoopy.parse_snoopy_line expects:
 *
 *     REDGAP\t<pid>\t<user>\t<cwd>\t<exe>\t<cmdline>
 *
 * Why this instead of a fancier collector:
 *  - It captures `docker exec <cmd>` top-level commands directly (the process itself is
 *    preloaded), so no shell-wrapping workaround is needed.
 *  - It emits real 0x09 TAB bytes trivially (no INI/format ambiguity).
 *  - Pure userspace glibc: works unprivileged, identically on a Linux host and on
 *    Docker Desktop's WSL2/LinuxKit VM. No syslog daemon required.
 *  - It is a telemetry SOURCE for a lab we own, not a security control: it only sees
 *    dynamically-linked execve and is bypassable (static binaries, direct syscalls).
 *
 * It is INDEPENDENT of RedGap's attacker code: the offense only runs commands via
 * `docker exec`; this collector, loaded by the container's own dynamic linker, is what
 * produces the telemetry. RedGap's Python never writes this log.
 *
 * It calls no exec (cannot recurse) and never aborts its host process (every failure
 * path returns silently). Build:  gcc -O2 -fPIC -shared -o redgap_exec.so redgap_exec.c
 */

#define _GNU_SOURCE
#include <fcntl.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef REDGAP_LOG
#define REDGAP_LOG "/var/log/redgap/exec.log"
#endif

__attribute__((constructor)) static void redgap_record(void) {
    /* argv, from /proc/self/cmdline: NUL-separated -> space-joined. */
    char cmd[4096];
    int fd = open("/proc/self/cmdline", O_RDONLY);
    if (fd < 0) return;
    ssize_t n = read(fd, cmd, sizeof(cmd) - 1);
    close(fd);
    if (n <= 0) return;
    for (ssize_t i = 0; i < n; i++) {
        if (cmd[i] == '\0') cmd[i] = ' ';
    }
    while (n > 0 && cmd[n - 1] == ' ') n--;
    cmd[n] = '\0';

    /* resolved executable path -> the Image field. */
    char exe[1024];
    ssize_t e = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (e < 0) e = 0;
    exe[e] = '\0';

    char cwd[1024];
    if (!getcwd(cwd, sizeof(cwd))) {
        cwd[0] = '?';
        cwd[1] = '\0';
    }

    const char *user = "?";
    struct passwd *pw = getpwuid(geteuid());
    if (pw && pw->pw_name) user = pw->pw_name;

    char line[8192];
    int m = snprintf(line, sizeof(line), "REDGAP\t%d\t%s\t%s\t%s\t%s\n",
                     (int)getpid(), user, cwd, exe, cmd);
    if (m < 0) return;
    if (m > (int)sizeof(line)) m = (int)sizeof(line);

    /* Raw append open/write so even an instantly-exiting command (e.g. /bin/true)
     * is durably recorded. */
    int out = open(REDGAP_LOG, O_WRONLY | O_APPEND | O_CREAT, 0644);
    if (out < 0) return;
    (void)write(out, line, (size_t)m);
    close(out);
}
