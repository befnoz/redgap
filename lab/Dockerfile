# RedGap disposable lab — a throwaway Debian container the agent attacks.
#
# The execve collector (redgap_exec.so) is compiled in a build stage against the same
# glibc as the runtime, then preloaded system-wide via /etc/ld.so.preload so it records
# every dynamically-linked process's own execution. Runs unprivileged as container-root
# with Docker's default capabilities/seccomp (chown root + chmod u+s need only
# CHOWN/SETUID/SETGID/FOWNER, all in the default set). No network, no services.
#
# Pin by digest for reproducibility once built:
#   FROM debian:trixie@sha256:<digest> AS build   (and the same for the runtime base)

FROM debian:trixie AS build
RUN apt-get update \
 && apt-get install -y --no-install-recommends gcc libc6-dev \
 && rm -rf /var/lib/apt/lists/*
COPY collector/redgap_exec.c /src/redgap_exec.c
RUN gcc -O2 -fPIC -shared -Wall -Wextra -o /redgap_exec.so /src/redgap_exec.c

FROM debian:trixie-slim AS lab
# The tools the benign techniques exercise. Each package supplies a real binary a
# technique runs so its shipped Sigma rule fires on genuine telemetry:
#   bash coreutils procps passwd  -> cat/cp/chmod/chown/touch/dd/shred/sed, ps, useradd
#   e2fsprogs(chattr) ca-certificates(update-ca-certificates) cron(crontab) at(at)
#   libcap2-bin(setcap) curl python3 systemd(systemctl)  findutils grep sed(explicit)
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      bash coreutils findutils grep sed procps passwd \
      e2fsprogs ca-certificates cron at libcap2-bin curl python3 systemd \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /redgap_exec.so /usr/local/lib/redgap_exec.so
RUN mkdir -p /var/log/redgap \
 && chmod 0777 /var/log/redgap \
 && echo /usr/local/lib/redgap_exec.so > /etc/ld.so.preload \
 && test -s /etc/ld.so.preload
WORKDIR /root
CMD ["sleep", "infinity"]
