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
# bash+coreutils (cat/cp/chmod/chown/touch), procps (ps), passwd (useradd/userdel).
RUN apt-get update \
 && apt-get install -y --no-install-recommends bash coreutils procps passwd \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /redgap_exec.so /usr/local/lib/redgap_exec.so
RUN mkdir -p /var/log/redgap \
 && chmod 0777 /var/log/redgap \
 && echo /usr/local/lib/redgap_exec.so > /etc/ld.so.preload \
 && test -s /etc/ld.so.preload
WORKDIR /root
CMD ["sleep", "infinity"]
