# Security Policy

## Reporting a vulnerability

If you find a security issue in RedGap — or believe a technique module could be misused beyond its intended own-lab scope — please **do not open a public issue with exploit details**. Instead, open a minimal private report (GitHub Security Advisory on this repository) or contact the maintainer directly. You will get an acknowledgement as soon as possible.

## What RedGap is (and is not)

- RedGap targets **only its own disposable local lab** (loopback / the lab bridge). It has no capability to attack third-party systems and no free-form target flag. See [SCOPE.md](SCOPE.md) and [ETHICS.md](ETHICS.md).
- The telemetry collector (an `LD_PRELOAD` execve logger) is a **telemetry source for a lab we own, not a security control**. It only observes dynamically-linked `execve` calls and can be bypassed (static binaries, direct syscalls). Do not treat it as tamper-proof monitoring.
- The detection rules under `rules/` are for measuring coverage in this lab. They are ordinary Sigma and portable, but they are not a production ruleset.

## Supported versions

RedGap is pre-1.0. Only the latest `main` is supported.
