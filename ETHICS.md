# Ethics

RedGap is a **defensive** tool: its purpose is to help a defender find out whether their detections actually fire. It is published in that spirit and engineered so it cannot easily be used for anything else.

## Hard rules (enforced in code and tests)

1. **Own-lab-only targeting.** RedGap acts only against its own disposable local lab. There is no free-form `--target host/ip` flag anywhere, and the live lab runs with **networking disabled**: every `docker run` is routed through `assert_lab_only` in `src/redgap/allowlist.py`, which refuses any launch that is not `--network none` (or pinned to the private lab subnet). `tests/test_allowlist.py` asserts that arbitrary hosts and networked launches are refused and that the allowlist cannot be widened via environment or CLI.

2. **Benign techniques only.** Every technique is a small, auditable module derived from a *published* Atomic Red Team test. It emits the observable artifact of an ATT&CK technique (a flagged command, a monitored write, a logging change) with **no exploit, no payload, no off-box action, and no runtime download**. Everything is vendored, which also keeps runs offline and reproducible.

3. **No weaponization by construction.** The privilege-escalation technique (T1548.001, Setuid) sets the setuid bit **only on an inert copy of `/bin/true`** — never on a shell or interpreter (`bash`, `sh`, `python`, ...), which would create a real local privilege-escalation primitive. This is asserted by a test (`tests/test_setuid_inert.py`).

4. **Idempotent, self-cleaning.** Every technique has an explicit cleanup step (delete the created account, remove the setuid copy, restore timestamps/logs) so repeated runs leave no residue.

5. **Integrity of the verdict.** The component that *attacks* never produces the telemetry the detection layer reads: the collector is the lab container's own `LD_PRELOAD` execve shim, and RedGap's Python never writes the log it later parses. A circular loop (attacker emits its own "detected" event) would make coverage meaningless, so independence is structural. That the verdict is a pure function of logs and rules — unchanged by the optional LLM — is asserted by `tests/test_planner.py` and `tests/test_determinism.py`.

## Why this is safe to publish

The techniques here are the same benign detection tests that defenders already run from Atomic Red Team; RedGap simply wraps a curated, scoped subset in a coverage loop against a container it spins up itself. It ships less capability than the tools it derives from, not more.

If you believe something in this repository crosses a line, please open an issue or contact the maintainer (see [SECURITY.md](SECURITY.md)).
