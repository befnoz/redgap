## What this changes

<!-- A short description of the change and why. -->

## Checklist

- [ ] `pytest` passes and `ruff check . && ruff format --check .` is clean
- [ ] Stays within RedGap's own-lab scope - no weaponized code, off-box actions, or real
      exploits (see SCOPE.md)
- [ ] New rules fire on real captured telemetry (fixture added); new techniques go through
      `redgap capture`, not hand-authored fixtures
- [ ] No secrets, real names, or absolute local paths introduced
