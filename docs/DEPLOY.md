# Deploying RedGap

Two independent things: the **web dashboard** (GitHub Pages) and the **`pip install redgap`**
package (PyPI). Both are wired with GitHub Actions; you only do a little one-time setup.

## 1. Web dashboard → GitHub Pages

`docs/index.html` is a self-contained dashboard (no external assets). It renders the real
coverage output - the ATT&CK heatmap, the coverage table, and the `--fix` round-trip toggle.

**One-time:** repo **Settings → Pages → Source = "GitHub Actions"**.

After that, every push to `main` that touches `docs/**` runs `.github/workflows/pages.yml`
and publishes to:

```
https://<your-username>.github.io/redgap/
```

That URL is the clickable proof to put in the CES application. (Prefer the branch method
instead? Settings → Pages → "Deploy from a branch" → `main` → `/docs` also works - then you
can delete `pages.yml`.)

## 2. `pip install redgap` → PyPI

The package is already wheel/sdist-clean (`python -m build` + `twine check` pass, and CI's
`install-smoke` job proves a non-editable install runs from any directory).

**First, check the name is free:** open <https://pypi.org/project/redgap/>. If it is taken,
rename the project in `pyproject.toml` (`name = "..."`, e.g. `redgap-coverage`) and update the
`url:` lines in `.github/workflows/publish.yml`.

**Set up Trusted Publishing (recommended - no tokens/secrets):**
1. On PyPI: your account → **Publishing** → **Add a pending publisher**.
2. Fill in: PyPI project name `redgap`, owner = your GitHub user, repository `redgap`,
   workflow `publish.yml`, environment `pypi`.
3. Save. (A "pending" publisher lets the very first release create the project.)

**Release:**
```bash
git tag v0.1.0
git push origin v0.1.0
```
The tag fires `.github/workflows/publish.yml`, which builds and publishes. Then anyone can:
```bash
pip install redgap
```

**Token fallback** (if you skip Trusted Publishing): create a PyPI API token, add it as the
repo secret `PYPI_API_TOKEN`, and pass `with: { password: ${{ secrets.PYPI_API_TOKEN }} }` to
the `pypa/gh-action-pypi-publish` step.

## Update the version

Bump `version` in `pyproject.toml`, then tag `v<that version>`. Keep the tag and the
`pyproject.toml` version in sync.
