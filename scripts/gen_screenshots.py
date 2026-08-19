#!/usr/bin/env python3
"""Render the dashboard screenshots under ``docs/`` with headless Chrome.

Loads the committed ``docs/index.html`` in a real browser (Playwright driving the
system Chrome via ``channel="chrome"``, no browser download), forces the scroll-reveal
elements visible, and captures two PNGs:

    docs/screenshot-matrix.png       the full ATT&CK coverage grid (all 11 tactics)
    docs/screenshot-playground.png   the Detection Playground drawer for the setuid flagship

    pip install playwright && python scripts/gen_screenshots.py

Requires Google Chrome installed. These are real renders of the actual page, not mockups.
"""

from __future__ import annotations

from pathlib import Path

from playwright.sync_api import sync_playwright

DOCS = Path(__file__).resolve().parents[1] / "docs"
URL = (DOCS / "index.html").as_uri()

# Prep the page for a clean capture: force scroll-reveal elements visible (else the
# headless shot is blank), kill transitions, hide the sticky top bar (it would overlap
# the grid's top row in an element screenshot), and pin the matrix column width so all
# 11 tactic columns render compactly side by side instead of the 6-then-scroll layout.
FORCE_VISIBLE = """
for (const e of document.querySelectorAll('.reveal')) {
  e.style.opacity = '1'; e.style.transform = 'none';
}
const s = document.createElement('style');
s.textContent = '*{transition:none!important;animation:none!important}'
  + ' .matrix{grid-auto-columns:130px!important}';
document.head.appendChild(s);
const bar = document.querySelector('.topbar');
if (bar) bar.style.display = 'none';
const ms = document.querySelector('.matrix-scroll');
if (ms) ms.style.overflow = 'visible';
"""


def main() -> None:
    with sync_playwright() as p:
        browser = p.chromium.launch(channel="chrome", headless=True)
        page = browser.new_page(
            viewport={"width": 1500, "height": 1000},
            device_scale_factor=2,
            color_scheme="dark",
        )
        page.goto(URL, wait_until="networkidle")
        page.wait_for_selector("#matrix .cell", timeout=15000)
        page.evaluate(FORCE_VISIBLE)
        page.wait_for_timeout(500)

        page.locator("#matrix").screenshot(path=str(DOCS / "screenshot-matrix.png"))
        print("wrote docs/screenshot-matrix.png")

        page.locator('.cell[data-id="T1548.001"]').first.click()
        page.wait_for_selector("#drawer.open", timeout=5000)
        page.wait_for_timeout(400)
        # The drawer is viewport-tall with its own scroll; let it grow to its content so
        # the element screenshot captures the whole evidence panel (down to the verdict).
        page.evaluate(
            "const d=document.getElementById('drawer');"
            "d.style.height='auto';d.style.maxHeight='none';d.style.overflowY='visible';"
        )
        page.wait_for_timeout(200)
        page.locator("#drawer").screenshot(path=str(DOCS / "screenshot-playground.png"))
        print("wrote docs/screenshot-playground.png")

        browser.close()


if __name__ == "__main__":
    main()
