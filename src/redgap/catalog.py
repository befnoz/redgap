"""The technique catalog (metadata only), built from :mod:`redgap.techniques.catalog_data`.

Benign, MITRE ATT&CK-mapped techniques spanning the enterprise matrix. Execution and
cleanup live in the ``techniques/`` modules; this file is the pure-data catalog the
engine, coverage join, and reports use. The mix is deliberate — detections plus two
*kinds* of gap (rule / base-rate) — so the coverage report demonstrates real gap
intelligence rather than an all-green checklist.
"""

from __future__ import annotations

from redgap.models import Technique
from redgap.techniques.catalog_data import TECHNIQUES

CATALOG: tuple[Technique, ...] = tuple(
    Technique(
        id=t.id,
        name=t.name,
        tactics=t.tactics,
        description=t.description,
        atomic_ref=t.id,
        expected_gap_type=t.expected,
    )
    for t in TECHNIQUES
)

BY_ID: dict[str, Technique] = {t.id: t for t in CATALOG}
