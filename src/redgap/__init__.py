"""RedGap — automated MITRE ATT&CK-mapped offense<->detection coverage harness.

The deterministic core (models, allowlist, telemetry schema, detection engine,
coverage) has no third-party dependencies beyond pySigma at the parsing edge and
never depends on a language model. The optional LLM planner lives behind the
``redgap[llm]`` extra and is disabled by default.
"""

__version__ = "0.2.0"
