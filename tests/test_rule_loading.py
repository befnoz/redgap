"""Loading rules: unsupported/broken rules are excluded with a warning (never silently
mismatched, never crashing the run), and both .yml and .yaml are loaded.
"""

from __future__ import annotations

import pytest

from redgap.detection.sigma_ast import load_rules, load_rules_detailed

GOOD = """
title: good
id: aaaaaaaa-0000-0000-0000-000000000001
logsource: {category: process_creation, product: linux}
detection:
  sel: {Image|endswith: '/cat'}
  condition: sel
tags: [attack.discovery, attack.t1087.001]
"""

BASE64 = """
title: b64
id: aaaaaaaa-0000-0000-0000-000000000002
logsource: {category: process_creation, product: linux}
detection:
  sel: {CommandLine|base64: 'chmod'}
  condition: sel
tags: [attack.t1548.001]
"""


def test_unsupported_rule_is_excluded_with_warning(tmp_path):
    (tmp_path / "good.yml").write_text(GOOD, encoding="utf-8")
    (tmp_path / "bad.yml").write_text(BASE64, encoding="utf-8")
    with pytest.warns(UserWarning):
        rules, excluded = load_rules_detailed(tmp_path)
    assert [r.id for r in rules] == ["aaaaaaaa-0000-0000-0000-000000000001"]
    assert len(excluded) == 1
    assert "bad.yml" in excluded[0][0]
    assert "base64" in excluded[0][1]


def test_yaml_extension_is_loaded(tmp_path):
    (tmp_path / "good.yaml").write_text(GOOD, encoding="utf-8")
    assert len(load_rules(tmp_path)) == 1


def test_one_bad_rule_does_not_abort_the_load(tmp_path):
    (tmp_path / "good.yml").write_text(GOOD, encoding="utf-8")
    (tmp_path / "bad.yml").write_text(BASE64, encoding="utf-8")
    with pytest.warns(UserWarning):
        rules = load_rules(tmp_path)
    assert len(rules) == 1  # the good rule still loads
