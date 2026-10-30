"""OTX tagging unit cases (block 4). No key or network needed — the tagger only
reads a local JSON file, and a missing file must mean everything is `unknown`.
"""
from __future__ import annotations

import json
import os

from normalizer.enrich import OtxTagger
from tests.unit.factories import at, ssh_event


def test_missing_file_tags_unknown(tmp_path):
    tagger = OtxTagger(path=str(tmp_path / "does-not-exist.json"))
    ev = ssh_event(at(0), ip="203.0.113.5", outcome="failure")  # base severity 20
    tagger.tag(ev)
    assert ev.threat.indicator.status == "unknown"
    assert ev.event.severity == 20


def test_known_bad_adds_severity(tmp_path):
    path = tmp_path / "otx.json"
    path.write_text(json.dumps(["203.0.113.5", "198.51.100.9"]))
    tagger = OtxTagger(path=str(path))

    bad = ssh_event(at(0), ip="203.0.113.5", outcome="failure")  # 20 -> 40
    tagger.tag(bad)
    assert bad.threat.indicator.status == "known_bad"
    assert bad.event.severity == 40

    good = ssh_event(at(1), ip="10.0.0.1", outcome="success")    # private lab IP
    tagger.tag(good)
    assert good.threat.indicator.status == "unknown"
    assert good.event.severity == 0


def test_reloads_when_file_changes(tmp_path):
    path = tmp_path / "otx.json"
    path.write_text(json.dumps([]))
    os.utime(str(path), (1000, 1000))
    tagger = OtxTagger(path=str(path))

    ev1 = ssh_event(at(0), ip="203.0.113.5")
    tagger.tag(ev1)
    assert ev1.threat.indicator.status == "unknown"

    path.write_text(json.dumps(["203.0.113.5"]))
    os.utime(str(path), (2000, 2000))                 # distinct mtime -> reload
    ev2 = ssh_event(at(1), ip="203.0.113.5")
    tagger.tag(ev2)
    assert ev2.threat.indicator.status == "known_bad"
