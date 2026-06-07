"""Offline tests for capability_ledger — verdict logic, polarity, slope, and the
like-for-like segmentation that removes the corpus/config confound. No network.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import capability_ledger as cl  # noqa: E402


def _write(d: Path, name: str, ts: str, metrics: dict, corpus: dict | None = None, config: str | None = None) -> None:
    d.mkdir(parents=True, exist_ok=True)
    obj: dict = {"benchmark": name[:-5], "timestamp": ts, "metrics": metrics}
    if corpus is not None:
        obj["corpus"] = corpus
    if config is not None:
        obj["engine"] = config
    (d / name).write_text(json.dumps(obj), encoding="utf-8")


def _find(led: dict, bench: str, metric: str) -> dict | None:
    for v in led["variants"].values():
        if v["_meta"]["benchmark"] == bench and metric in v["metrics"]:
            return v["metrics"][metric]
    return None


def _variants_for(led: dict, bench: str) -> list[str]:
    return [k for k, v in led["variants"].items() if v["_meta"]["benchmark"] == bench]


def test_polarity():
    assert cl._polarity("clear_block_rate") == "higher_better"
    assert cl._polarity("fp_rate") == "lower_better"
    assert cl._polarity("obf_bypass_rate") == "lower_better"
    assert cl._polarity("recall") == "higher_better"


def test_slope_direction():
    assert cl._slope([0.2, 0.4, 0.6]) > 0
    assert cl._slope([0.6, 0.4, 0.2]) < 0


def test_higher_better_improving(tmp_path):
    _write(tmp_path / "g1", "policy.json", "2026-01-01T00:00:00", {"clear_block_rate": 0.50})
    _write(tmp_path / "g2", "policy.json", "2026-01-02T00:00:00", {"clear_block_rate": 0.75})
    _write(tmp_path / "g3", "policy.json", "2026-01-03T00:00:00", {"clear_block_rate": 1.00})
    led = cl.build_ledger(tmp_path)
    v = _find(led, "policy", "clear_block_rate")
    assert v and v["verdict"] == "improving"
    assert "COMPOUNDING" in led["overall"]


def test_lower_better_regressing(tmp_path):
    _write(tmp_path / "g1", "det.json", "2026-01-01T00:00:00", {"obf_bypass_rate": 0.10})
    _write(tmp_path / "g2", "det.json", "2026-01-02T00:00:00", {"obf_bypass_rate": 0.30})
    _write(tmp_path / "g3", "det.json", "2026-01-03T00:00:00", {"obf_bypass_rate": 0.55})
    led = cl.build_ledger(tmp_path)
    assert _find(led, "det", "obf_bypass_rate")["verdict"] == "regressing"
    assert "REGRESSING" in led["overall"]


def test_confound_benign_changed(tmp_path):
    _write(tmp_path / "g1", "aap.json", "2026-01-01T00:00:00", {"fp_rate": 0.04},
           corpus={"malicious_sha256": "MAL_SAME", "benign_sha256": "BEN_168"})
    _write(tmp_path / "g2", "aap.json", "2026-01-02T00:00:00", {"fp_rate": 0.005},
           corpus={"malicious_sha256": "MAL_SAME", "benign_sha256": "BEN_528"})
    led = cl.build_ledger(tmp_path)
    assert _find(led, "aap", "fp_rate")["verdict"] == "confounded-benign-changed"


def test_like_for_like_segments_no_false_regression(tmp_path):
    _write(tmp_path / "g1", "aap.json", "2026-01-01T00:00:00", {"block_rate": 0.63},
           corpus={"malicious_sha256": "CTI_CORPUS", "benign_sha256": "B"})
    _write(tmp_path / "g2", "aap.json", "2026-01-02T00:00:00", {"block_rate": 0.14},
           corpus={"malicious_sha256": "STANDARD_CORPUS", "benign_sha256": "B"})
    led = cl.build_ledger(tmp_path)
    assert len(_variants_for(led, "aap")) == 2
    assert "REGRESSING" not in led["overall"]


def test_example_results_compound():
    # the shipped example_results must demonstrate COMPOUNDING out of the box
    led = cl.build_ledger(Path(__file__).resolve().parent / "example_results")
    assert "COMPOUNDING" in led["overall"]
    assert _find(led, "policy_gate", "clear_block_rate")["verdict"] == "improving"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
