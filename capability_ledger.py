#!/usr/bin/env python3
"""capability_ledger.py — does a self-improving security engine actually get STRONGER
over generations, or just busier?

Most "self-improving AI" dashboards track ACTIVITY — how many evolution cycles ran,
how many knowledge entries accumulated. Activity is not capability. A loop can spin,
a knowledge base can grow, and real detection capability can stay flat or regress.

This tool measures the thing that matters: the security-capability metrics recorded
in your benchmark result JSONs (`{benchmark, timestamp, metrics:{...}}`), as a TIME
SERIES across generations, and reports — honestly — whether each metric is
COMPOUNDING, FLAT, or REGRESSING.

LIKE-FOR-LIKE only. A "variant" is (benchmark, config, malicious-corpus fingerprint).
Comparing a 0.63 in-domain block-rate against a 0.14 external-corpus block-rate is a
confound that fakes a regression; this segments by corpus SHA + config so only
comparable runs form a series. FP-type metrics depend on the BENIGN set, so if that
changed within a series the verdict is `confounded-benign-changed`, not a false trend.

Pure stdlib, offline, deterministic. Point it at any folder of result JSONs:

    python capability_ledger.py --results example_results
    python capability_ledger.py --results <your eval results dir> --json

Honest-numbers by design: a measured "flat" beats an unmeasured "92% to AGI".
Part of Aevora policy-gate-bench — https://github.com/Aevora-Sec/policy-gate-bench
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_DEFAULT_RESULTS = _HERE / "example_results"

_LOWER_BETTER = ("fp", "false_positive", "bypass", "latency", "error", "miss")
_HIGHER_BETTER = ("clear_block", "block_rate", "recall", "auc", "precision", "mrr", "f1", "accuracy")
_FLAT_EPS = 0.005  # |slope per step| below this counts as FLAT


def _polarity(metric: str) -> str:
    m = metric.lower()
    if any(tok in m for tok in _LOWER_BETTER):
        return "lower_better"
    if any(tok in m for tok in _HIGHER_BETTER):
        return "higher_better"
    return "unknown"


def _slope(values: list[float]) -> float:
    n = len(values)
    if n < 2:
        return 0.0
    xs = list(range(n))
    mx = sum(xs) / n
    my = sum(values) / n
    num = sum((x - mx) * (y - my) for x, y in zip(xs, values))
    den = sum((x - mx) ** 2 for x in xs)
    return num / den if den else 0.0


def _identity(obj: dict) -> tuple[str, str, str]:
    """(config, malicious_fingerprint, benign_fingerprint) — compare only like-for-like."""
    config = obj.get("engine") or obj.get("pass") or "default"
    c = obj.get("corpus") or {}
    mal = c.get("malicious_sha256")
    ben = c.get("benign_sha256")
    if not mal:
        cs = obj.get("corpus_sha256") or {}
        mal, ben = cs.get("malicious"), cs.get("benign")
    if mal:
        return str(config), str(mal)[:10], (str(ben)[:10] if ben else "?")
    if c.get("malicious_rows") is not None:
        return str(config), f"m{c.get('malicious_rows')}", f"b{c.get('benign_rows', '?')}"
    s = obj.get("samples") or {}
    if s:
        return str(config), f"m{s.get('malicious', '?')}", f"b{s.get('benign', '?')}"
    return str(config), "nofp", "nofp"


def _load_result(path: Path) -> dict | None:
    try:
        obj = json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception:
        return None
    if not isinstance(obj, dict):
        return None
    metrics = obj.get("metrics")
    if not isinstance(metrics, dict):
        return None
    numeric = {k: float(v) for k, v in metrics.items() if isinstance(v, (int, float)) and v is not None}
    if not numeric:
        return None
    bench = str(obj.get("benchmark") or path.stem)
    ts = obj.get("timestamp") or datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc).isoformat()
    config, mal_fp, ben_fp = _identity(obj)
    return {
        "benchmark": bench, "config": config, "mal_fp": mal_fp, "ben_fp": ben_fp,
        "variant": f"{bench}  [{config}]  set={mal_fp}",
        "timestamp": str(ts), "metrics": numeric, "path": str(path),
    }


def collect(results_dir: Path) -> list[dict]:
    rows: list[dict] = []
    if not results_dir.is_dir():
        return rows
    for dirpath, _dirnames, filenames in os.walk(results_dir):
        for fn in filenames:
            if fn.endswith(".json"):
                r = _load_result(Path(dirpath) / fn)
                if r:
                    rows.append(r)
    rows.sort(key=lambda r: r["timestamp"])
    return rows


def build_ledger(results_dir: Path) -> dict:
    rows = collect(results_dir)
    series: dict[str, dict[str, list[tuple[str, float, str]]]] = {}
    meta: dict[str, dict] = {}
    for r in rows:
        b = series.setdefault(r["variant"], {})
        meta.setdefault(r["variant"], {"benchmark": r["benchmark"], "config": r["config"], "mal_fp": r["mal_fp"]})
        for k, v in r["metrics"].items():
            b.setdefault(k, []).append((r["timestamp"], v, r["ben_fp"]))

    report: dict[str, dict] = {}
    for variant, metrics in series.items():
        report[variant] = {"_meta": meta[variant], "metrics": {}}
        for metric, pts in metrics.items():
            vals = [v for _ts, v, _ben in pts]
            bens = {ben for _ts, _v, ben in pts}
            base = {"points": len(vals),
                    "first": round(vals[0], 4) if vals else None,
                    "latest": round(vals[-1], 4) if vals else None}
            if len(vals) < 2:
                report[variant]["metrics"][metric] = {**base, "verdict": "insufficient-data"}
                continue
            pol = _polarity(metric)
            base["delta"] = round(vals[-1] - vals[0], 4)
            if "fp" in metric.lower() and len(bens) > 1:
                report[variant]["metrics"][metric] = {**base, "polarity": pol, "verdict": "confounded-benign-changed"}
                continue
            sl = _slope(vals)
            if pol == "higher_better":
                verdict = "improving" if sl > _FLAT_EPS else "regressing" if sl < -_FLAT_EPS else "flat"
            elif pol == "lower_better":
                verdict = "improving" if sl < -_FLAT_EPS else "regressing" if sl > _FLAT_EPS else "flat"
            else:
                verdict = "changed" if abs(sl) > _FLAT_EPS else "flat"
            report[variant]["metrics"][metric] = {**base, "slope_per_step": round(sl, 5), "polarity": pol, "verdict": verdict}

    judged = [m for v in report.values() for m in v["metrics"].values()
              if m.get("verdict") in ("improving", "regressing", "flat")]
    improving = sum(1 for m in judged if m["verdict"] == "improving")
    regressing = sum(1 for m in judged if m["verdict"] == "regressing")
    flat = sum(1 for m in judged if m["verdict"] == "flat")
    n = len(judged)
    if n == 0:
        overall = "no-capability-series-yet (need ≥2 comparable runs)"
    elif regressing > improving:
        overall = "REGRESSING — capability is declining; the loop is not net-positive"
    elif improving > flat + regressing:
        overall = "COMPOUNDING — capability measurably improves across generations"
    elif improving > 0:
        overall = "MIXED — some metrics improve, others flat; net slightly positive"
    else:
        overall = "FLAT — activity without measurable capability gain"

    return {
        "schema": "capability-ledger/v2",
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "measurements": len(rows),
        "variants": report,
        "tally": {"improving": improving, "regressing": regressing, "flat": flat, "judged_metrics": n},
        "overall": overall,
    }


def _print_human(led: dict) -> None:
    bar = "=" * 66
    print(bar)
    print("CAPABILITY LEDGER — is the engine actually getting STRONGER?")
    print(bar)
    print(f"  measurements parsed : {led['measurements']}")
    t = led["tally"]
    print(f"  metrics judged      : {t['judged_metrics']}  "
          f"(^improving={t['improving']}  ~flat={t['flat']}  v regressing={t['regressing']})")
    print("  series are LIKE-FOR-LIKE: same benchmark + config + malicious corpus")
    print("-" * 66)
    for variant, blk in led["variants"].items():
        print(f"  {variant}")
        for metric, d in blk["metrics"].items():
            v = d.get("verdict")
            if v == "insufficient-data":
                print(f"     . {metric:<22} {str(d.get('latest')):<10} (n={d['points']}, need >=2)")
            elif v == "confounded-benign-changed":
                print(f"     ~ {metric:<22} {d['first']:>8} -> {d['latest']:<8} (benign set changed - not comparable)")
            else:
                sym = {"improving": "^", "regressing": "v", "flat": "~", "changed": "*"}.get(v, "?")
                print(f"     {sym} {metric:<22} {d['first']:>8} -> {d['latest']:<8} "
                      f"d={d['delta']:+.4f}  ({v}, n={d['points']})")
    print("-" * 66)
    print(f"  OVERALL: {led['overall']}")
    print(bar)
    print("  honest-numbers: a measured 'flat' beats an unmeasured 'self-improving!'")


def main() -> int:
    for _s in (sys.stdout, sys.stderr):
        try:
            _s.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    ap = argparse.ArgumentParser(description="Capability-over-generations ledger (offline, like-for-like).")
    ap.add_argument("--results", default=None, help="results dir (default: ./example_results)")
    ap.add_argument("--json", action="store_true", help="emit JSON only")
    args = ap.parse_args()
    led = build_ledger(Path(args.results) if args.results else _DEFAULT_RESULTS)
    if args.json:
        print(json.dumps(led, ensure_ascii=False, indent=2))
    else:
        _print_human(led)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
