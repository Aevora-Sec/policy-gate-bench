#!/usr/bin/env python3
"""
policy_bench.py - reproducible benchmark for execution-time policy gates.

A *policy gate* decides whether an AI agent's ACTION (a shell command, an API
call, a tool invocation) is allowed to run. This harness measures any such gate
against a versioned adversarial corpus and reports honest metrics - including the
ones you would rather not show.

Bring your own engine: pass --engine NAME where NAME is an importable module that
exposes `audit(text: str) -> bool` (return True to BLOCK). The bundled
`example_engine` is a deliberately small, ILLUSTRATIVE ruleset - NOT a production
gate - so the harness runs end-to-end out of the box.

Usage:
    python policy_bench.py                       # bundled illustrative engine
    python policy_bench.py --engine my_engine    # your gate
    python policy_bench.py --output results      # also write a JSON result

Metrics:
    block_rate        fraction of ALL malicious samples blocked (recall)
    clear_block_rate  block-rate on NON-obfuscated malicious (the easy cases)
    obf_bypass_rate   fraction of OBFUSCATED malicious that SLIPPED THROUGH
    fp_rate           fraction of benign samples wrongly blocked
    latency p50/p95   per-decision wall time (ms)

No third-party dependencies. Python 3.9+. Runs fully offline.
"""
from __future__ import annotations

import argparse
import importlib
import json
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
CORPORA = HERE / "corpora"


def load_corpus(path: Path) -> list[dict]:
    rows: list[dict] = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def load_engine(name: str):
    """Import a module exposing audit(text)->bool. Bundled engines live here."""
    sys.path.insert(0, str(HERE))
    try:
        mod = importlib.import_module(name)
    except Exception as exc:  # pragma: no cover
        sys.exit(f"FATAL: could not import engine '{name}': {exc}")
    audit = getattr(mod, "audit", None)
    if not callable(audit):
        sys.exit(f"FATAL: engine '{name}' must expose a callable audit(text: str) -> bool")
    return audit


def run(audit) -> dict:
    malicious = load_corpus(CORPORA / "malicious_actions.jsonl")
    benign = load_corpus(CORPORA / "benign_actions.jsonl")

    latencies: list[float] = []
    mal_blocked = 0
    obf_total = obf_blocked = 0
    clear_total = clear_blocked = 0
    mal_detail: list[dict] = []
    for row in malicious:
        t0 = time.perf_counter()
        blocked = bool(audit(row["text"]))
        latencies.append((time.perf_counter() - t0) * 1000)
        mal_blocked += int(blocked)
        if row.get("obfuscated"):
            obf_total += 1
            obf_blocked += int(blocked)
        else:
            clear_total += 1
            clear_blocked += int(blocked)
        mal_detail.append(
            {"id": row["id"], "blocked": blocked, "obfuscated": bool(row.get("obfuscated", False))}
        )

    fp = 0
    ben_detail: list[dict] = []
    for row in benign:
        t0 = time.perf_counter()
        blocked = bool(audit(row["text"]))
        latencies.append((time.perf_counter() - t0) * 1000)
        fp += int(blocked)
        ben_detail.append({"id": row["id"], "blocked": blocked})

    n_mal, n_ben = len(malicious), len(benign)
    p50 = statistics.median(latencies) if latencies else 0.0
    p95 = (
        statistics.quantiles(latencies, n=20)[18]
        if len(latencies) >= 20
        else max(latencies, default=0.0)
    )

    return {
        "benchmark": "aevora_policy_gate",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "samples": {"malicious": n_mal, "benign": n_ben},
        "metrics": {
            "block_rate": round(mal_blocked / n_mal, 4) if n_mal else None,
            "clear_block_rate": round(clear_blocked / clear_total, 4) if clear_total else None,
            "obf_bypass_rate": round(1 - obf_blocked / obf_total, 4) if obf_total else None,
            "fp_rate": round(fp / n_ben, 4) if n_ben else None,
            "latency_ms_p50": round(p50, 3),
            "latency_ms_p95": round(p95, 3),
        },
        "detail": {"malicious": mal_detail, "benign": ben_detail},
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="Reproducible execution-time policy-gate benchmark.")
    ap.add_argument(
        "--engine",
        default="example_engine",
        help="importable module exposing audit(text)->bool (default: example_engine)",
    )
    ap.add_argument("--output", default=None, help="dir to write a JSON result (default: print only)")
    args = ap.parse_args()

    audit = load_engine(args.engine)
    res = run(audit)
    m = res["metrics"]

    bar = "=" * 60
    print(bar)
    print(f"Aevora policy-gate benchmark  |  engine: {args.engine}")
    print(bar)
    print(f"  malicious samples : {res['samples']['malicious']}")
    print(f"  benign samples    : {res['samples']['benign']}")
    print("-" * 60)
    print(f"  clear_block_rate  : {m['clear_block_rate']:.1%}   (non-obfuscated malicious blocked)")
    print(f"  block_rate        : {m['block_rate']:.1%}   (all malicious blocked)")
    print(f"  obf_bypass_rate   : {m['obf_bypass_rate']:.1%}   (obfuscated slipped through)")
    print(f"  fp_rate           : {m['fp_rate']:.1%}   (benign wrongly blocked)")
    print(f"  latency p50 / p95 : {m['latency_ms_p50']:.2f} / {m['latency_ms_p95']:.2f} ms")
    print(bar)
    print("A high obf_bypass_rate is EXPECTED for a deterministic-only gate and is")
    print("the honest evidence that motivates a second (semantic) layer.")

    if args.output:
        outdir = Path(args.output)
        outdir.mkdir(parents=True, exist_ok=True)
        outfile = outdir / f"{args.engine}.json"
        outfile.write_text(json.dumps(res, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"\nresults written: {outfile}")


if __name__ == "__main__":
    main()
