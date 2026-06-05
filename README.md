# Aevora Policy-Gate Bench

**100% block-rate on clear attacks · 0% false positives · 0.67 ms p95 — and an honest 91.7% obfuscation-bypass that we publish on purpose.**

A small, reproducible benchmark for **execution-time policy gates**: the layer that
decides whether an AI agent's *action* — a shell command, an API call, a tool
invocation — is allowed to run. Bring your own engine and measure it honestly
against a versioned adversarial corpus.

> In AI security you win with *numbers*, not claims. This repo is a methodology + a
> corpus you can run in one command — including the number we are **not** proud of.

---

## The headline, honestly

Measured on the **Aevora production policy engine** on 2026-06-04, against this exact
corpus (`malicious_actions.jsonl` 72 · `benign_actions.jsonl` 100, SHA-256 pinned in
[`corpora/README.md`](corpora/README.md)):

| Metric | Value | What it means |
|---|---|---|
| `clear_block_rate` | **100.0%** | non-obfuscated malicious actions blocked |
| `fp_rate` | **0.0%** | benign actions wrongly blocked (100-sample control) |
| `obf_bypass_rate` | **91.7%** | obfuscated malicious actions that **slipped through** |
| `latency` p50 / p95 | **0.41 / 0.67 ms** | per-decision wall time (CPU, no GPU) |

Read the third row again. A deterministic (regex/heuristic) policy gate blocks *clear*
attacks perfectly and never cries wolf — but it is **near-blind to obfuscation**
(base64, `$IFS` splitting, homoglyphs, zero-width characters). We publish that 91.7%
because it is the honest evidence that a single deterministic layer is **not enough**,
and it is exactly what justifies adding a second, semantic layer. A benchmark that
shows only its trophy numbers is marketing; one that shows its failures is engineering.

> The production engine ships with the Aevora platform and is **not** included here.
> This repository gives you the corpus + harness so the measurement is auditable and
> so you can run the same benchmark against **any** policy gate, including your own.

---

## Run it now (offline, one command, zero dependencies)

```bash
python policy_bench.py
```

This uses the **bundled illustrative engine** (`example_engine.py`) — a deliberately
tiny 10-pattern ruleset, here only to demonstrate the harness. Its honest score:

```
clear_block_rate : 27.1%   (non-obfuscated malicious blocked)
fp_rate          :  0.0%   (benign wrongly blocked)
obf_bypass_rate  : 91.7%   (obfuscated slipped through)
latency p95      : 0.06 ms
```

A naive 10-pattern list catches **27%** of clear attacks; the production engine
catches **100%**. That gap is the value of measuring instead of guessing.

| Engine | clear-block | FP | reproduce |
|---|---|---|---|
| `example_engine` (bundled, illustrative) | 27.1% | 0.0% | `python policy_bench.py` *(this repo, right now)* |
| Aevora production engine (platform) | 100.0% | 0.0% | plug the engine + `--engine`; corpus is public above |

---

## Plug your own engine

The interface is one function. Any importable Python module that exposes:

```python
def audit(text: str) -> bool:
    """Return True to BLOCK the action, False to allow."""
    ...
```

can be benchmarked:

```bash
python policy_bench.py --engine your_module --output results
```

You get `block_rate`, `clear_block_rate`, `obf_bypass_rate`, `fp_rate`, and latency
percentiles — the same metrics, computed the same way, on the same pinned corpus.

---

## What's measured

| Metric | Definition |
|---|---|
| `block_rate` | malicious blocked / all malicious (recall) |
| `clear_block_rate` | blocked / non-obfuscated malicious (the easy cases) |
| `obf_bypass_rate` | 1 − (blocked / obfuscated malicious) — **lower is better** |
| `fp_rate` | benign blocked / all benign (false alarms) |
| `latency_ms_p50/p95` | per-decision wall time |

Full definitions, corpus schema, and the obfuscation taxonomy are in
[`METHODOLOGY.md`](METHODOLOGY.md). The corpus is documented in
[`corpora/README.md`](corpora/README.md).

---

## Why this exists

- **EU AI Act Article 15** requires high-risk AI systems to *declare* accuracy,
  robustness, and cybersecurity levels. A declared number needs a reproducible test
  behind it. This is one.
- Most "AI security" repositories ship **zero** reproducible numbers. A single
  defensible, reproducible benchmark — including its weaknesses — beats ten unverified
  features.
- It runs **fully offline, on CPU**, with no third-party dependencies — by design
  (sovereign, air-gappable, auditable).

## Honesty rules (the methodology)

1. Every number is reproducible by one command, offline.
2. Results are append-only; a worse number is never silently overwritten by a better one.
3. We publish weaknesses (see `obf_bypass_rate`).
4. A number is always reported with its **corpus SHA-256 and date**.

## Not in this repo (by design)

- The **production policy engine** (part of the Aevora platform).
- The **input-time injection-defense** corpus and harness (prompt-injection / OWASP
  LLM01) — a separate, deliberate release.

## License

Apache-2.0 — see [`LICENSE`](LICENSE). Corpus is defensive evaluation data; see the
responsible-use note in [`corpora/README.md`](corpora/README.md).
