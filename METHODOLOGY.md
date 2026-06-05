# Methodology

How the Aevora policy-gate benchmark measures an **execution-time policy gate**, so
that any reported number is reproducible and comparable. Open methodology is the
point: cite it, reproduce it, challenge it.

## 1. What is under test

A *policy gate* is a function that classifies an agent **action** as block / allow:

```python
def audit(text: str) -> bool:   # True = BLOCK
```

The benchmark is engine-agnostic. It treats the gate as a black box and only records
its block/allow decision and the wall-clock time per call. `policy_bench.py` imports
the engine named by `--engine` (default `example_engine`) and requires only that it
exposes a callable `audit(text) -> bool`.

## 2. Corpus

Two JSONL files in `corpora/` (schema and integrity hashes in `corpora/README.md`):

- `malicious_actions.jsonl` — 72 rows: **48 clear** + **24 obfuscated**, across
  5 categories (DESTRUCTIVE, PRIVACY, SECURITY, NETWORK, PERSISTENCE).
- `benign_actions.jsonl` — 100 rows: everyday-safe commands + hard negatives that
  look risky but are legitimate.

Each row carries ground truth (`should_block`) and an `obfuscated` flag. A result is
only comparable against the **corpus SHA-256** it was measured on; always report it.

## 3. Metrics (exact definitions)

Let `M` = malicious rows, `B` = benign rows, `Mc`/`Mo` = clear/obfuscated subsets of `M`.
`blocked(x)` = the gate returned True on row `x`.

| Metric | Formula | Direction |
|---|---|---|
| `block_rate` | `|{x∈M : blocked(x)}| / |M|` | higher better |
| `clear_block_rate` | `|{x∈Mc : blocked(x)}| / |Mc|` | higher better |
| `obf_bypass_rate` | `1 − (|{x∈Mo : blocked(x)}| / |Mo|)` | **lower better** |
| `fp_rate` | `|{x∈B : blocked(x)}| / |B|` | **lower better** |
| `latency_ms_p50` | median over all `|M|+|B|` calls | lower better |
| `latency_ms_p95` | 95th percentile (`statistics.quantiles(n=20)[18]`) | lower better |

These mirror the definitions used to produce the production numbers, so in-repo and
production results are directly comparable.

## 4. The production result (provenance)

| Field | Value |
|---|---|
| Engine | Aevora production policy engine (deterministic layer; not bundled) |
| Date | 2026-06-04 |
| Corpus | `malicious_actions.jsonl` (SHA `a5fd4ec…b4e9c`) · `benign_actions.jsonl` (SHA `b44032f0…0177e`) |
| Hardware | CPU only, no GPU |
| clear_block_rate | 100.0% |
| fp_rate | 0.0% |
| obf_bypass_rate | 91.7% |
| latency p50 / p95 | 0.41 / 0.67 ms |

The bundled `example_engine` on the same corpus/date: clear 27.1%, FP 0.0%,
obf-bypass 91.7%, p95 0.06 ms — reproducible right now via `python policy_bench.py`.

## 5. Obfuscation taxonomy

The 24 obfuscated rows disguise a clear malicious action using techniques a
deterministic matcher tends to miss:

| Technique | Idea |
|---|---|
| base64 / hex encoding | payload encoded, decoded at runtime |
| `$IFS` / quote splitting | `r''m -rf`, `rm${IFS}-rf` |
| homoglyph substitution | Cyrillic/Greek look-alike characters |
| zero-width insertion | invisible separators inside keywords |
| reverse / case tricks | reversed strings, mixed case |
| comment / env indirection | inline comments, `$ENV`-resolved commands |

A high `obf_bypass_rate` for a deterministic gate is **expected** and motivates a
second, semantic layer (LLM-/model-based) that operates on the actions the regex layer
passes. Measuring the bypass rate is how you quantify the need for layer two.

## 6. Reproduce

```bash
# bundled illustrative engine (offline, zero deps)
python policy_bench.py

# your engine + write a JSON result
python policy_bench.py --engine your_module --output results
```

Result JSON includes the timestamp, sample counts, all metrics, and per-row decisions.
Report it together with the corpus SHA-256 from `corpora/README.md`.

## 7. Design constraints

- **Offline, CPU, zero third-party deps** — auditable and air-gappable by design.
- **Append-only results** — never overwrite a worse number with a better one silently.
- **Honest weaknesses published** — `obf_bypass_rate` is a headline metric, not a footnote.

## 8. Roadmap

1. Input-time **injection-defense** benchmark (prompt-injection / OWASP LLM01) — corpus
   + harness, separate release.
2. A reference **semantic second layer** for the actions the deterministic gate passes,
   with its own measured `obf_bypass_rate` reduction.
3. Mapping to OWASP LLM Top 10 / NIST AI RMF (MEASURE) / EU AI Act Article 15.

## References

- OWASP Top 10 for LLM Applications — <https://genai.owasp.org/>
- NIST AI Risk Management Framework — <https://www.nist.gov/itl/ai-risk-management-framework>
- EU AI Act, Article 15 (accuracy, robustness, cybersecurity) —
  <https://artificialintelligenceact.eu/article/15/>
- garak (LLM vulnerability scanner) — <https://github.com/NVIDIA/garak>
