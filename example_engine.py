"""
example_engine.py - an ILLUSTRATIVE policy gate (NOT a production ruleset).

A deliberately tiny set of textbook-obvious patterns, included only so that
`policy_bench.py` runs end-to-end out of the box and so you can see the
`audit(text) -> bool` interface. It scores mediocrely on the corpus - which is
exactly the point: naive pattern lists underperform, and the only way to know by
how much is to MEASURE. Replace this with your own engine to benchmark a real gate.

    python policy_bench.py --engine your_module

The production Aevora policy engine is part of the platform and is not bundled
here; this repository ships the corpus + harness so anyone can measure any gate.
"""
from __future__ import annotations

import re

# A handful of obvious dangerous-action patterns. Intentionally minimal.
_PATTERNS = [
    r"\brm\s+-rf\b",                 # recursive force-delete
    r"\bformat\s+[a-z]:",            # format a Windows volume
    r"\bdd\s+if=/dev/(zero|random)", # raw disk overwrite
    r"\bmkfs\b",                     # make filesystem (wipe)
    r":\(\)\s*\{.*\};\s*:",          # classic fork bomb
    r"\bvssadmin\s+delete\b",        # delete shadow copies
    r"\bwbadmin\s+delete\b",         # delete backups
    r"\breg\s+delete\b",             # delete registry keys
    r"\bcurl\b.*\|\s*(ba)?sh\b",     # curl | sh remote exec
    r"\.onion\b",                    # tor exfil endpoint
]
_RX = [re.compile(p, re.IGNORECASE) for p in _PATTERNS]


def audit(text: str) -> bool:
    """Return True to BLOCK the action. Illustrative only - do not ship."""
    return any(rx.search(text) for rx in _RX)
