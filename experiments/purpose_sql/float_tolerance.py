"""Compare the 1e-9 Gram-Schmidt rank test with exact rational elimination.

Weights are the integer row counts the audit actually stores. The script reports
how often the two tests disagree on which entities are exactly derivable.

    python experiments/purpose_sql/float_tolerance.py
"""
from __future__ import annotations

import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "guardrail-service"))
from guardrail.purpose import ExactLinearAuditor, LinearAuditor  # noqa: E402

OUT = ROOT / "experiments" / "results" / "purpose_sql" / "float_tolerance.json"


def _one(weights: list[dict]) -> dict:
    fl, ex = LinearAuditor(), ExactLinearAuditor()
    disagree = 0
    for w in weights:
        if set(fl.disclosed([w])) != set(ex.disclosed([w])):
            disagree += 1
        fl.commit([w])
        ex.commit([w])
    return {"steps": len(weights), "disagreement_steps": disagree,
            "final_float": len(fl.disclosed([])), "final_exact": len(set(ExactLinearAuditor._units(ex.rows)))}


def main() -> None:
    rng = random.Random(0)
    families = {}
    # unit-weight ranges, the shape of key-range aggregates
    trials = []
    for _ in range(200):
        n, m = 400, 30
        weights = []
        for _i in range(m):
            lo = rng.randrange(n)
            hi = min(n, lo + rng.randint(1, 40))
            weights.append({k: 1 for k in range(lo, hi)})
        trials.append(_one(weights))
    families["unit_ranges_n400"] = {
        "trials": len(trials),
        "trials_with_any_disagreement": sum(t["disagreement_steps"] > 0 for t in trials),
        "disagreement_steps": sum(t["disagreement_steps"] for t in trials),
    }
    # large integer multiplicities, the shape of a join fan-out
    trials = []
    for _ in range(200):
        weights = []
        for _i in range(25):
            support = rng.sample(range(80), rng.randint(2, 12))
            weights.append({k: rng.randint(1, 50) for k in support})
        trials.append(_one(weights))
    families["join_weights_1_to_50"] = {
        "trials": len(trials),
        "trials_with_any_disagreement": sum(t["disagreement_steps"] > 0 for t in trials),
        "disagreement_steps": sum(t["disagreement_steps"] for t in trials),
    }
    # a deliberately ill-conditioned pair: nearly dependent huge weights
    fl, ex = LinearAuditor(), ExactLinearAuditor()
    a = {0: 10**9, 1: 10**9}
    b = {0: 10**9, 1: 10**9 - 1}
    ill = set(fl.disclosed([a, b])) != set(ex.disclosed([a, b]))
    families["ill_conditioned_pair"] = {
        "float_disclosed": sorted(fl.disclosed([a, b])),
        "exact_disclosed": sorted(ex.disclosed([a, b])),
        "disagree": ill,
        "note": "weights (1e9, 1e9) and (1e9, 1e9-1). Their difference is e_1. "
                "Float Gram-Schmidt uses TOL=1e-9 on the projection diagonal.",
    }
    out = {"tolerance": LinearAuditor.TOL, "families": families}
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(out, indent=1))
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
