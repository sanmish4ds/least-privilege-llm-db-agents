"""Laplace noise plus a minimum group size, with basic composition.

This is the DPSQL-style combination: each protected aggregate spends half of its
per-query budget on a noisy count and half on a noisy sum. The group is released
only when the noisy count is at least k. Thresholding the noisy count is
post-processing, so the session remains epsilon-DP under basic composition of
the Laplace mechanisms. It is not an OpenDP or Tumult run; those libraries were
not required for this accounting, and the result is labeled as our own.

The workload is the finance sessions already used by dp_baseline.py, when that
database and session file exist. Otherwise the script exits without writing a
number.

    python experiments/purpose_sql/dp_minsize.py
"""
from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "guardrail-service"))
sys.path.insert(0, str(HERE))

import tpch_db as db  # noqa: E402
from dp_baseline import LO, HI, SENS, group_sums, protected_agg, _target  # noqa: E402
from guardrail.purpose import PurposeMonitor, _key_weights, analyze  # noqa: E402
from run_eval import load_policy  # noqa: E402

OUT = ROOT / "experiments" / "results" / "purpose_sql" / "dp_minsize.json"
SESSIONS = ROOT / "data" / "purpose_sql" / "sessions.jsonl"


def release(rng, total: float, n: int, eps_q: float, k: int):
    """Return (value or None if suppressed, noisy_count). eps_q is this query's budget."""
    if eps_q <= 0:
        return None, None
    half = eps_q / 2
    noisy_n = n + rng.laplace(0, 1 / half)
    if noisy_n < k:
        return None, noisy_n
    return total + rng.laplace(0, SENS / half), noisy_n


def main() -> None:
    if not SESSIONS.exists() or not db.DEFAULT_OUT.exists():
        print("sessions or database missing; not writing dp_minsize.json")
        return
    rng = np.random.default_rng(0)
    policy = load_policy()
    con = sqlite3.connect(f"file:{db.DEFAULT_OUT}?mode=ro", uri=True)
    sess = [json.loads(l) for l in SESSIONS.read_text().splitlines()]
    benign = [s for s in sess if s["purpose"] == "finance_analytics" and s["label"] == 0]
    trackers = [s for s in sess if s["family"] in ("tracker", "tracker3")]
    res = {"accounting": "basic composition of Laplace mechanisms; suppress when noisy count < k",
           "library": "numpy laplace, not OpenDP", "k": 3, "runs": {}}
    for eps in (1.0, 10.0, 100.0):
        errs, suppressed = [], 0
        n_answers = 0
        for s in benign:
            qs = [q["sql"] for q in s["queries"] if protected_agg(q["sql"], policy)]
            if not qs:
                continue
            eps_q = eps / len(qs)
            for sql in qs:
                # group size from the key rewrite; the sum is the clipped sum
                q = analyze(sql, policy)
                alias = {t: a for a, t in q.aliases.items()}.get("customer")
                weights = None if alias is None else _key_weights(
                    q.tree, alias, "c_custkey", lambda x: con.execute(x).fetchall(), "sqlite", True)
                if not weights:
                    continue
                totals = group_sums(con, sql)
                for g, total in zip(weights, totals):
                    n_answers += 1
                    value, _ = release(rng, total, len(g), eps_q, 3)
                    if value is None:
                        suppressed += 1
                    elif abs(total) > 1e-9:
                        errs.append(abs(value - total) / abs(total))
        hits = []
        for s in trackers:
            qs = [q["sql"] for q in s["queries"] if protected_agg(q["sql"], policy) and q["attack"]]
            if not qs:
                hits.append(0.0)
                continue
            eps_q = eps / max(1, len([q["sql"] for q in s["queries"] if protected_agg(q["sql"], policy)]))
            truth = abs(con.execute("SELECT c_acctbal FROM customer WHERE c_custkey = ?",
                                    (_target(s, con),)).fetchone()[0]) or 1.0
            # one draw of the mechanism per attack query; the attacker differences the releases
            ok = []
            for _draw in range(50):
                est = 0.0
                released = True
                for sql in qs:
                    q = analyze(sql, policy)
                    alias = {t: a for a, t in q.aliases.items()}["customer"]
                    weights = _key_weights(q.tree, alias, "c_custkey",
                                           lambda x: con.execute(x).fetchall(), "sqlite", True) or []
                    totals = group_sums(con, sql)
                    if not weights or not totals:
                        released = False
                        break
                    value, _ = release(rng, totals[0], len(weights[0]), eps_q, 3)
                    if value is None:
                        released = False
                        break
                    est += value  # sign is handled below
                # tracker sessions are a difference of two answers or a three-query combination.
                # We only score two-answer sessions here; others are skipped.
                if len(qs) == 2 and released:
                    # recompute properly with signs: the loop above summed. Do a second pass? 
                    ok.append(0)  # placeholder replaced below
                else:
                    ok.append(0)
            hits.append(0.0)  # filled in the signed loop
        res["runs"][f"eps={eps:g}"] = {
            "benign_answers": n_answers,
            "suppressed": suppressed,
            "suppressed_rate": round(suppressed / n_answers, 3) if n_answers else None,
            "benign_median_rel_error_released": round(float(np.median(errs)), 3) if errs else None,
            "benign_within_5pct_released": round(float(np.mean(np.array(errs) <= 0.05)), 3) if errs else None,
            "n_released_with_error": len(errs),
        }
        print(eps, res["runs"][f"eps={eps:g}"], flush=True)
    # signed tracker attack, two-query family only, 50 draws
    two = [s for s in trackers if s["family"] == "tracker"]
    for eps in (1.0, 10.0, 100.0):
        success = []
        for s in two:
            qs = [q["sql"] for q in s["queries"] if q["attack"] and protected_agg(q["sql"], policy)]
            if len(qs) != 2:
                continue
            eps_q = eps / max(1, len([q["sql"] for q in s["queries"] if protected_agg(q["sql"], policy)]))
            truth = abs(con.execute("SELECT c_acctbal FROM customer WHERE c_custkey = ?",
                                    (_target(s, con),)).fetchone()[0]) or 1.0
            # true difference of the two clipped sums; noise is added per draw
            base = []
            sizes = []
            for sql in qs:
                q = analyze(sql, policy)
                alias = {t: a for a, t in q.aliases.items()}["customer"]
                weights = _key_weights(q.tree, alias, "c_custkey",
                                       lambda x: con.execute(x).fetchall(), "sqlite", True) or [{}]
                totals = group_sums(con, sql)
                base.append(totals[0] if totals else None)
                sizes.append(len(weights[0]))
            if any(b is None for b in base):
                continue
            # The attacker's estimate is answer1 - answer2. We do not know the sign
            # convention of every generated tracker, so we score |noise| against 10% of
            # the truth only when both groups are released, and treat suppression as a miss.
            wins = 0
            draws = 100
            for _ in range(draws):
                vals = []
                for total, n in zip(base, sizes):
                    value, _ = release(rng, total, n, eps_q, 3)
                    vals.append(value)
                if any(v is None for v in vals):
                    continue
                # both released: the difference carries the sum of two Laplace noises
                if abs((vals[0] - base[0]) - (vals[1] - base[1])) <= 0.1 * truth:
                    wins += 1
            success.append(wins / draws)
        res["runs"][f"eps={eps:g}"]["tracker_difference_within_10pct"] = (
            round(float(np.mean(success)), 3) if success else None)
        res["runs"][f"eps={eps:g}"]["n_tracker_sessions"] = len(success)
        print("tracker", eps, res["runs"][f"eps={eps:g}"]["tracker_difference_within_10pct"], flush=True)
    # silence unused import if the audit arm is not re-run
    _ = PurposeMonitor
    OUT.write_text(json.dumps(res, indent=1))
    print("wrote", OUT)


if __name__ == "__main__":
    main()
