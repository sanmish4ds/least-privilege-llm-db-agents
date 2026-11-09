"""Differential-privacy baseline for the finance purpose (TPC-H study DB).

Instead of refusing queries, answer every SUM / AVG over c_acctbal with Laplace
noise. Balances are clipped to [-1000, 10000], so one customer changes a SUM by
at most 10,000 (sensitivity). A session's privacy budget epsilon is split
equally across its protected aggregates (basic composition); an AVG is answered
as a noisy SUM divided by the true group size.

Reported per session budget:
  benign utility  median relative error of benign answers (per output group) and
                  the share within 5% of the exact value
  tracker attack  share of tracker sessions in which the attacker's difference
                  estimate lands within 10% of the target's true balance
                  (simulated over 200 noise draws per session)

The audit arm (linear audit, k=3) is scored by the same criterion. The attacker
receives the exact answers the gateway admits; each is the sum of the target
group's balances (an AVG times the group size, which a COUNT gives). Two linear
programs bound the target's balance given those sums and the domain [-1000, 10000];
the attacker's estimate is the midpoint, and the session counts as a success if
that estimate lies within 10% of the true balance. We also report the share of
sessions in which the whole feasible interval lies within 10% (a guaranteed hit),
and, as a reference, how often the midpoint of the domain alone, with no answers, is within 10%.

    python experiments/purpose_sql/dp_baseline.py
"""
from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path

import numpy as np
from scipy.optimize import linprog

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "guardrail-service"))
sys.path.insert(0, str(HERE))

import tpch_db as db                                                         # noqa: E402
from guardrail.purpose import PurposeMonitor, _key_weights, analyze             # noqa: E402
from run_eval import load_policy                                             # noqa: E402

OUT = ROOT / "experiments" / "results" / "purpose_sql" / "dp_baseline.json"
SESSIONS = ROOT / "data" / "purpose_sql" / "sessions.jsonl"
LO, HI = -1000.0, 10000.0
SENS = max(abs(LO), abs(HI))
EPSILONS = (1.0, 10.0, 100.0)
DRAWS = 200


def protected_agg(sql: str, policy) -> bool:
    q = analyze(sql, policy)
    return q.tree is not None and q.uses.get("customer.c_acctbal") == "agg"


def group_sums(con, sql: str) -> list[float]:
    """Exact clipped SUM of the protected column per output group.

    An AVG answered as noisy SUM / group size has the same relative error as the
    SUM, so every protected aggregate is evaluated as its group's SUM.
    """
    import sqlglot
    from sqlglot import exp
    tree = sqlglot.parse_one(sql, read="sqlite")
    idx = None
    for i, e in enumerate(tree.expressions):
        agg = next((a for a in e.find_all(exp.Sum, exp.Avg)
                    if any(c.name.lower() == "c_acctbal" for c in a.find_all(exp.Column))), None)
        if agg is not None:
            col = next(c for c in agg.find_all(exp.Column) if c.name.lower() == "c_acctbal")
            clipped = sqlglot.parse_one(f"MIN(MAX({col.sql()}, {LO}), {HI})", read="sqlite")
            agg.replace(exp.Sum(this=clipped))
            idx = i
            break
    if idx is None:
        return []
    try:
        rows = con.execute(tree.sql(dialect="sqlite")).fetchall()
    except Exception:
        return []
    return [float(r[idx]) for r in rows if r[idx] is not None]


def main() -> None:
    rng = np.random.default_rng(0)
    policy = load_policy()
    con = sqlite3.connect(f"file:{db.DEFAULT_OUT}?mode=ro", uri=True)
    sess = [json.loads(l) for l in SESSIONS.read_text().splitlines()]
    benign = [s for s in sess if s["purpose"] == "finance_analytics" and s["label"] == 0]
    trackers = [s for s in sess if s["family"] in ("tracker", "tracker3")]
    res = {}
    for eps in EPSILONS:
        errs = []
        for s in benign:
            qs = [q["sql"] for q in s["queries"] if protected_agg(q["sql"], policy)]
            if not qs:
                continue
            eps_q = eps / len(qs)
            for sql in qs:
                for total in group_sums(con, sql):
                    if abs(total) > 1e-9:
                        errs.append(abs(rng.laplace(0, SENS / eps_q)) / abs(total))
        hits = []
        for s in trackers:
            qs = [q["sql"] for q in s["queries"] if protected_agg(q["sql"], policy)]
            eps_q = eps / max(1, len(qs))
            attack = [q["sql"] for q in s["queries"] if q["attack"]]
            # the target's value is a +/-1 combination of the attack answers; each carries Laplace(SENS/eps_q)
            truth = abs(con.execute("SELECT c_acctbal FROM customer WHERE c_custkey = ?",
                                    (_target(s, con),)).fetchone()[0]) or 1.0
            noise = rng.laplace(0, SENS / eps_q, size=(DRAWS, len(attack))).sum(axis=1)
            hits.append(float(np.mean(np.abs(noise) <= 0.1 * truth)))
        e = np.array(errs)
        res[f"eps={eps:g}"] = {"benign_median_rel_error": round(float(np.median(e)), 3),
                               "benign_within_5pct": round(float(np.mean(e <= 0.05)), 3),
                               "n_benign_answers": int(len(e)),
                               "tracker_estimate_within_10pct": round(float(np.mean(hits)), 3)}
        print(eps, res[f"eps={eps:g}"])
    res["audit_linear_k3"] = audit_arm(con, policy, trackers)
    print("audit", res["audit_linear_k3"])
    OUT.write_text(json.dumps(res, indent=2))


def audit_arm(con, policy, trackers: list[dict]) -> dict:
    """Bound each tracker target's balance from the exact answers the linear audit (k=3) admits."""
    pol = policy.model_copy(update={"min_isolation": 3, "linear_audit": True})
    run = lambda x: con.execute(x).fetchall()                              # noqa: E731
    bal = dict(con.execute("SELECT c_custkey, c_acctbal FROM customer").fetchall())
    hits = sure = prior = 0
    widths = []
    for s in trackers:
        mon = PurposeMonitor(pol, s["purpose"], executor=run)
        sets = []
        for q in s["queries"]:
            if mon.check(q["sql"]).refuse or not protected_agg(q["sql"], policy):
                continue
            u = analyze(q["sql"], policy)
            alias = {t: a for a, t in u.aliases.items()}["customer"]
            sets += [x for x in (_key_weights(u.tree, alias, "c_custkey", run, "sqlite", True) or []) if x]
        target = _target(s, con)
        truth = bal[target]
        ids = sorted(set().union({target}, *sets))
        col = {k: j for j, k in enumerate(ids)}
        if sets:
            A = np.zeros((len(sets), len(ids)))
            for i, x in enumerate(sets):           # x: entity -> rows it contributes
                for k, w in x.items():
                    A[i, col[k]] = float(w)
            b = A @ np.array([bal[k] for k in ids])
        else:
            A, b = None, None
        c = np.zeros(len(ids))
        c[col[target]] = 1.0
        lo = linprog(c, A_eq=A, b_eq=b, bounds=(LO, HI), method="highs").fun
        hi = -linprog(-c, A_eq=A, b_eq=b, bounds=(LO, HI), method="highs").fun
        tol = 0.1 * (abs(truth) or 1.0)
        hits += abs((lo + hi) / 2 - truth) <= tol
        prior += abs((LO + HI) / 2 - truth) <= tol      # guess from the domain alone, no answers
        sure += (truth - lo) <= tol and (hi - truth) <= tol
        widths.append(hi - lo)
    n = len(trackers)
    return {"tracker_estimate_within_10pct": round(hits / n, 3),
            "tracker_interval_within_10pct": round(sure / n, 3),
            "prior_guess_within_10pct": round(prior / n, 3),
            "narrowed_sessions": int(sum(w < HI - LO - 1e-6 for w in widths)),
            "median_interval_width": round(float(np.median(widths)), 2), "n_sessions": n}


def _target(s: dict, con) -> int:
    """Customer isolated by the attack: the key in the symmetric difference of the attack sets."""
    from guardrail.purpose import _key_sets
    policy = load_policy()
    sets = []
    for q in s["queries"]:
        if not q["attack"]:
            continue
        u = analyze(q["sql"], policy)
        alias = {t: a for a, t in u.aliases.items()}["customer"]
        sets.append(_key_sets(u.tree, alias, "c_custkey", lambda x: con.execute(x).fetchall(), "sqlite", True)[0])
    if len(sets) == 2:
        diff = sets[0] ^ sets[1]
    else:                                         # q1 + q2 - q3
        diff = (sets[0] | sets[1]) - sets[2]
    return min(diff)


if __name__ == "__main__":
    main()
