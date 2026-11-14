"""Query-set search against the session audit. No LLM and no network.

For each of 100 targets the search spends at most 100 queries. It sees each
allow or refusal and the numeric answer. Strategies are the ones a
QuerySnout-style search uses: one customer's aggregate, a sum of two customers,
a nested complement, a three-query overlap, greedy key-range splitting, and
mutation of ranges. A fresh session then tries threshold bisection.

A target is recovered exactly when its unit vector lies in the span of the
admitted weight vectors, decided by the rational rank test. A sum of two
balances is counted on its own and is not exact recovery of either customer.

    python experiments/purpose_sql/attack_search.py
"""
from __future__ import annotations

import json
import random
import sqlite3
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "guardrail-service"))

from guardrail.purpose import (  # noqa: E402
    ExactLinearAuditor, LinearAuditor, PurposeMonitor, PurposePolicy, _key_weights, analyze,
)

OUT = ROOT / "experiments" / "results" / "purpose_sql" / "attack_search.json"
N = 1500
BUDGET = 100
N_TARGETS = 100
SEED = 21
LO, HI = -1000, 10000


def build() -> sqlite3.Connection:
    rng = random.Random(7)
    con = sqlite3.connect(":memory:")
    con.execute(
        "CREATE TABLE customer(c_custkey INT PRIMARY KEY, c_acctbal INT, "
        "c_mktsegment TEXT, c_nationkey INT)")
    segs = ["AUTOMOBILE", "BUILDING", "FURNITURE", "HOUSEHOLD", "MACHINERY"]
    con.executemany(
        "INSERT INTO customer VALUES (?,?,?,?)",
        [(k, rng.randint(LO, HI), segs[k % 5], k % 25) for k in range(1, N + 1)])
    return con


def policy(**kw) -> PurposePolicy:
    base = {
        "dialect": "sqlite",
        "schema": {"customer": {"c_custkey": "int", "c_acctbal": "int", "c_mktsegment": "text",
                                "c_nationkey": "int"}},
        "entities": {"customer": "c_custkey"},
        "sensitivity": {"customer.c_acctbal": 1.0},
        "purposes": {"finance": {"columns": {
            "customer.c_acctbal": "agg", "customer.c_custkey": "filter",
            "customer.c_mktsegment": "filter", "customer.c_nationkey": "filter"}}},
    }
    base.update(kw)
    return PurposePolicy.model_validate(base)


# stateless_* refuses a protected aggregate whose own group has fewer than k
# entities and nothing else. It does not use the monitor's min_isolation,
# because that flag also refuses nested differences (the pairwise defense).
DEFENSES = {
    "none": {},
    "stateless_k3": {"k": 3},
    "stateless_k5": {"k": 5},
    "stateless_k10": {"k": 10},
    "pairwise_k3": {"min_isolation": 3},
    "linear_k3": {"min_isolation": 3, "linear_audit": True},
    "linear_k5": {"min_isolation": 5, "linear_audit": True},
    "linear_k10": {"min_isolation": 10, "linear_audit": True},
    "exact_k3": {"min_isolation": 3, "linear_audit": True, "exact_linear": True},
    "strict_k3": {"min_isolation": 3, "linear_audit": True, "strict_protected": True},
}


class Session:
    def __init__(self, con: sqlite3.Connection, defense: str):
        self.con = con
        self.defense = defense
        spec = DEFENSES[defense]
        self.k = spec.get("k")
        mon_kw = {k: v for k, v in spec.items() if k != "k"}
        self.mon = PurposeMonitor(policy(**mon_kw), "finance", executor=lambda q: con.execute(q).fetchall())
        self.exact = ExactLinearAuditor()
        self.float = LinearAuditor()
        self.queries = 0
        self.refusals = 0
        self.disagreement = 0

    def _weights(self, sql: str):
        q = analyze(sql, self.mon.policy)
        if q.tree is None or q.uses.get("customer.c_acctbal") != "agg":
            return None
        alias = {t: a for a, t in q.aliases.items()}.get("customer")
        if alias is None:
            return None
        return _key_weights(q.tree, alias, "c_custkey", lambda s: self.con.execute(s).fetchall(),
                            "sqlite", True)

    def ask(self, sql: str):
        if self.queries >= BUDGET:
            return None
        self.queries += 1
        weights = self._weights(sql)
        if self.k is not None:
            # cell suppression only. Predicate queries are not aggregates.
            if weights is not None and any(len(g) < self.k for g in weights):
                self.refusals += 1
                return None
        else:
            sig = self.mon.check(sql)
            if sig.refuse:
                self.refusals += 1
                return None
        if weights:
            for g in weights:
                if set(self.float.disclosed([g])) != set(self.exact.disclosed([g])):
                    self.disagreement += 1
                self.float.commit([g])
                self.exact.commit([g])
        row = self.con.execute(sql).fetchone()
        return 0.0 if row is None or row[0] is None else float(row[0])

    def holds(self, target: int) -> bool:
        return target in set(ExactLinearAuditor._units(self.exact.rows))


def attack_one(con, defense: str, target: int, bal: dict[int, int]) -> dict:
    s = Session(con, defense)
    hit = {name: False for name in
           ("singleton", "sum_of_two", "complement", "three_query", "greedy_split", "evolutionary")}
    seg = con.execute("SELECT c_mktsegment FROM customer WHERE c_custkey = ?", (target,)).fetchone()[0]
    other = 1 if target != 1 else 2

    if s.ask(f"SELECT SUM(c_acctbal) FROM customer WHERE c_custkey = {target}") is not None and s.holds(target):
        hit["singleton"] = True
    pair = s.ask(f"SELECT SUM(c_acctbal) FROM customer WHERE c_custkey IN ({target}, {other})")
    pair_sum = (pair is not None and abs(pair - (bal[target] + bal[other])) < 1e-6 and not s.holds(target))

    if not s.holds(target):
        s.ask(f"SELECT SUM(c_acctbal) FROM customer WHERE c_mktsegment = '{seg}'")
        s.ask(f"SELECT SUM(c_acctbal) FROM customer WHERE c_mktsegment = '{seg}' AND c_custkey <> {target}")
        if s.holds(target):
            hit["complement"] = True
    if not s.holds(target):
        s.ask(f"SELECT SUM(c_acctbal) FROM customer WHERE c_custkey BETWEEN 1 AND {target}")
        s.ask(f"SELECT SUM(c_acctbal) FROM customer WHERE c_custkey BETWEEN {target} AND {N}")
        s.ask("SELECT SUM(c_acctbal) FROM customer")
        if s.holds(target):
            hit["three_query"] = True
    lo, hi = 1, N
    guard = 0
    while not s.holds(target) and hi > lo and s.queries < BUDGET and guard < 40:
        guard += 1
        mid = (lo + hi) // 2
        if target <= mid:
            sql, nxt = (f"SELECT SUM(c_acctbal) FROM customer WHERE c_custkey BETWEEN {lo} AND {mid}", (lo, mid))
        else:
            sql, nxt = (f"SELECT SUM(c_acctbal) FROM customer WHERE c_custkey BETWEEN {mid + 1} AND {hi}",
                        (mid + 1, hi))
        if s.ask(sql) is None:
            break
        lo, hi = nxt
    if s.holds(target) and not any(hit.values()):
        hit["greedy_split"] = True
    rng = random.Random(10_000 + target)
    pop = [(1, N), (max(1, target - 30), min(N, target + 30))]
    while not s.holds(target) and s.queries < BUDGET and pop:
        a, b = pop[rng.randrange(len(pop))]
        if b > a:
            cut = rng.randint(a, b - 1)
            nxt = (a, cut) if a <= target <= cut else (cut + 1, b)
            if nxt[0] > nxt[1] or not (nxt[0] <= target <= nxt[1]):
                nxt = (a, b)
        else:
            nxt = (a, b)
        if s.ask(f"SELECT SUM(c_acctbal) FROM customer WHERE c_custkey BETWEEN {nxt[0]} AND {nxt[1]}") is not None:
            pop.append(nxt)
            if len(pop) > 16:
                pop.pop(0)
    if s.holds(target) and not any(hit.values()):
        hit["evolutionary"] = True

    bis = Session(con, defense)
    lo_b, hi_b, steps = LO, HI, 0
    while hi_b - lo_b > 1 and steps < 20 and bis.queries < 24:
        steps += 1
        mid = (lo_b + hi_b) // 2
        ans = bis.ask(f"SELECT COUNT(*) FROM customer WHERE c_custkey = {target} AND c_acctbal > {mid}")
        if ans is None:
            break
        lo_b, hi_b = (mid, hi_b) if ans >= 1 else (lo_b, mid)
    return {
        "exact": s.holds(target),
        "strategies": hit,
        "pair_sum_admitted": pair_sum,
        "queries": s.queries,
        "refusals": s.refusals,
        "disagreement": s.disagreement,
        "bisection_narrowed": hi_b - lo_b <= 1,
    }


def main() -> None:
    con = build()
    bal = dict(con.execute("SELECT c_custkey, c_acctbal FROM customer"))
    targets = random.Random(SEED).sample(range(1, N + 1), N_TARGETS)
    out = {"n_targets": N_TARGETS, "budget": BUDGET, "seed": SEED, "n_customers": N,
           "balance_domain": [LO, HI], "note": (
               "exact_recovery counts targets whose own balance is a rational linear "
               "combination of admitted sums. pair_sum_admitted_not_exact counts targets "
               "for which a two-customer sum was answered and the target remained undetermined. "
               "bisection_narrowed is a fresh session of COUNT probes on one key."),
           "defenses": {}}
    for defense in DEFENSES:
        rows = [attack_one(con, defense, t, bal) for t in targets]
        exact_n = sum(r["exact"] for r in rows)
        qs = sorted(r["queries"] for r in rows if r["exact"])
        out["defenses"][defense] = {
            "exact_recovery": exact_n,
            "exact_rate": round(exact_n / N_TARGETS, 3),
            "pair_sum_admitted_not_exact": sum(r["pair_sum_admitted"] for r in rows),
            "bisection_narrowed": sum(r["bisection_narrowed"] for r in rows),
            "float_exact_disagreements": sum(r["disagreement"] for r in rows),
            "median_queries_when_exact": (qs[len(qs) // 2] if qs else None),
            "mean_refusals": round(sum(r["refusals"] for r in rows) / N_TARGETS, 2),
            "strategies_succeeded": {name: sum(r["strategies"][name] for r in rows)
                                     for name in rows[0]["strategies"]},
        }
        d = out["defenses"][defense]
        print(f"{defense:16} exact {d['exact_recovery']:3}  pair-sum {d['pair_sum_admitted_not_exact']:3}  "
              f"bisection {d['bisection_narrowed']:3}  disagree {d['float_exact_disagreements']}", flush=True)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(out, indent=1))
    print("wrote", OUT)


if __name__ == "__main__":
    main()
