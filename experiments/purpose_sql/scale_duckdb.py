"""Latency of entity-set computation inside DuckDB, and audit-history growth.

The cell test needs only a count of distinct keys. The linear test needs the
key multiset. Both are computed in SQL. The rank test then runs in process on
the aggregated (key, multiplicity) pairs, which is one row per entity rather
than one row per joined fact.

No warehouse account is used.

    python experiments/purpose_sql/scale_duckdb.py
"""
from __future__ import annotations

import json
import random
import statistics
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "guardrail-service"))
import duckdb  # noqa: E402
from guardrail.purpose import ExactLinearAuditor  # noqa: E402

OUT = ROOT / "experiments" / "results" / "purpose_sql" / "scale_duckdb.json"
N = 1_000_000
HISTORY = 1000


def pct(xs, p):
    xs = sorted(xs)
    if not xs:
        return None
    i = min(len(xs) - 1, int(round(p / 100 * (len(xs) - 1))))
    return round(xs[i], 3)


def main() -> None:
    con = duckdb.connect()
    con.execute(f"""
        CREATE TABLE customer AS
        SELECT i AS c_custkey,
               (i % 11000) - 1000 AS c_acctbal,
               i % 25 AS c_nationkey,
               i % 5 AS c_mktsegment
        FROM range(1, {N + 1}) t(i)
    """)
    con.execute("CREATE TABLE orders AS SELECT i AS o_orderkey, (i % {n}) + 1 AS o_custkey "
                "FROM range(1, {m}) t(i)".format(n=N, m=N * 2))

    def time_sql(sql, reps=7):
        # one warmup
        con.execute(sql).fetchall()
        ts = []
        for _ in range(reps):
            t0 = time.perf_counter()
            con.execute(sql).fetchall()
            ts.append(1000 * (time.perf_counter() - t0))
        return {"median_ms": round(statistics.median(ts), 3), "min_ms": round(min(ts), 3)}

    cell_sql = "SELECT COUNT(DISTINCT c_custkey) FROM customer WHERE c_nationkey = 7"
    keys_sql = "SELECT c_custkey, COUNT(*) FROM customer WHERE c_nationkey = 7 GROUP BY c_custkey"
    join_sql = ("SELECT c.c_custkey, COUNT(*) FROM customer c JOIN orders o ON o.o_custkey = c.c_custkey "
                "WHERE c.c_nationkey = 7 GROUP BY c.c_custkey")
    ship_sql = "SELECT c_custkey FROM customer WHERE c_nationkey = 7"

    latency = {
        "customers": N,
        "cell_count_distinct_in_db": time_sql(cell_sql),
        "aggregated_key_weights_in_db": time_sql(keys_sql),
        "join_key_weights_in_db": time_sql(join_sql),
        "ship_every_matching_key": time_sql(ship_sql),
    }
    n_nation = con.execute("SELECT COUNT(*) FROM customer WHERE c_nationkey = 7").fetchone()[0]
    latency["rows_in_nation_7"] = n_nation

    # tail of the in-process exact rank test over a long-lived identity
    rng = random.Random(1)
    aud = ExactLinearAuditor()
    checks = []
    for i in range(HISTORY):
        width = rng.choice([5, 20, 50, 100])
        lo = rng.randint(1, N - width)
        t0 = time.perf_counter()
        rows = con.execute(
            "SELECT c_custkey, COUNT(*) FROM customer WHERE c_custkey BETWEEN ? AND ? GROUP BY c_custkey",
            [lo, lo + width - 1]).fetchall()
        fetch_ms = 1000 * (time.perf_counter() - t0)
        weights = {r[0]: r[1] for r in rows}
        t1 = time.perf_counter()
        aud.disclosed([weights])
        rank_ms = 1000 * (time.perf_counter() - t1)
        aud.commit([weights])
        checks.append({"fetch_ms": fetch_ms, "rank_ms": rank_ms, "total_ms": fetch_ms + rank_ms,
                       "rank": len(aud.rows), "support": len(weights)})
    totals = [c["total_ms"] for c in checks]
    over_1s = sum(t > 1000 for t in totals)
    history = {
        "queries": HISTORY,
        "customers": N,
        "final_rank": len(aud.rows),
        "basis_rows": len(aud.rows),
        "median_total_ms": pct(totals, 50),
        "p95_total_ms": pct(totals, 95),
        "p99_total_ms": pct(totals, 99),
        "max_total_ms": round(max(totals), 3),
        "checks_over_1s": over_1s,
        "median_fetch_ms": pct([c["fetch_ms"] for c in checks], 50),
        "median_rank_ms": pct([c["rank_ms"] for c in checks], 50),
        "p95_rank_ms": pct([c["rank_ms"] for c in checks], 95),
        "max_rank_ms": round(max(c["rank_ms"] for c in checks), 3),
    }

    # concurrent sessions, each with its own connection and its own basis
    def worker(tid, barrier, sink):
        barrier.wait()
        c = duckdb.connect()
        # read the same data from a fresh in-memory view by attaching is unnecessary:
        # each worker builds nothing; it queries the parent only if we share. DuckDB
        # connections are not free to share, so each worker uses its own 200k slice
        # generated the same way. The point is concurrent rank tests, not shared IO.
        c.execute("""
            CREATE TABLE customer AS
            SELECT i AS c_custkey FROM range(1, 200001) t(i)
        """)
        aud_w = ExactLinearAuditor()
        rng_w = random.Random(tid)
        t0 = time.perf_counter()
        n_q = 50
        for _ in range(n_q):
            lo = rng_w.randint(1, 190000)
            rows = c.execute(
                "SELECT c_custkey, 1 FROM customer WHERE c_custkey BETWEEN ? AND ?",
                [lo, lo + 99]).fetchall()
            w = {r[0]: 1 for r in rows}
            aud_w.disclosed([w])
            aud_w.commit([w])
        sink.append(1000 * (time.perf_counter() - t0) / n_q)

    barrier = threading.Barrier(8)
    sink: list[float] = []
    threads = [threading.Thread(target=worker, args=(i, barrier, sink)) for i in range(8)]
    t0 = time.perf_counter()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    wall = time.perf_counter() - t0
    concurrent = {"sessions": 8, "queries_each": 50, "customers_each": 200_000,
                  "per_session_mean_check_ms": round(statistics.mean(sink), 3),
                  "wall_seconds": round(wall, 3)}

    out = {"latency": latency, "history": history, "concurrent": concurrent,
           "machine_note": "DuckDB in process, Linux VM, single host. Not a warehouse."}
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(out, indent=1))
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
