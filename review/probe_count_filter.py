"""Probe: can COUNT queries that filter on the protected column recover one balance
through the gateway's linear (non-strict) audit? Read-only; uses the repo's own policy.

Run: python3 probe_count_filter.py /Users/sanjaymishra/cra-guardrails
"""
import sqlite3
import sys
from pathlib import Path

ROOT = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(ROOT / "guardrail-service"))
sys.path.insert(0, str(ROOT / "experiments" / "purpose_sql"))

import tpch_db as db  # noqa: E402
from guardrail.purpose import PurposeMonitor  # noqa: E402
from run_eval import load_policy  # noqa: E402

TARGET = 570
con = sqlite3.connect(f"file:{db.DEFAULT_OUT}?mode=ro", uri=True)
run = lambda sql: con.execute(sql).fetchall()  # noqa: E731
truth = run(f"SELECT c_acctbal FROM customer WHERE c_custkey={TARGET}")[0][0]

for defense, upd in {
    "linear": {"min_isolation": 3, "linear_audit": True, "strict_protected": False},
    "strict": {"min_isolation": 3, "linear_audit": True, "strict_protected": True},
}.items():
    pol = load_policy().model_copy(update=upd)
    mon = PurposeMonitor(pol, "finance_analytics", executor=run)
    lo, hi, n, refused = -1000.0, 10000.0, 0, 0
    while hi - lo > 0.005 and n < 40:
        mid = round((lo + hi) / 2, 3)
        sql = f"SELECT COUNT(*) FROM customer WHERE c_custkey = {TARGET} AND c_acctbal > {mid}"
        s = mon.check(sql)
        n += 1
        if s.refuse:
            refused += 1
            print(f"[{defense}] refused: {s.reasons}")
            break
        (lo, hi) = (mid, hi) if run(sql)[0][0] else (lo, mid)
    print(f"[{defense}] queries={n} refused={refused} interval=[{lo}, {hi}] truth={truth}")
