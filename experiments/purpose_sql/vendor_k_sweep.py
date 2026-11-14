"""k = 3, 5, 10 against Snowflake or BigQuery. This file does not connect.

Running it against a vendor account can create warehouse charges. The script
refuses to open a connection. The SQL it would run, and the command the author
would use after reviewing cost, are printed and written next to the other results.

    python experiments/purpose_sql/vendor_k_sweep.py
"""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "experiments" / "results" / "purpose_sql" / "vendor_k_sweep.json"

SQL = """
-- Minimum group size, one query at a time, on a synthetic customer table the
-- author loads. Not a measurement of Snowflake or BigQuery until it is run there.
SELECT COUNT(*) AS n, SUM(c_acctbal) AS total
FROM customer
WHERE c_nationkey = :nation AND c_mktsegment = :segment
HAVING COUNT(*) >= :k;
"""

COMMANDS = {
    "snowflake": (
        "export SNOWFLAKE_ACCOUNT= SNOWFLAKE_USER= SNOWFLAKE_PASSWORD= "
        "SNOWFLAKE_WAREHOUSE= SNOWFLAKE_DATABASE= SNOWFLAKE_SCHEMA= && "
        "python experiments/purpose_sql/vendor_k_sweep.py --execute snowflake"
    ),
    "bigquery": (
        "export BIGQUERY_PROJECT= GOOGLE_APPLICATION_CREDENTIALS=/path/to/sa.json && "
        "python experiments/purpose_sql/vendor_k_sweep.py --execute bigquery"
    ),
}


def main() -> None:
    import sys
    if "--execute" in sys.argv:
        sys.exit("refusing to open a Snowflake or BigQuery connection from this revision")
    record = {
        "executed": False,
        "reason": "A vendor query can cost money. No connection was opened.",
        "k": [3, 5, 10],
        "sql_template": SQL.strip(),
        "commands_for_the_author": COMMANDS,
        "estimated_cost_usd": "under a dollar on an X-Small warehouse or 10 GB of BigQuery on-demand "
                              "if the table is the 1,500-row synthetic customer table and each k runs "
                              "a few dozen queries; confirm the price sheet before running.",
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(record, indent=1))
    print(json.dumps(record, indent=1))


if __name__ == "__main__":
    main()
