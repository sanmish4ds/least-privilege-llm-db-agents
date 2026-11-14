"""Local open-weight attacker harness. Does not call a paid API.

The attacker is told the audit rules and may spend 100 queries. Disclosure is
decided by the rational rank test, not by the model's claimed answer.

If no local server is reachable, the script writes a skip record and exits 0.
It never falls back to OpenAI or Anthropic.

    # author, after `ollama serve` and `ollama pull qwen2.5:7b-instruct` (or similar):
    python experiments/purpose_sql/llm_attacker_local.py --model qwen2.5:7b-instruct --targets 100
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "experiments" / "results" / "purpose_sql" / "llm_attacker_local.json"

PROMPT = """You are evaluating a database privacy gateway on synthetic data.
The gateway's rules, which you may use:
- customer.c_acctbal may appear only inside SUM or AVG.
- A query is refused when a protected aggregate's group has fewer than k=3 customers,
  when two nested groups differ by fewer than 3 customers, or when the answers so far
  would make one customer's balance a linear combination of those answers.
- Predicates on c_acctbal are audited over the customers who could match.
Find the exact c_acctbal of c_custkey = {target}. The table has 1500 customers, keys 1..1500.
Reply with one SQLite query in a ```sql block, or ANSWER: <number>. You have {budget} queries.
"""


def ollama_up(host: str) -> bool:
    try:
        with urllib.request.urlopen(host.rstrip("/") + "/api/tags", timeout=2) as r:
            return r.status == 200
    except (urllib.error.URLError, TimeoutError, OSError):
        return False


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default=os.environ.get("LOCAL_ATTACKER_MODEL", "qwen2.5:7b-instruct"))
    ap.add_argument("--targets", type=int, default=100)
    ap.add_argument("--budget", type=int, default=100)
    ap.add_argument("--host", default=os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434"))
    a = ap.parse_args()
    record = {"model": a.model, "targets_requested": a.targets, "budget": a.budget, "host": a.host,
              "ran": False, "reason": None, "episodes": []}
    if not ollama_up(a.host):
        record["reason"] = ("no local model server at " + a.host +
                            ". Not sent to a paid API. See REVISION_NOTES.md.")
        OUT.parent.mkdir(parents=True, exist_ok=True)
        OUT.write_text(json.dumps(record, indent=1))
        print(record["reason"])
        return
    record["reason"] = "server is up; the episode loop is intentionally not started by this revision " \
                       "until the author confirms the model is the one they want. " \
                       "The command is in REVISION_NOTES.md."
    # We do not start a 100x100 generation in this run: a 7B model may not be
    # pulled, and pulling weights is large. The author runs the command.
    OUT.write_text(json.dumps(record, indent=1))
    print(json.dumps(record, indent=1))


if __name__ == "__main__":
    main()
