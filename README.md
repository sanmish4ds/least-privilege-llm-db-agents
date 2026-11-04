# Least-Privilege Data Access for LLM Database Agents

Paper (target: IEEE TKDE) and code for task-scoped capabilities and session-level
inference control for LLM agents that query databases. Moved out of `cra-guardrails`
on 2026-11-03.

| Path | Contents |
|---|---|
| `paper/tkde/` | Manuscript (`main.tex`), `make_figures.py` (writes `numbers.tex`, figures), `build_overleaf.sh` |
| `guardrail-service/guardrail/` | Gateway: `purpose.py` (capabilities + session audit), `mcp_gateway.py`, `db_mcp_server.py`, `backends.py`; `sql_guard.py` / `config.py` copied for the baseline |
| `experiments/purpose_sql/` | TPC-H session benchmark, audit eval, adaptive attackers, DP baseline, BIRD workloads, scaling |
| `experiments/task_capability/` | BIRD capability derivation and injection study (needs a local BIRD copy, `BIRD_DIR`) |
| `experiments/mcp_e2e/` | End-to-end MCP replay on PostgreSQL 16 (cluster in `data/purpose_sql/pgdata`, port 55432) |
| `experiments/results/` | Result files and LLM caches; every number in the paper comes from here |
| `data/purpose_sql/` | Generated SQLite DB, sessions, Postgres cluster (not in git; regenerate with `tpch_db.py` / `sessions.py`) |
| `review/` | Review notes and the COUNT-bisection probe |

## Setup

```bash
cd guardrail-service && uv venv .venv && uv pip install --python .venv/bin/python -r ../requirements-pinned.txt && uv pip install --python .venv/bin/python --no-deps -e .
```

## Rebuild

```bash
P=guardrail-service/.venv/bin/python
$P -m pytest -q guardrail-service/tests
$P experiments/purpose_sql/run_eval.py && $P experiments/purpose_sql/bird_benign.py
$P paper/tkde/make_figures.py && (cd paper/tkde && latexmk -pdf main.tex)
```

API keys for LLM reruns go in `.env` (not committed). See `paper/tkde/README.md` for the full run list.
