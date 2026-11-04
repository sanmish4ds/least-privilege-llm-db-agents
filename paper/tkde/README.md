# Manuscript: Least-Privilege Data Access for LLM Database Agents

Target: **IEEE Transactions on Knowledge and Data Engineering (TKDE)**, regular paper,
IEEE Computer Society template (`IEEEtran.cls`, `journal,compsoc`).

## Build

```bash
# 1. experiments (see each script's docstring; BIRD_DIR points to a local BIRD dev copy)
P=guardrail-service/.venv/bin/python
$P experiments/purpose_sql/tpch_db.py && $P experiments/purpose_sql/sessions.py && $P experiments/purpose_sql/run_eval.py
$P experiments/purpose_sql/bird_benign.py && $P experiments/purpose_sql/dp_baseline.py && $P experiments/purpose_sql/audit_scaling.py
$P experiments/purpose_sql/adaptive_attack.py --model gpt-4o-mini --targets 50 && $P experiments/purpose_sql/adaptive_attack.py --model gpt-4o --targets 25
$P experiments/task_capability/run_capability_eval.py --model gpt-4o-mini   # and gpt-4o, claude-sonnet-5-5 (EXTRA_ENV=.env with ANTHROPIC_API_KEY), qwen3:4b-instruct --per-db 5
$P experiments/mcp_e2e/load_tpch_pg.py && $P experiments/mcp_e2e/run_e2e.py   # needs local PostgreSQL 16 on port 55432
$P experiments/task_capability/injection_eval.py --model gpt-4o-mini        # and --model gpt-4o
# 2. paper
$P paper/tkde/make_figures.py        # figures/*.pdf and numbers.tex (every number in the text)
python3 paper/tkde/verify_refs.py    # references.bib + REFERENCE_AUDIT.md from Crossref / arXiv
bash paper/tkde/build_overleaf.sh    # overleaf/tkde-overleaf.zip, compiled from a clean copy
```

LLM responses are cached under `experiments/results/`, so reruns are deterministic and free.

## Journal selection and requirements (checked 2026-10-17)

| Item | Finding | Basis |
|---|---|---|
| Scope fit | Database access control, inference control / auditing, privacy-preserving data management | TKDE aims and scope; journal's long record on these topics |
| Quartile | Q1 (Information Systems) | Secondary aggregators (Editage, Researcher.life) citing SJR; Peeref lists Q1 by CiteScore. **SCImago was not opened directly; confirm before submission.** |
| Length | Regular paper: **12 formatted pages** including abstract, references and biographies; up to 14 subject to Mandatory Overlength Page Charges ($220 per page beyond 12); up to 18 only with EIC approval. Our manuscript: 10 pages before biographies (about 10.5 with them), so no overlength charge | IEEE CS Author resources page (computer.org/publications/author-resources/authors, read 2026-10-18): 12-page Transactions limit, MOPC $220/page. TKDE-specific 12/14/18 rule quoted from the TKDE "Write for Us" page in a Feb-2024 blog; the official TKDE page could not be fetched (JavaScript-rendered). **Check the TKDE page in a browser before submitting.** |
| Template | IEEE Computer Society journal template | Same sources; `IEEEtran` `compsoc` option used |

## Open items for the authors

1. **Affiliations:** copied from arXiv:2607.19361 (G. R. Naik at Flinders University). The TIFS manuscript lists Torrens University Australia. Confirm which is current.
2. **Declarations:** fill in funding, conflicts of interest, and AI-tool use per IEEE / TKDE policy.
3. **Overlap with the TIFS manuscript (`paper/v2`):** this paper cites the arXiv CRA paper and does not reuse v2's results. If both are under review at the same time, disclose the related submission in the cover letter.
4. **API budgets:** Sonnet capability results are complete; the Sonnet injection study stopped on an exhausted credit balance, and Sonnet refused the attacker role (cyber classifier). The OpenAI balance ran out before the gpt-4o adaptive study reached 50 targets. The paper states all of this. qwen3:4b-instruct runs locally, on a 55-task subset.
5. **Biographies and photos:** TKDE expects them at final submission; they count toward the page limit.

See `SELF_REVIEW.md` for the scored self-review and what would raise the score.
