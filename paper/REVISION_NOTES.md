# Revision notes

Point-by-point response for the review of "Session-Level Inference Control for LLM Agents on Analytical Databases" (Sanjay Mishra).

## Where the manuscript was

`paper/pvldb/` and `paper/pvldb/overleaf/` were not in the repository. A search of the git history, the TKDE Overleaf zip, and the author's other public repositories did not find a PVLDB source or `agent_numbers.tex`. The only manuscript in this repo is the longer TKDE paper at `paper/tkde/main.tex`.

This revision adds the PVLDB manuscript at `paper/pvldb/main.tex`, compiled with the PVLDB Vol. 20 template (`acmart` 2026/06/27 v2.19 plus `pvldb.sty`). The TKDE manuscript was not edited. Shared code changed only by adding `ExactLinearAuditor` and an `exact_linear` flag that defaults to off, so the cached TKDE path is unchanged. New tests cover that flag.

Compiled length: **5 pages total** (`pdfinfo` on `paper/pvldb/main.pdf`). The body ends and the reference list begins on page 4, so the paper is inside the 12-page limit excluding references. The extended notes are `paper/pvldb/appendix.tex` and are not input by `main.tex`.

Every number in the PVLDB paper is a macro from `paper/pvldb/make_numbers.py`. That script reads result JSON and does not edit numbers by hand.

## Model roles

Checked in `experiments/purpose_sql/adaptive_attack.py` and the three result files.

| Model id | Role | What the files show |
|---|---|---|
| `gpt-4o-mini` | SQL agent, and attacker | 220 BIRD tasks. Attacker: 50 targets, 5 defenses, budget 15, 0 exact disclosures under the linear audit. |
| `gpt-4o` | SQL agent, and attacker | 220 tasks. Attacker: 25 targets, 4 defenses. Strict mode was not run. 0 exact disclosures under the linear audit. |
| `claude-sonnet-5-5` | SQL agent. Attacker attempt only. | 220 tasks as the agent. As an attacker: 1 target, 5 defenses, `attacker_declined` on every episode, 0 queries. It sent no SQL. It is not included in any attack success rate. |
| `qwen3:4b-instruct` | SQL agent only, local | 55 tasks. Not an attacker. |
| none | Disclosure judge | `LinearAuditor` / `ExactLinearAuditor`. Not a model. |

Dated API snapshots were not stored. The paper pins the identifier strings above. No new paid call was made in this revision.

## A. Correctness

1. **Abstract cost claim.** The finance sessions do not support "the audit costs the same as a per-query minimum group size" at \(k=3\). Recomputed in `audit_k10.json` (matches the committed `results.json`): suppression refuses 0.6% of benign queries and 7.0% of benign sessions; the linear audit refuses 3.3% and 26.8%. At \(k=10\) on the same sessions the query-refusal rate is 20.1% for suppression, nested pairs, and the linear audit, while two-query prevention is 76% versus 100%. The abstract and Table 3 say this. A separate "large-group TPC-H" equality was not in the committed audit log (the audit log is the finance purpose), so it is not claimed.

2. **"Four vendor attacks recovered every target's exact value."** That sentence is not in the committed TKDE paper, and there is no vendor-attack result file. It is not repeated. The new two-customer probe (`pair_sum_probe.json`): with no minimum group size, 100 of 100 sums matched the sum of the two balances and determined neither customer. At \(k=3\) the linear audit refused all 100.

3. **Spider 2.0 / `agent_numbers.tex`.** The file is not in the repo. No Sonnet 27→18 or 27→20 figure is reported. The paper says so.

4. **BIRD admitted counts.** The only committed audit log is `experiments/results/purpose_sql/bird_benign.json`: 106 `financial` gold queries and 64 `debit_card_specializing` gold queries, one audit version (weighted sums, predicate test, \(k=3\)). The 93/41 versus 90/40 split, and the 134+27=161 versus 170 arithmetic, are not in the file. They are not regenerated. Table 4 is that one file.

5. **Sessions column identical to rules.** In `bird_benign.json` the \(k=3\) stateless and linear query-refusal rates are equal (19.6% and 41.5%). The session tests added no refusals on these gold-query sessions. The table shows that equality and the text says it is the measurement.

6. **Medians do not add.** On the committed PostgreSQL log (`per_query.json`, direct path), 2,616 queries executed. Median check + execute + transport = 14.0 ms. Median round trip on those queries = 53.7 ms. The paper states that the median of a sum is not the sum of medians, and that the older round-trip median was taken over a different set (all 2,942 queries, including refusals).

7. **2.2 ms versus 2.4 ms.** Those two check times are not in the log. The two paths are 1.4 ms and 1.8 ms median. The paper says the 2.2/2.4 pair is not in the log. (The number 2.2 appears in the TKDE draft as a DP attacker percent and as a mean refusal count, not as a check time.)

8. **Figure labels and the RQ4 table.** The search figure uses "No audit", "Min. group", "Nested pairs", "Linear audit", "Strict". It does not use `tracker` or `tracker3`. Table 3 is the numeric prevention/refusal table for \(k=3\) and \(k=10\).

9. **CRA citation and the journal submission.** `mishra2026cra` (arXiv:2607.19361, authors Sanjay Mishra, Divya Chukkapalli, Ganesh R. Naik) is cited. A journal-version entry records the venue conflict: `paper/tkde/README.md` calls it a TIFS manuscript (`paper/v2`, not in this repo); the review asked for TDSC. The paper asks the author to confirm the venue. Overlap, in the paper and in `appendix.tex`: dialogue scores versus SQL weight vectors; the shared lesson that a session score can track length; no copied text, tables, or numbers. Nothing from that manuscript was available in this repo to copy.

10. **Stale Overleaf files and model ids.** There was no `paper/pvldb/overleaf/` to clean. Model ids are pinned to the strings in the result files. Dated snapshots were not recorded.

## B. Related work

Citations were checked against arXiv, the ACL Anthology bib, or Crossref before they were added. `paper/pvldb/references.bib` has the DOIs and the arXiv ids.

- Wang et al., arXiv:2606.08661. V8 is "Lack of Compositional Leakage Control": policies that approve each query can still leak through a sequence of aggregates. The paper describes V8 that way and positions the audit as a defense for it. The old "one query at a time" gloss is not used.
- SafeNLIDB, arXiv:2511.06778, AAAI 2026 extended version (Liu, Chen, Zhang, Zhang, Zhang, Yang).
- SecureSQL, EMNLP Findings 2024, DOI 10.18653/v1/2024.findings-emnlp.346 (Song et al.). It evaluates leakage; it is not described as a defense.
- FactGate, arXiv:2607.00751v2 (Wu). Version 1 was titled SessionBound. The paper uses the current title and says inference from predicates is outside FactGate's guarantee.
- DPSQL+, arXiv:2602.22699 (Matsumoto, Takakura, Takagi, Hasegawa), TPDP 2026. Minimum frequency plus DP. Our baseline is not their library.
- PIMENTO, arXiv:2609.14745 (Sadia, Chen, Roy Chowdhury). Text queries, not this audit.
- QuerySnout, CCS 2022, DOI 10.1145/3548606.3560581, pages 623–637.
- QueryCheetah, CCS 2024, DOI 10.1145/3658644.3690272, pages 3451–3465.
- Provenance: Green, Karvounarakis, Tannen, PODS 2007, DOI 10.1145/1265530.1265535; Buneman, Khanna, Tan, ICDT 2001, DOI 10.1007/3-540-44503-X_20; Cheney, Chiticariu, Tan, Foundations and Trends in Databases, 2009, DOI 10.1561/1900000006. Crossref returns Tan's name as "Tan Wang-Chiew"; the bib uses Wang-Chiew Tan.

Contribution 1 is not "first measurement of native Snowflake and BigQuery controls." Those systems were not measured. The contribution is the session audit and the finance-session cost.

Table 1 is the positioning table in Section 2.

## C. New evidence

Ran, all local:

- **Query portfolio** (`attack_search.py`, 100 targets, budget 100, no LLM). No audit: 100/100 by a single-customer sum. Minimum group size at \(k=3,5,10\): 100/100 by the segment complement, and 100/100 by threshold bisection. Nested pairs: 100/100 by the three-range overlap, bisection 0/100. Linear audit, rational linear audit, and strict mode: 0/100 exact (Wilson upper bound 3.7%) and 0/100 bisection. The mutation loop added no recovery beyond the named patterns. This is a portfolio that includes known attacks, not a QuerySnout discovery claim.
- **Two-customer sum** (`pair_sum_probe.json`). See A2.
- **\(k=10\) on the finance sessions**, and a recompute of \(k=3\) that matches the committed rates.
- **Rational versus \(10^{-9}\) rank test** (`float_tolerance.json`). 0 disagreements in 400 random trials (200 unit ranges, 200 join weights in 1..50) and 0 on the search. A constructed pair with weights near \(10^9\) is determined exactly; the floating-point test reports neither entity.
- **DuckDB entity sets** (`scale_duckdb.json`), 1,000,000 customers. Median: count-distinct 3.0 ms, aggregated weights 9.4 ms, join weights 14.2 ms, shipping keys 6.0 ms, on a 40,000-customer nation. 1,000 range queries (width 5–100): median 1.02 ms, max 3.71 ms, 0 checks over 1 s, final rank 1,000. Eight concurrent sessions: mean check 4.6 ms.
- **PostgreSQL tail, from the committed log, not a new run.** 112 of 2,942 direct checks exceeded 1 s. Maximum 4.44 s. The review's 471/2,942 and 231 s are not in this log. They are not used.
- **Laplace plus a noisy minimum count** (`dp_minsize.py`), basic composition, not OpenDP. At \(\varepsilon=1\), suppression 25.2%, median relative error of released answers 148%, difference-attack draws 0.1%. At \(\varepsilon=100\), 29 answers suppressed, median error 1.8%, difference within 10% on 11.2% of draws. The cached naive Laplace attacker at \(\varepsilon=100\) is 18.7%. The paper treats DP as complementary. The cached linear-program widths on 200 scripted tracker sessions stay at the full domain (median width 11,000, 0 narrowed).
- **BIRD execution accuracy over all tasks**, from the cached per-task files, plus the admitted-only rate. Example, `gpt-4o-mini`, columns+keys: 40.5% of 220 tasks, 57.8% of 154 admitted queries. The paper says to use the all-tasks number.

Did not run, and why:

- Open-weight LLM attacker. `llm_attacker_local.py` found no server at `http://127.0.0.1:11434` and did not call a paid API.
- Snowflake / BigQuery. `vendor_k_sweep.py` refuses `--execute`.
- OpenDP / Tumult. Not installed; the baseline is our own Laplace accounting, labeled as such.
- A cheaper strict mode that stays simulatable. Not found. Strict refusal was remeasured: 25.6% of benign finance queries and 94.0% of benign sessions at \(k=3\).
- An interval-refusal mode. Scoped out. The cached LP widths are the evidence that the scripted attacks' admitted answers did not narrow the box.

## Paid calls awaiting approval

No paid call was made. Do not run these without approving the charge.

1. **Local-or-paid attacker, 100 targets, budget 100.** Free command, if Ollama is up and the model is pulled:

```bash
python experiments/purpose_sql/llm_attacker_local.py --model qwen2.5:7b-instruct --targets 100 --budget 100
```

The harness currently records that the server was down and does not start generation. A paid substitute (for example `gpt-4o` through `experiments/purpose_sql/adaptive_attack.py`, which would need a code change to raise the budget from 15 to 100) is on the order of 100 targets × 100 calls. At a few cents a call that is tens of dollars. This revision did not look up a live price and did not send the calls.

2. **Snowflake or BigQuery, \(k=3,5,10\).** Command the script will refuse until this note is updated:

```bash
python experiments/purpose_sql/vendor_k_sweep.py --execute snowflake
python experiments/purpose_sql/vendor_k_sweep.py --execute bigquery
```

Estimated cost if the table is the 1,500-row synthetic customer table and each \(k\) runs a few dozen queries: under a dollar on an X-Small warehouse or on BigQuery on-demand. Confirm the price sheet. No connection was opened.

## Commands the author can re-run locally

```bash
python3 -m venv .venv && .venv/bin/pip install numpy scipy sqlglot pydantic pyyaml pytest matplotlib duckdb
PYTHONPATH=guardrail-service .venv/bin/python -m pytest -q guardrail-service/tests
.venv/bin/python experiments/purpose_sql/float_tolerance.py
.venv/bin/python experiments/purpose_sql/attack_search.py          # about 5 minutes
.venv/bin/python experiments/purpose_sql/scale_duckdb.py
.venv/bin/python experiments/purpose_sql/tpch_db.py
.venv/bin/python experiments/purpose_sql/sessions.py
.venv/bin/python experiments/purpose_sql/dp_minsize.py             # several minutes
.venv/bin/python paper/pvldb/make_numbers.py
cd paper/pvldb && pdflatex main && bibtex main && pdflatex main && pdflatex main
```

The \(k=10\) finance recomputation is the loop in the session that wrote `audit_k10.json`. Re-running `run_eval.py` regenerates \(k=2,3,5\) only.

## TKDE

`paper/tkde/main.tex` was not changed. If the TKDE draft still says the audit's benign cost in a way that a reader can hear as "the same as per-query suppression," that sentence is the finance \(k=3\) comparison above and should be read from Table 3 of the PVLDB paper. The TKDE numbers file was not regenerated.
