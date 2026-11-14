"""Write numbers.tex, result tables, and the search figure from result files.

Every number in the PVLDB manuscript comes from this script. It does not call
a model or a warehouse.

    /tmp/venv/bin/python paper/pvldb/make_numbers.py
"""
from __future__ import annotations

import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
RES = ROOT / "experiments" / "results"


def load(path: Path):
    return json.loads(path.read_text())


def pct(x: float) -> str:
    return f"{100 * x:.1f}"


def wilson_upper(k: int, n: int, z: float = 1.96) -> float:
    p = k / n
    denom = 1 + z ** 2 / n
    centre = p + z ** 2 / (2 * n)
    margin = z * ((p * (1 - p) / n + z ** 2 / (4 * n ** 2)) ** 0.5)
    return (centre + margin) / denom


def main() -> None:
    N = {}

    def put(name: str, value: str) -> None:
        N[name] = value

    audit = load(RES / "purpose_sql" / "audit_k10.json")
    for k, modes in audit.items():
        tag = {"k=3": "kthree", "k=10": "kten"}[k]
        for mode, v in modes.items():
            put(f"{tag}{mode}q", pct(v["benign_query_refusal_rate"]))
            put(f"{tag}{mode}s", pct(v["benign_session_hit_rate"]))
            for fam, rate in v["attack_prevented"].items():
                fam_name = {"small_cell": "small", "tracker": "two", "tracker3": "three"}[fam]
                put(f"{tag}{mode}{fam_name}", pct(rate))
    put("kthreenq", str(audit["k=3"]["linear"]["n_benign_queries"]))
    put("kthreens", str(audit["k=3"]["linear"]["n_benign_sessions"]))

    search = load(RES / "purpose_sql" / "attack_search.json")
    put("searchn", str(search["n_targets"]))
    put("searchbudget", str(search["budget"]))
    for defense, v in search["defenses"].items():
        safe = (defense.replace("_", "").replace("k10", "kten").replace("k3", "kthree").replace("k5", "kfive"))
        put(f"search{safe}", str(v["exact_recovery"]))
        put(f"search{safe}bis", str(v["bisection_narrowed"]))
    put("searchwilson", pct(wilson_upper(0, search["n_targets"])))

    pair = load(RES / "purpose_sql" / "pair_sum_probe.json")
    put("pairn", str(pair["n_targets"]))
    put("pairnoneadm", str(pair["defenses"]["none"]["admitted"]))
    put("pairnonesum", str(pair["defenses"]["none"]["sum_matches_two_balances"]))
    put("pairnoneexact", str(pair["defenses"]["none"]["either_customer_exact"]))
    put("pairkthreeadm", str(pair["defenses"]["linear_k3"]["admitted"]))

    tol = load(RES / "purpose_sql" / "float_tolerance.json")
    unit = tol["families"]["unit_ranges_n400"]
    join = tol["families"]["join_weights_1_to_50"]
    put("floattoler", "1e-9")
    put("floattrials", str(unit["trials"] + join["trials"]))
    put("floatdisagree", str(unit["trials_with_any_disagreement"] + join["trials_with_any_disagreement"]))
    put("floatsearchdisagree", str(search["defenses"]["linear_k3"]["float_exact_disagreements"]))

    scale = load(RES / "purpose_sql" / "scale_duckdb.json")
    put("scalecell", f"{scale['latency']['cell_count_distinct_in_db']['median_ms']:.1f}")
    put("scaleweights", f"{scale['latency']['aggregated_key_weights_in_db']['median_ms']:.1f}")
    put("scalejoin", f"{scale['latency']['join_key_weights_in_db']['median_ms']:.1f}")
    put("scaleship", f"{scale['latency']['ship_every_matching_key']['median_ms']:.1f}")
    put("scalenation", f"{scale['latency']['rows_in_nation_7']:,}")
    h = scale["history"]
    put("histn", str(h["queries"]))
    put("histcust", f"{h['customers']:,}")
    put("histmed", f"{h['median_total_ms']:.2f}")
    put("histmax", f"{h['max_total_ms']:.2f}")
    put("histover", str(h["checks_over_1s"]))
    put("histrank", str(h["final_rank"]))
    c = scale["concurrent"]
    put("concsess", str(c["sessions"]))
    put("concq", str(c["queries_each"]))
    put("concms", f"{c['per_session_mean_check_ms']:.1f}")

    # End-to-end tail and the median-sum gap, from the committed per-query log.
    e2e = load(RES / "mcp_e2e" / "per_query.json")

    def walk(x, acc):
        if isinstance(x, dict) and "check_ms" in x:
            acc.append(x)
        elif isinstance(x, list):
            for y in x:
                walk(y, acc)

    flat = []
    walk(e2e["direct"], flat)
    checks = sorted(q["check_ms"] for q in flat)
    executed = [q for q in flat if q["execute_ms"] is not None]

    def med(xs):
        xs = sorted(xs)
        return xs[len(xs) // 2]

    chk_e = med([q["check_ms"] for q in executed])
    exe = med([q["execute_ms"] for q in executed])
    tr = med([q["roundtrip_ms"] - q["check_ms"] - q["execute_ms"] for q in executed])
    rt_e = med([q["roundtrip_ms"] for q in executed])
    put("een", str(len(flat)))
    put("eeexecn", str(len(executed)))
    put("eeover", str(sum(c > 1000 for c in checks)))
    put("eemax", f"{max(checks) / 1000:.2f}")
    put("eechk", f"{med(checks):.1f}")
    proxy = []
    walk(e2e["proxy"], proxy)
    put("eechkproxy", f"{med([q['check_ms'] for q in proxy]):.1f}")
    put("eesummed", f"{(chk_e + exe + tr):.1f}")
    put("eertexec", f"{rt_e:.1f}")
    put("eeexe", f"{exe:.1f}")

    dp = load(RES / "purpose_sql" / "dp_minsize.json")
    naive = load(RES / "purpose_sql" / "dp_baseline.json")
    lines = []
    for eps, label in (("1", "one"), ("10", "ten"), ("100", "hundred")):
        v = dp["runs"][f"eps={eps}"]
        nv = naive[f"eps={eps}"]
        put(f"dp{label}sup", pct(v["suppressed_rate"]))
        put(f"dp{label}supn", str(v["suppressed"]))
        put(f"dp{label}err", pct(v["benign_median_rel_error_released"] / 100 if False else v["benign_median_rel_error_released"]))
        # benign_median_rel_error_released is already a ratio (1.48 means 148%)
        put(f"dp{label}errpct", pct(v["benign_median_rel_error_released"]))
        put(f"dp{label}five", pct(v["benign_within_5pct_released"]))
        put(f"dp{label}att", pct(v["tracker_difference_within_10pct"]))
        put(f"naive{label}err", pct(v["benign_median_rel_error_released"] and nv["benign_median_rel_error"]))
        put(f"naive{label}att", pct(nv["tracker_estimate_within_10pct"]))
        lines.append(
            f"{eps} & {pct(nv['benign_median_rel_error'])}\\% & {pct(nv['tracker_estimate_within_10pct'])}\\% "
            f"& {pct(v['suppressed_rate'])}\\% & {pct(v['benign_median_rel_error_released'])}\\% "
            f"& {pct(v['tracker_difference_within_10pct'])}\\% \\\\"
        )
    (HERE / "tables").mkdir(exist_ok=True)
    (HERE / "tables" / "dp.tex").write_text("\n".join(lines) + "\n")
    au = naive["audit_linear_k3"]
    put("dpauditatt", pct(au["tracker_estimate_within_10pct"]))
    put("dpauditprior", pct(au["prior_guess_within_10pct"]))
    put("dpauditwidth", f"{au['median_interval_width']:.0f}")
    put("dpauditnarrow", str(au["narrowed_sessions"]))
    put("dpauditn", str(au["n_sessions"]))

    bird = load(RES / "purpose_sql" / "bird_benign.json")
    brows = []
    for db, short in (("financial", "fin"), ("debit_card_specializing", "deb")):
        v = bird[db]
        put(f"bird{short}n", str(v["n_gold_queries"]))
        put(f"bird{short}ref", pct(v["audit"]["k=3/linear"]["query_refusal_rate"]))
        put(f"bird{short}stat", pct(v["audit"]["k=3/stateless"]["query_refusal_rate"]))
        put(f"bird{short}strict", pct(v["audit"]["k=3/strict"]["query_refusal_rate"]))
        put(f"bird{short}hit", pct(v["audit"]["k=3/linear"]["session_hit_rate"]))
        same = v["audit"]["k=3/stateless"]["query_refusal_rate"] == v["audit"]["k=3/linear"]["query_refusal_rate"]
        put(f"bird{short}same", "yes" if same else "no")
        brows.append(
            f"{short} & {v['n_gold_queries']} & {pct(v['audit']['k=3/stateless']['query_refusal_rate'])}\\% "
            f"& {pct(v['audit']['k=3/linear']['query_refusal_rate'])}\\% "
            f"& {pct(v['audit']['k=3/strict']['query_refusal_rate'])}\\% "
            f"& {pct(v['audit']['k=3/linear']['session_hit_rate'])}\\% \\\\"
        )
    (HERE / "tables" / "bird.tex").write_text("\n".join(brows) + "\n")

    # BIRD execution accuracy over every task, and over admitted queries only.
    cap_rows = []
    specs = [
        ("gpt-4o-mini", RES / "task_capability" / "per_task.json"),
        ("gpt-4o", RES / "task_capability" / "gpt-4o" / "per_task.json"),
        ("claude-sonnet-5-5", RES / "task_capability" / "claude-sonnet-5-5" / "per_task.json"),
        ("qwen3:4b-instruct", RES / "task_capability" / "qwen3:4b-instruct" / "per_task.json"),
    ]
    for model, path in specs:
        rows = load(path)
        n = len(rows)
        g = "columns+keys"
        correct = sum(r["grants"][g]["agent_correct"] for r in rows)
        allowed = [r for r in rows if r["grants"][g]["agent_allowed"]]
        correct_a = sum(r["grants"][g]["agent_correct"] for r in allowed)
        put_name = {"gpt-4o-mini": "mini", "gpt-4o": "four", "claude-sonnet-5-5": "sonnet",
                    "qwen3:4b-instruct": "qwen"}[model]
        put(f"ex{put_name}n", str(n))
        put(f"ex{put_name}all", pct(correct / n))
        put(f"ex{put_name}adm", pct(correct_a / len(allowed) if allowed else 0))
        put(f"ex{put_name}admn", str(len(allowed)))
        cap_rows.append(
            f"\\texttt{{{model}}} & {n} & {pct(correct / n)}\\% & {len(allowed)} & "
            f"{pct(correct_a / len(allowed))}\\% \\\\"
        )
    (HERE / "tables" / "bird_ex.tex").write_text("\n".join(cap_rows) + "\n")

    # Attack-search figure. Internal family names are not used as labels.
    order = [
        ("none", "No audit"),
        ("stateless_k3", "Min.\ group\n$k{=}3$"),
        ("pairwise_k3", "Nested\npairs"),
        ("linear_k3", "Linear\naudit"),
        ("strict_k3", "Strict"),
    ]
    fig, ax = plt.subplots(figsize=(3.35, 1.7))
    xs = range(len(order))
    exact = [search["defenses"][k]["exact_recovery"] for k, _ in order]
    bis = [search["defenses"][k]["bisection_narrowed"] for k, _ in order]
    ax.bar([i - 0.18 for i in xs], exact, 0.36, label="Exact balance", color="#4C78A8")
    ax.bar([i + 0.18 for i in xs], bis, 0.36, label="Threshold bisection", color="#F58518")
    ax.set_xticks(list(xs), [lab for _, lab in order], fontsize=7)
    ax.set_ylabel("Targets recovered (of 100)", fontsize=7)
    ax.set_ylim(0, 115)
    ax.tick_params(axis="y", labelsize=7)
    ax.legend(fontsize=6, frameon=False, loc="upper right")
    fig.tight_layout()
    (HERE / "figures").mkdir(exist_ok=True)
    fig.savefig(HERE / "figures" / "search.pdf")
    plt.close(fig)

    # k = 3 and k = 10 finance table
    krows = []
    for k, tag in (("3", "kthree"), ("10", "kten")):
        for mode, label in (("stateless", "Min.\\ group"), ("pairwise", "Nested pairs"),
                            ("linear", "Linear"), ("strict", "Strict")):
            krows.append(
                "$k{=}" + k + f"$ & {label} & {N[f'{tag}{mode}q']}\\% & {N[f'{tag}{mode}s']}\\% "
                f"& {N[f'{tag}{mode}two']}\\% & {N[f'{tag}{mode}three']}\\% \\\\"
            )
    (HERE / "tables" / "audit_k.tex").write_text("\n".join(krows) + "\n")

    lines = ["% generated by paper/pvldb/make_numbers.py -- do not edit"]
    for key in sorted(N):
        lines.append(f"\\newcommand{{\\N{key}}}{{{N[key]}}}")
    (HERE / "numbers.tex").write_text("\n".join(lines) + "\n")
    print(f"{len(N)} macros")


if __name__ == "__main__":
    main()
