"""Figures and number macros for the TKDE manuscript, generated from experiments/results only.

    python paper/tkde/make_figures.py      # writes figures/*.pdf and numbers.tex
"""
from __future__ import annotations

import json
import math
import random
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt                                             # noqa: E402
import numpy as np                                                          # noqa: E402

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
RES = ROOT / "experiments" / "results"
FIG = HERE / "figures"
FIG.mkdir(exist_ok=True)

# reference categorical palette (light mode, fixed order) + hatches for grayscale print
C = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#6250d6"]
H = ["", "//", "..", "xx", "\\\\"]
INK, MUTED, GRID = "#0b0b0b", "#52514e", "#dcdbd6"
plt.rcParams.update({
    "font.family": "serif", "font.serif": ["Times New Roman", "Times", "DejaVu Serif"],
    "font.size": 7.5, "axes.titlesize": 8, "axes.labelsize": 7.5, "legend.fontsize": 6.5,
    "xtick.labelsize": 6.5, "ytick.labelsize": 6.5, "axes.edgecolor": MUTED, "axes.labelcolor": INK,
    "xtick.color": MUTED, "ytick.color": MUTED, "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.5,
    "axes.axisbelow": True, "axes.spines.top": False, "axes.spines.right": False, "pdf.fonttype": 42,
    "legend.frameon": False, "lines.linewidth": 1.4, "patch.linewidth": 0.4,
})
W1, W2 = 3.45, 7.1          # IEEE single / double column width (in)

N: dict[str, str] = {}      # LaTeX number macros


def num(name: str, value, fmt: str = "{:.3f}") -> None:
    N[name] = fmt.format(value) if not isinstance(value, str) else value


def pct(x: float) -> str:
    return f"{100 * x:.1f}"


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return max(0.0, c - h), min(1.0, c + h)


def paired_boot(a: list[bool], b: list[bool], reps: int = 5000, seed: int = 0) -> tuple[float, float, float]:
    rng = random.Random(seed)
    n = len(a)
    diffs = sorted(sum(b[i] - a[i] for i in (rng.randrange(n) for _ in range(n))) / n for _ in range(reps))
    return (sum(b) - sum(a)) / n, diffs[int(0.025 * reps)], diffs[int(0.975 * reps)]


def save(fig, name: str) -> None:
    fig.savefig(FIG / f"{name}.pdf", bbox_inches="tight", pad_inches=0.02)
    fig.savefig(FIG / f"{name}.png", dpi=200, bbox_inches="tight", pad_inches=0.02)
    plt.close(fig)


def load(path: Path):
    return json.loads(path.read_text()) if path.exists() else None


# ── capability (BIRD) ────────────────────────────────────────────────────────
MODELS = [("gpt-4o-mini", RES / "task_capability", "m"), ("gpt-4o", RES / "task_capability" / "gpt-4o", "o"),
          ("claude-sonnet-5-5", RES / "task_capability" / "claude-sonnet-5-5", "s"),
          ("qwen3:4b-instruct", RES / "task_capability" / "qwen3:4b-instruct", "q")]
GRANTS = ["full", "tables", "columns", "columns+keys", "gold"]
GLABEL = {"full": "Role (all columns)", "tables": "Tables", "columns": "Columns", "columns+keys": "Columns+keys",
          "gold": "Oracle footprint", "esc": "Columns+keys+escalation"}


def capability_figs() -> None:
    fig, ax = plt.subplots(figsize=(W1, 2.3))
    for mi, (model, d, tag) in enumerate(MODELS):
        s, rows = load(d / "summary.json"), load(d / "per_task.json")
        if not s:
            continue
        xs, ys, lo, hi, labels = [], [], [], [], []
        for g in GRANTS + ["esc"]:
            if g == "esc":
                ok = [r["escalation"]["agent_correct"] for r in rows]
                cols = s["columns+keys+escalation"]["mean_columns"]
            else:
                ok = [r["grants"][g]["agent_correct"] for r in rows]
                cols = s["grants"][g]["mean_columns"]
            k, n = sum(ok), len(ok)
            l, h = wilson(k, n)
            xs.append(cols); ys.append(k / n); lo.append(max(0, k / n - l)); hi.append(max(0, h - k / n)); labels.append(g)
            num(f"ex{tag}{g.replace('+', '').replace('columns', 'cols')}", pct(k / n), "{}")
            num(f"cols{tag}{g.replace('+', '').replace('columns', 'cols')}", f"{cols:.1f}", "{}")
        pretty = {"gpt-4o-mini": "gpt-4o-mini", "gpt-4o": "gpt-4o", "claude-sonnet-5-5": "Claude Sonnet 5.5",
                  "qwen3:4b-instruct": "qwen3-4b (55 tasks)"}[model]
        ax.errorbar(xs, ys, yerr=[lo, hi], fmt="os^D"[mi], color=C[mi], ms=4.5, capsize=1.5,
                    elinewidth=0.6, label=pretty, mec="white", mew=0.6)
        if mi == 0:
            off = {"full": (-38, 7), "tables": (4, 4), "columns": (5, -2), "columns+keys": (5, -9),
                   "gold": (-8, 9), "esc": (5, 3)}
            for x, y, g in zip(xs, ys, labels):
                ax.annotate(GLABEL[g], (x, y), textcoords="offset points", xytext=off[g], fontsize=5.6, color=MUTED)
        full = [r["grants"]["full"]["agent_correct"] for r in rows]
        esc = [r["escalation"]["agent_correct"] for r in rows]
        gold = [r["grants"]["gold"]["agent_correct"] for r in rows]
        d1, l1, h1 = paired_boot(full, esc)
        d2, l2, h2 = paired_boot(full, gold)
        num(f"dEsc{tag}", f"{100 * d1:+.1f}", "{}"); num(f"dEsc{tag}lo", f"{100 * l1:+.1f}", "{}")
        num(f"dEsc{tag}hi", f"{100 * h1:+.1f}", "{}")
        num(f"dGold{tag}", f"{100 * d2:+.1f}", "{}"); num(f"dGold{tag}lo", f"{100 * l2:+.1f}", "{}")
        num(f"dGold{tag}hi", f"{100 * h2:+.1f}", "{}")
        num(f"escRate{tag}", pct(s["columns+keys+escalation"]["tasks_escalating"]), "{}")
        num(f"escReq{tag}", f"{s['columns+keys+escalation']['mean_requested']:.2f}", "{}")
        num(f"adm{tag}cols", pct(s["grants"]["columns"]["admissible"]), "{}")
        num(f"adm{tag}colskeys", pct(s["grants"]["columns+keys"]["admissible"]), "{}")
        num(f"raw{tag}cols", f"{s['grants']['columns']['mean_raw']:.1f}", "{}")
        if tag == "m":
            num("ntasks", str(s["n_tasks"]), "{}")
    ax.set_xscale("log")
    ax.set_xticks([3, 5, 10, 20, 40, 80], ["3", "5", "10", "20", "40", "80"])
    ax.minorticks_off()
    ax.set_xlabel("Columns granted per task (mean, log scale)")
    ax.set_ylabel("Agent execution accuracy")
    ax.set_ylim(0, 0.8)
    ax.legend(loc="lower right", title="model", title_fontsize=6)
    save(fig, "fig2_capability_tradeoff")

    # per-difficulty bars
    s, rows = load(MODELS[0][1] / "summary.json"), load(MODELS[0][1] / "per_task.json")
    diffs = ["simple", "moderate", "challenging"]
    show = ["full", "tables", "esc", "gold"]
    fig, ax = plt.subplots(figsize=(W1, 1.9))
    w = 0.2
    for gi, g in enumerate(show):
        vals = []
        for dname in diffs:
            R = [r for r in rows if r["difficulty"] == dname]
            ok = [r["escalation"]["agent_correct"] if g == "esc" else r["grants"][g]["agent_correct"] for r in R]
            vals.append(sum(ok) / len(ok))
        ax.bar(np.arange(3) + (gi - 1.5) * w, vals, w * 0.92, color=C[gi], hatch=H[gi], edgecolor="white",
               label=GLABEL[g])
    ax.set_xticks(range(3), [f"{d}\n(n={sum(r['difficulty'] == d for r in rows)})" for d in diffs])
    ax.set_ylabel("Execution accuracy")
    ax.set_ylim(0, 0.85)
    ax.legend(ncol=2, loc="upper right")
    save(fig, "fig3_capability_difficulty")


def capability_table() -> None:
    """Table: per model and grant, admissibility, EX [95% CI], refusals, columns, raw columns."""
    rows_out = []
    for model, d, tag in MODELS:
        s, rows = load(d / "summary.json"), load(d / "per_task.json")
        if not s:
            continue
        first = True
        for g in GRANTS + ["esc"]:
            if g == "esc":
                ok = [r["escalation"]["agent_correct"] for r in rows]
                adm, ref = "--", "--"
                cols = s["columns+keys+escalation"]["mean_columns"]
                raw = None
            else:
                G = s["grants"][g]
                ok = [r["grants"][g]["agent_correct"] for r in rows]
                adm, ref = f"{G['admissible']:.2f}", f"{G['agent_refused']:.2f}"
                cols, raw = G["mean_columns"], G["mean_raw"]
            k, n = sum(ok), len(ok)
            lo, hi = wilson(k, n)
            name = model.replace("_", "\\_") if first else ""
            first = False
            rows_out.append(f"{name} & {GLABEL[g]} & {adm} & {k / n:.3f} [{lo:.2f}, {hi:.2f}] & {ref} & {cols:.1f} & {'--' if raw is None else f'{raw:.1f}'} \\\\")
        rows_out.append("\\midrule")
    if rows_out:
        rows_out = rows_out[:-1]
    (HERE / "tables").mkdir(exist_ok=True)
    (HERE / "tables" / "capability.tex").write_text("\n".join(rows_out) + "\n")


def injection_fig() -> None:
    variants = ["clean", "blunt", "plausible", "hint"]
    fig, axes = plt.subplots(1, 2, figsize=(W2 * 0.62, 1.9))
    present = [(m, t) for m, _, t in MODELS if (RES / "task_capability" / f"injection_{m}.json").exists()]
    w = 0.8 / len(present)
    for mi, (model, tag) in enumerate(present):
        s = load(RES / "task_capability" / f"injection_{model}.json")["summary"]
        x = np.arange(len(variants)) + (mi - (len(present) - 1) / 2) * w
        axes[0].bar(x, [s[v]["mean_columns"] for v in variants], w * 0.95, color=C[mi], hatch=H[mi],
                    edgecolor="white", label=model)
        axes[1].bar(x, [s[v]["tasks_with_identifying_raw"] for v in variants], w * 0.95, color=C[mi],
                    hatch=H[mi], edgecolor="white", label=model)
        for v in variants:
            num(f"inj{tag}{v}cols", f"{s[v]['mean_columns']:.1f}", "{}")
            num(f"inj{tag}{v}ident", pct(s[v]["tasks_with_identifying_raw"]), "{}")
            num(f"inj{tag}{v}new", pct(s[v]["tasks_with_new_identifying_raw"]), "{}")
    for ax, t in zip(axes, ["Columns granted (mean)", "Tasks granting identifying columns raw"]):
        ax.set_xticks(range(len(variants)), variants)
        ax.set_ylabel(t)
    axes[1].set_ylim(0, 1)
    axes[0].set_ylim(0, 11)
    axes[0].legend(loc="upper center", ncol=2)
    fig.tight_layout(w_pad=1.5)
    save(fig, "fig4_injection")


# ── session signals (TPC-H) ──────────────────────────────────────────────────
def session_figs() -> None:
    r = load(RES / "purpose_sql" / "results.json")
    fams = ["drift", "small_cell", "tracker", "tracker3", "enumeration"]
    dets = ["queries", "sqlguard_count", "row_ledger", "drift_q", "drift", "cell_q", "cell", "breadth_q", "breadth"]
    dl = {"queries": "Query count", "sqlguard_count": "SQL guard (sensitive cols)", "row_ledger": "Row ledger",
          "drift_q": "Drift (per query)", "drift": "Drift (session)", "cell_q": "Cell (per query)",
          "cell": "Cell+differencing (session)", "breadth_q": "Breadth (per query)", "breadth": "Breadth (session)"}
    M = np.array([[r["auroc"][f][d] for f in fams] for d in dets])
    fig, ax = plt.subplots(figsize=(W1, 2.6))
    im = ax.imshow(M, cmap="Blues", vmin=0.3, vmax=1.0, aspect="auto")
    for i in range(len(dets)):
        for j in range(len(fams)):
            ax.text(j, i, f"{M[i, j]:.2f}", ha="center", va="center", fontsize=6,
                    color="white" if M[i, j] > 0.75 else INK)
    ax.set_xticks(range(len(fams)), fams, rotation=20)
    ax.set_yticks(range(len(dets)), [dl[d] for d in dets])
    ax.grid(False)
    cb = fig.colorbar(im, ax=ax, fraction=0.04, pad=0.02)
    cb.ax.tick_params(labelsize=6)
    cb.set_label("AUROC", fontsize=6.5)
    save(fig, "fig5_session_auroc")

    op = r["operating"]["alpha=0.01"]
    tests = {"drift": 400, "small_cell": 100, "tracker": 100, "tracker3": 100, "enumeration": 100}
    show = [("existing_or", "Existing (guard + ledger)"), ("stateless_or", "Purpose, per query"),
            ("stateful_or", "Purpose, session")]
    fig, ax = plt.subplots(figsize=(W1, 1.9))
    for di, (d, lab) in enumerate(show):
        vals = [op["tpr"][d][f] for f in fams]
        err = np.array([[max(0, v - wilson(round(v * 100), 100)[0]), max(0, wilson(round(v * 100), 100)[1] - v)] for v in vals]).T
        ax.bar(np.arange(len(fams)) + (di - 1) * 0.27, vals, 0.25, color=C[di], hatch=H[di], edgecolor="white",
               yerr=err, error_kw={"elinewidth": 0.5, "capsize": 1}, label=lab)
    ax.set_xticks(range(len(fams)), fams)
    ax.set_ylabel("Detection rate at 1% benign FPR")
    ax.set_ylim(0, 1.12)
    ax.legend(ncol=3, loc="upper center", bbox_to_anchor=(0.5, 1.17))
    save(fig, "fig6_session_tpr")
    for d, _ in show:
        for f in fams:
            num(f"tpr{d.replace('_', '')}{f.replace('_', '')}", pct(op["tpr"][d][f]), "{}")
    for f in fams:
        for d in dets:
            num(f"auc{f.replace('_', '')}{d.replace('_', '')}", f"{r['auroc'][f][d]:.2f}", "{}")

    # audit trade-off
    fig, axes = plt.subplots(1, 2, figsize=(W1, 1.9), sharey=True)
    for ax, fam in zip(axes, ["tracker", "tracker3"]):
        for mi, mode in enumerate(["stateless", "pairwise", "linear", "strict"]):
            xs = [r["audit"][f"k={k}"][mode]["benign_query_refusal_rate"] * 100 for k in (2, 3, 5)]
            ys = [r["audit"][f"k={k}"][mode]["attack_prevented"][fam] for k in (2, 3, 5)]
            ax.plot(xs, ys, marker="os^D"[mi], color=C[mi], ms=4 if mi < 3 else 3.2, label=mode, mec="white",
                    mew=0.5, linestyle=["-", "--", ":", "-."][mi])
            if mode == "stateless":
                for x, y, k in zip(xs, ys, (2, 3, 5)):
                    ax.annotate(f"k={k}", (x, y), textcoords="offset points", xytext=(-4, 5), fontsize=5.5,
                                color=MUTED)
        ax.set_title(fam)
        ax.set_xscale("symlog", linthresh=0.5)
        ax.set_xticks([0, 0.5, 1, 2, 5, 10], ["0", "0.5", "1", "2", "5", "10"])
        ax.minorticks_off()
        ax.set_xlabel("Benign queries refused (%)")
    axes[0].set_ylabel("Attacks prevented")
    axes[0].set_ylim(-0.03, 1.08)
    h, l = axes[0].get_legend_handles_labels()
    fig.legend(h, l, loc="lower center", ncol=4, bbox_to_anchor=(0.5, -0.2))
    save(fig, "fig7_audit_tradeoff")
    for k in (2, 3, 5):
        for mode in ("stateless", "pairwise", "linear", "strict"):
            a = r["audit"][f"k={k}"][mode]
            t = f"k{k}{mode}"
            num(f"ref{t}", pct(a["benign_query_refusal_rate"]), "{}")
            num(f"hit{t}", pct(a["benign_session_hit_rate"]), "{}")
            for f in ("small_cell", "tracker", "tracker3"):
                num(f"prev{t}{f.replace('_', '')}", pct(a["attack_prevented"][f]), "{}")


def adaptive_fig() -> None:
    defs = ["purpose", "stateless", "pairwise", "linear", "strict"]
    fig, ax = plt.subplots(figsize=(W1, 1.9))
    for mi, model in enumerate(["gpt-4o-mini", "gpt-4o"]):
        r = load(RES / "purpose_sql" / f"adaptive_attack_{model}.json")
        if not r:
            continue
        tag = "m" if model == "gpt-4o-mini" else "o"
        vals, err = [], []
        for d in defs:
            E = [e for e in r["episodes"] if e["defense"] == d]
            if not E:                                  # defense not run for this model
                vals.append(np.nan); err.append((0, 0))
                continue
            k, n = sum(e["disclosed"] for e in E), len(E)
            lo, hi = wilson(k, n)
            vals.append(k / n); err.append((max(0, k / n - lo), max(0, hi - k / n)))
            num(f"adv{tag}{d}", pct(k / n), "{}"); num(f"adv{tag}{d}hi", pct(hi), "{}")
            num(f"adv{tag}{d}refusals", f"{np.mean([e['refusals'] for e in E]):.1f}", "{}")
            num(f"advn{tag}", str(n), "{}")
        ax.bar(np.arange(len(defs)) + (mi - 0.5) * 0.36, vals, 0.34, color=C[mi], hatch=H[mi], edgecolor="white",
               yerr=np.array(err).T, error_kw={"elinewidth": 0.5, "capsize": 1.2}, label=f"attacker: {model} (n={len({e['target'] for e in r['episodes']})})")
    ax.set_xticks(range(len(defs)), ["Purpose\n(columns)", "+ cell\nsuppression", "+ pairwise\ndifferencing",
                                     "+ linear\naudit", "+ strict\n(simulatable)"])
    ax.set_ylabel("Targets disclosed (oracle)")
    ax.set_ylim(0, 1.1)
    ax.legend(loc="upper right")
    save(fig, "fig8_adaptive_attacker")


def bird_fig() -> None:
    r = load(RES / "purpose_sql" / "bird_benign.json")
    dbs = ["financial", "debit_card_specializing"]
    lab = {"financial": "financial", "debit_card_specializing": "debit_card"}
    fig, axes = plt.subplots(1, 2, figsize=(W1, 1.9))
    ax = axes[0]
    parts = [("mode_refusal_rate", "Mode (raw protected value)"), ("k=3/stateless", "Audit, per query"),
             ("k=3/linear", "Audit, session (linear)"), ("k=3/strict", "Audit, strict")]
    for pi, (key, l) in enumerate(parts):
        vals = [r[d][key] if key in r[d] else r[d]["audit"][key]["query_refusal_rate"] for d in dbs]
        ax.bar(np.arange(2) + (pi - 1.5) * 0.21, vals, 0.19, color=C[pi], hatch=H[pi], edgecolor="white", label=l)
    ax.set_xticks(range(2), [lab[d] for d in dbs])
    ax.set_ylabel("Benign queries refused")
    ax.set_ylim(0, 0.62)
    ax.legend(loc="upper left", fontsize=5.2, ncol=1)
    ax = axes[1]
    for di, d in enumerate(dbs):
        L, Q = r[d]["latency_ms_k3"]["linear"], r[d]["query_exec_ms"]
        ax.bar([di - 0.2, di + 0.2], [L["median"], Q["median"]], 0.36, color=[C[0], C[3]], edgecolor="white")
        ax.scatter([di - 0.2, di + 0.2], [L["p95"], Q["p95"]], marker="_", s=60, color=INK, zorder=3)
    ax.set_yscale("log")
    ax.set_xticks(range(2), [lab[d] for d in dbs])
    ax.set_ylabel("ms (bar: median, tick: p95)")
    ax.set_ylim(0.1, 20000)
    ax.legend(handles=[plt.Rectangle((0, 0), 1, 1, color=C[0]), plt.Rectangle((0, 0), 1, 1, color=C[3])],
              labels=["Monitor check", "Query itself"], loc="upper center", ncol=2, fontsize=5.5)
    fig.tight_layout(w_pad=1.2)
    save(fig, "fig9_bird_benign")
    for d in dbs:
        t = "fin" if d == "financial" else "debit"
        v = r[d]
        num(f"{t}nq", str(v["n_gold_queries"]), "{}")
        num(f"{t}mode", pct(v["mode_refusal_rate"]), "{}")
        num(f"{t}cov", pct(v["key_set_coverage"]), "{}")
        num(f"{t}npa", str(v["protected_aggregate_queries"]), "{}")
        cats = v.get("single_query_refusals_k3_linear", {})
        for c in ("rank", "threshold", "weighted", "aggregate", "opaque"):
            num(f"{t}cat{c}", str(cats.get(c, 0)), "{}")
        num(f"{t}single", str(sum(cats.values())), "{}")
        num(f"{t}singleold", str(v.get("single_query_refusals_k3_linear_without_predicate_test", 0)), "{}")
        for m in ("stateless", "linear", "strict"):
            num(f"{t}ref{m}", pct(v["audit"][f"k=3/{m}"]["query_refusal_rate"]), "{}")
            num(f"{t}hit{m}", pct(v["audit"][f"k=3/{m}"]["session_hit_rate"]), "{}")
        num(f"{t}latmed", f"{v['latency_ms_k3']['linear']['median']:.2f}", "{}")
        num(f"{t}latp", f"{v['latency_ms_k3']['linear']['p95']:.1f}", "{}")
        num(f"{t}qmed", f"{v['query_exec_ms']['median']:.2f}", "{}")
        num(f"{t}qp", f"{v['query_exec_ms']['p95']:.1f}", "{}")


def benign_leak_numbers() -> None:
    """Share of benign finance sessions whose answered aggregates isolate exactly one customer."""
    import sqlite3
    import sys
    sys.path.insert(0, str(ROOT / "guardrail-service"))
    sys.path.insert(0, str(ROOT / "experiments" / "purpose_sql"))
    import tpch_db
    from guardrail.purpose import PurposeMonitor
    from run_eval import load_policy
    pol = load_policy()
    con = sqlite3.connect(f"file:{tpch_db.DEFAULT_OUT}?mode=ro", uri=True)
    run = lambda q: con.execute(q).fetchall()                            # noqa: E731
    sess = [json.loads(l) for l in (ROOT / "data" / "purpose_sql" / "sessions.jsonl").read_text().splitlines()]
    fin = [x for x in sess if x["purpose"] == "finance_analytics" and x["label"] == 0]
    one = 0
    for x in fin:
        m = PurposeMonitor(pol, x["purpose"], executor=run)
        for q in x["queries"]:
            m.check(q["sql"])
        one += m.cell >= 1.0
    num("benignleak", pct(one / len(fin)), "{}")
    num("benignleakn", str(one), "{}")
    num("nfinbenign", str(len(fin)), "{}")
    num("nsessions", str(len(sess)), "{}")
    num("nbenign", str(sum(x["label"] == 0 for x in sess)), "{}")
    num("nattack", str(sum(x["label"] == 1 for x in sess)), "{}")


def scaling_table() -> None:
    r = load(RES / "purpose_sql" / "audit_scaling.json")
    lines = [f"{x['n']:,} & {x['rank']} & {x['check_ms']:.2f} & {x['basis_mb']:.1f} \\\\" for x in r]
    (HERE / "tables").mkdir(exist_ok=True)
    (HERE / "tables" / "scaling.tex").write_text("\n".join(lines) + "\n")
    big = max(r, key=lambda x: (x["n"], x["rank"]))
    num("scalebigms", f"{big['check_ms']:.0f}", "{}")
    num("scalebigmb", f"{big['basis_mb']:.0f}", "{}")
    small = min(r, key=lambda x: (x["n"], x["rank"]))
    num("scalesmallms", f"{small['check_ms']:.2f}", "{}")


def dp_numbers() -> None:
    r = load(RES / "purpose_sql" / "dp_baseline.json")
    lines = []
    for key, v in r.items():
        e = key.split("=")[1]
        t = {"1": "one", "10": "ten", "100": "hundred"}[e]
        num(f"dp{t}med", pct(v["benign_median_rel_error"]), "{}")
        num(f"dp{t}five", pct(v["benign_within_5pct"]), "{}")
        num(f"dp{t}att", pct(v["tracker_estimate_within_10pct"]), "{}")
        lines.append(f"DP, $\\varepsilon={e}$ & {pct(v['benign_median_rel_error'])}\\% & "
                     f"{pct(v['benign_within_5pct'])}\\% & -- & {pct(v['tracker_estimate_within_10pct'])}\\% \\\\")
    (HERE / "tables" / "dp.tex").write_text("\n".join(lines) + "\n")


def e2e_table() -> None:
    r = load(RES / "mcp_e2e" / "results.json")
    num("eesessions", str(r["n_sessions"]), "{}")
    num("eequeries", f"{r['n_queries']:,}", "{}")
    lines = []
    for path, v in r["paths"].items():
        t = {"direct": "dir", "proxy": "prx"}[path]
        num(f"ee{t}parity", pct(v["decision_parity_with_library"]), "{}")
        num(f"ee{t}chkmed", f"{v['check_ms']['median']:.1f}", "{}")
        num(f"ee{t}chkp", f"{v['check_ms']['p95']:.0f}", "{}")
        num(f"ee{t}exmed", f"{v['execute_ms']['median']:.1f}", "{}")
        num(f"ee{t}exp", f"{v['execute_ms']['p95']:.0f}", "{}")
        num(f"ee{t}tr", f"{v['transport_overhead_ms']['median']:.1f}", "{}")
        num(f"ee{t}rtmed", f"{v['roundtrip_ms']['median']:.1f}", "{}")
        num(f"ee{t}rtp", f"{v['roundtrip_ms']['p95']:.0f}", "{}")
        br = v["benign_query_refusal"]
        num(f"ee{t}benlo", pct(min(br.values())), "{}"); num(f"ee{t}benhi", pct(max(br.values())), "{}")
        prev = v["attack_prevented"]
        num(f"ee{t}prevmin", pct(min(prev.values())), "{}")
        name = {"direct": "Gateway $\\to$ Postgres", "proxy": "Gateway $\\to$ DB MCP $\\to$ Postgres"}[path]
        lines.append(f"{name} & {pct(v['decision_parity_with_library'])}\\% & {v['check_ms']['median']:.1f} / "
                     f"{v['check_ms']['p95']:.0f} & {v['execute_ms']['median']:.1f} / {v['execute_ms']['p95']:.0f} & "
                     f"{v['transport_overhead_ms']['median']:.1f} & {v['roundtrip_ms']['median']:.1f} / "
                     f"{v['roundtrip_ms']['p95']:.0f} \\\\")
    (HERE / "tables" / "e2e.tex").write_text("\n".join(lines) + "\n")


def main() -> None:
    benign_leak_numbers()
    e2e_table()
    dp_numbers()
    scaling_table()
    capability_figs()
    capability_table()
    injection_fig()
    session_figs()
    adaptive_fig()
    bird_fig()
    lines = ["% generated by make_figures.py from experiments/results -- do not edit"]
    for k, v in sorted(N.items()):
        words = dict(zip("0123456789", ["zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine"]))
        safe = "".join(words.get(ch, ch) for ch in k if ch.isalnum())
        lines.append(f"\\newcommand{{\\N{safe}}}{{{v}}}")
    (HERE / "numbers.tex").write_text("\n".join(lines) + "\n")
    print(f"{len(N)} macros, figures in {FIG}")


if __name__ == "__main__":
    main()
