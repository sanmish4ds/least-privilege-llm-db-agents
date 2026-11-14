"""Redraw the audit tradeoff figure with the paper's names, not tracker/tracker3.

Data: experiments/results/purpose_sql/results.json, the same audit block the
finance-session macros were generated from.
"""
from __future__ import annotations

import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parents[2]
r = json.loads((ROOT / "experiments/results/purpose_sql/results.json").read_text())
fig, axes = plt.subplots(1, 2, figsize=(3.4, 1.85), sharey=True)
colors = ["#4C78A8", "#F58518", "#54A24B", "#E45756"]
for ax, fam, title in zip(
    axes,
    ["tracker", "tracker3"],
    ["Two-query differencing", "Three-query differencing"],
):
    for mi, mode in enumerate(["stateless", "pairwise", "linear", "strict"]):
        xs = [r["audit"][f"k={k}"][mode]["benign_query_refusal_rate"] * 100 for k in (2, 3, 5)]
        ys = [r["audit"][f"k={k}"][mode]["attack_prevented"][fam] for k in (2, 3, 5)]
        ax.plot(xs, ys, marker="os^D"[mi], color=colors[mi], ms=4, label=mode,
                linestyle=["-", "--", ":", "-."][mi])
    ax.set_title(title, fontsize=8)
    ax.set_xscale("symlog", linthresh=0.5)
    ax.set_xlabel("Benign queries refused (%)", fontsize=7)
    ax.tick_params(labelsize=6)
axes[0].set_ylabel("Attacks prevented", fontsize=7)
axes[0].set_ylim(-0.03, 1.08)
h, lab = axes[0].get_legend_handles_labels()
fig.legend(h, lab, loc="lower center", ncol=4, fontsize=6, frameon=False, bbox_to_anchor=(0.5, -0.08))
fig.tight_layout()
out = Path(__file__).resolve().parent / "figures" / "fig7_audit_tradeoff.pdf"
fig.savefig(out)
print(out)
