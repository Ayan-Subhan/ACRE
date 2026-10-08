"""Figures, shared across phases.

Kept out of the phase scripts because phases 5-7 need the same styling, and
because a plotting bug should never be able to destroy an expensive run: every
function here reads a saved report file, never live state.
"""

from __future__ import annotations

import logging
from pathlib import Path

import matplotlib

matplotlib.use("Agg")  # no display on a headless/CI run
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

log = logging.getLogger(__name__)

MODEL_ORDER = ["mlp", "cnn", "lstm"]
ATTACK_ORDER = ["fgsm", "bim", "pgd", "deepfool"]

# Colour-blind-safe, and distinguishable in greyscale print.
ATTACK_COLORS = {
    "fgsm": "#4C72B0",
    "bim": "#DD8452",
    "pgd": "#55A868",
    "deepfool": "#C44E52",
}
CLEAN_COLOR = "#8C8C8C"

# BIM and PGD frequently agree to the decimal -- PGD is BIM with more iterations
# -- so on a line chart one is drawn exactly on top of the other and appears
# missing. Distinct dash patterns and marker shapes keep every series readable
# where they coincide; colour alone is not enough.
ATTACK_STYLES = {
    "fgsm": {"linestyle": "-", "marker": "o", "linewidth": 1.8},
    "bim": {"linestyle": "--", "marker": "s", "linewidth": 2.6},
    "pgd": {"linestyle": ":", "marker": "^", "linewidth": 1.8},
    "deepfool": {"linestyle": "-.", "marker": "D", "linewidth": 1.8},
}


def _style(ax) -> None:
    ax.spines[["top", "right"]].set_visible(False)
    ax.grid(axis="y", alpha=0.3, linewidth=0.6)
    ax.set_axisbelow(True)


def figure3_evasion(metrics: dict, out_path: Path) -> Path:
    """Figure 3 - clean vs. adversarial accuracy, grouped by model.

    The paper's headline result: three models above 99.7% on clean traffic,
    collapsing under perturbation. One grey bar per model for the clean
    baseline, then one coloured bar per attack.
    """
    results = metrics["results"]
    models = [m for m in MODEL_ORDER if m in results]
    attacks = [a for a in ATTACK_ORDER if any(a in results[m] for m in models)]

    n_bars = len(attacks) + 1
    width = 0.8 / n_bars
    x = np.arange(len(models))

    fig, ax = plt.subplots(figsize=(9, 4.8))

    clean = [100 * results[m][attacks[0]]["accuracy_clean"] for m in models]
    ax.bar(x - 0.4 + width / 2, clean, width, label="clean", color=CLEAN_COLOR)

    for i, attack in enumerate(attacks, start=1):
        vals = [
            100 * results[m][attack]["accuracy_adv"] if attack in results[m] else np.nan
            for m in models
        ]
        ax.bar(
            x - 0.4 + width * (i + 0.5),
            vals,
            width,
            label=attack.upper(),
            color=ATTACK_COLORS.get(attack),
        )

    ax.set_xticks(x)
    ax.set_xticklabels([m.upper() for m in models])
    ax.set_ylabel("Detection rate on attack flows (%)")
    ax.set_ylim(0, 105)
    ax.set_title(
        "Figure 3 - baseline NIDS accuracy under white-box evasion\n"
        f"{metrics['n_samples']:,} true-attack test flows per cell",
        fontsize=11,
    )
    ax.legend(frameon=False, ncol=n_bars, loc="upper center", bbox_to_anchor=(0.5, -0.09))
    _style(ax)
    fig.tight_layout()

    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path, dpi=200, bbox_inches="tight")
    plt.close(fig)
    log.info("wrote %s", out_path)
    return out_path


def figure4_eps_sweep(sweep: pd.DataFrame, out_path: Path) -> Path:
    """Figure 4 - accuracy vs. eps, one panel per model.

    The result the paper does not have. A single operating point cannot
    distinguish a model that degrades gracefully from one that falls off a
    cliff, and a non-monotone curve is evidence of gradient masking.
    """
    models = [m for m in MODEL_ORDER if m in set(sweep["model"])]
    fig, axes = plt.subplots(1, len(models), figsize=(4.2 * len(models), 4.2), sharey=True)
    axes = np.atleast_1d(axes)

    for ax, model in zip(axes, models):
        sub = sweep[sweep["model"] == model]
        for attack in [a for a in ATTACK_ORDER if a in set(sub["attack"])]:
            s = sub[sub["attack"] == attack].sort_values("eps")
            ax.plot(
                s["eps"],
                100 * s["accuracy_adv"],
                markersize=5.5,
                markerfacecolor="none",
                label=attack.upper(),
                color=ATTACK_COLORS.get(attack),
                **ATTACK_STYLES.get(attack, {"linestyle": "-", "marker": "o"}),
            )
        ax.set_xscale("log")
        ax.set_xlabel(r"$\epsilon$  (L$_\infty$ budget, fraction of feature range)")
        ax.set_title(model.upper(), fontsize=11)
        _style(ax)

    axes[0].set_ylabel("Detection rate on attack flows (%)")
    axes[0].set_ylim(-3, 105)
    axes[-1].legend(frameon=False, title="attack")
    fig.suptitle("Figure 4 - robustness vs. perturbation budget", fontsize=12)
    fig.tight_layout()

    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path, dpi=200, bbox_inches="tight")
    plt.close(fig)
    log.info("wrote %s", out_path)
    return out_path


PROTOCOL_COLORS = {
    "random": "#8C8C8C",
    "leave_one_attack_out": "#C44E52",
    "leave_one_model_out": "#4C72B0",
}


def figure5_discriminator(table: pd.DataFrame, out_path: Path) -> Path:
    """Figure 5 - discriminator catch rate and FPR, per evaluation protocol.

    The point of the figure is the *gap*, so the random-protocol catch rate is
    drawn as a reference line across the hold-out bars. A reader who only sees
    the leftmost bar has the paper's result; the distance from that line to the
    coloured bars is what the reproduction adds.

    FPR shares the figure rather than sitting in a separate one because the two
    numbers are only meaningful together -- a gate that quarantines 3% of
    legitimate traffic is unusable whatever it catches.
    """
    labels = [
        r["held_out"] if r["held_out"] != "-" else "all attacks"
        for _, r in table.iterrows()
    ]
    colors = [PROTOCOL_COLORS.get(p, "#55A868") for p in table["protocol"]]
    x = np.arange(len(table))

    fig, axes = plt.subplots(
        2, 1, figsize=(max(6.5, 1.1 * len(table)), 5.6),
        sharex=True, gridspec_kw={"height_ratios": [2.6, 1]},
    )

    bars = axes[0].bar(x, table["catch_%"], color=colors, width=0.68)
    axes[0].bar_label(bars, fmt="%.1f", fontsize=8, padding=2)
    baseline = table.loc[table["protocol"] == "random", "catch_%"]
    if len(baseline):
        axes[0].axhline(
            baseline.iloc[0], color="#333333", linestyle="--", linewidth=1.0,
            label=f"trained on all attacks ({baseline.iloc[0]:.2f}%)",
        )
        axes[0].legend(frameon=False, loc="center left", fontsize=9)
    axes[0].set_ylabel("Catch rate on\nadversarial rows (%)")
    axes[0].set_ylim(0, 112)

    # FPR keeps its own panel even when every fold reports zero: the catch rate
    # only means something next to the cost of achieving it, and an empty panel
    # labelled as empty says that more plainly than dropping it would.
    axes[1].bar(x, table["fpr_%"], color=colors, width=0.68)
    axes[1].set_ylabel("Clean traffic\nquarantined (%)")
    top = float(table["fpr_%"].max())
    axes[1].set_ylim(0, max(top * 1.3, 0.05))
    if top == 0:
        axes[1].text(
            0.5, 0.55, "no false positives in any fold",
            transform=axes[1].transAxes, ha="center", fontsize=9, color="#555555",
        )
    axes[1].set_xticks(x)
    axes[1].set_xticklabels(labels, rotation=30, ha="right", fontsize=9)

    for ax in axes:
        _style(ax)

    present = [p for p in PROTOCOL_COLORS if p in set(table["protocol"])]
    handles = [plt.Rectangle((0, 0), 1, 1, color=PROTOCOL_COLORS[p]) for p in present]
    axes[0].legend(
        axes[0].get_legend_handles_labels()[0] + handles,
        axes[0].get_legend_handles_labels()[1] + [p.replace("_", " ") for p in present],
        frameon=False, fontsize=8.5, loc="center left",
    )

    fig.suptitle("Figure 5 - what the discriminator is worth against an unseen attack", fontsize=12)
    fig.tight_layout()

    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path, dpi=200, bbox_inches="tight")
    plt.close(fig)
    log.info("wrote %s", out_path)
    return out_path


REGIME_COLORS = {
    "baseline": "#8C8C8C",
    "transferred": "#55A868",
    "adaptive": "#C44E52",
}


def figure6_eids(clean: pd.DataFrame, robustness: pd.DataFrame, out_path: Path) -> Path:
    """Figure 6 - what adversarial training bought, and what it cost.

    Left: the ensemble's detection rate per attack in three regimes. The middle
    bar is what a stale adversary gets; the right bar is what a current one gets.
    A tall middle bar next to a short right bar is the signature of static
    adversarial training and the single most important thing this figure has to
    show, so the two are drawn side by side rather than in separate panels.

    Right: the clean-traffic cost. Robustness that arrives with an unusable false
    alarm rate is not an improvement, and FPR is the axis where an OR ensemble
    pays for its extra recall.
    """
    fig, axes = plt.subplots(1, 2, figsize=(11.5, 4.6), gridspec_kw={"width_ratios": [1.55, 1]})

    # --- robustness ---------------------------------------------------------
    ens = [c for c in robustness.columns if c.upper().startswith("ENSEMBLE")]
    ens_col = ens[0] if ens else None
    attacks = [a for a in ATTACK_ORDER if a in set(robustness["attack"])]
    width = 0.27
    x = np.arange(len(attacks))

    def mean_for(regime: str, column: str) -> list[float]:
        sub = robustness[robustness["regime"] == regime]
        return [float(sub.loc[sub["attack"] == a, column].mean()) if len(sub) else np.nan
                for a in attacks]

    series = [("baseline", mean_for("transferred", "baseline_%"))]
    if ens_col:
        series.append(("transferred", mean_for("transferred", ens_col)))
        if (robustness["regime"] == "adaptive").any():
            series.append(("adaptive", mean_for("adaptive", ens_col)))

    for i, (label, values) in enumerate(series):
        offset = (i - (len(series) - 1) / 2) * width
        bars = axes[0].bar(x + offset, values, width, label=label,
                           color=REGIME_COLORS.get(label, "#4C72B0"))
        axes[0].bar_label(bars, fmt="%.0f", fontsize=7.5, padding=2)

    axes[0].set_xticks(x)
    axes[0].set_xticklabels([a.upper() for a in attacks])
    axes[0].set_ylabel("Detection rate on adversarial flows (%)")
    # Headroom for the legend: with three regimes at least one series is usually
    # near 100%, and a legend inside the axes lands on top of it.
    axes[0].set_ylim(0, 128)
    axes[0].set_title("EIDS under attack", fontsize=11)
    axes[0].legend(frameon=False, fontsize=9, ncol=len(series), loc="upper center")
    _style(axes[0])

    # --- clean cost ---------------------------------------------------------
    order = [m for m in [n.upper() for n in MODEL_ORDER] + ["ENSEMBLE"]
             if m in set(clean["model"])]
    xc = np.arange(len(order))
    for i, variant in enumerate(["baseline", "eids"]):
        sub = clean[clean["variant"] == variant].set_index("model")
        values = [float(sub.loc[m, "fpr_%"]) if m in sub.index else np.nan for m in order]
        bars = axes[1].bar(
            xc + (i - 0.5) * 0.36, values, 0.36, label=variant,
            color="#8C8C8C" if variant == "baseline" else "#4C72B0",
        )
        axes[1].bar_label(bars, fmt="%.3f", fontsize=7.5, padding=2)

    axes[1].set_xticks(xc)
    axes[1].set_xticklabels(order, fontsize=9)
    axes[1].set_ylabel("Clean traffic false-flagged (%)")
    axes[1].set_title("What it costs on clean traffic", fontsize=11)
    axes[1].legend(frameon=False, fontsize=9)
    _style(axes[1])

    fig.suptitle("Figure 6 - adversarial training and the OR ensemble", fontsize=12)
    fig.tight_layout()

    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path, dpi=200, bbox_inches="tight")
    plt.close(fig)
    log.info("wrote %s", out_path)
    return out_path


STAGE_COLORS = {
    "validator": "#12655C",
    "discriminator": "#DD8452",
    "eids": "#4C72B0",
    "allowed": "#D9D9D9",
}


def figure7_pipeline(table: pd.DataFrame, ablation: pd.DataFrame, out_path: Path) -> Path:
    """Figure 7 - which stage stops what, and what each stage adds.

    Left: one stacked bar per traffic class, segmented by the stage that stopped
    the flow. Stacking is the right form here because the stages are exclusive by
    construction -- the pipeline short-circuits, so every row belongs to exactly
    one segment and the bar sums to 100%.

    Right: the ablation. Catch rate as bars against the left axis, false-positive
    rate as points against the right. They share a panel because a subset is only
    better than another if it improves one without ruining the other, and that
    comparison is impossible across two figures.
    """
    fig, axes = plt.subplots(
        1, 2, figsize=(13.5, max(4.4, 0.42 * len(table) + 1.6)),
        gridspec_kw={"width_ratios": [1.35, 1]},
    )

    # --- who stopped what ---------------------------------------------------
    segments = [(f"by_{s}_%", s) for s in ("validator", "discriminator", "eids")]
    segments.append(("allowed_%", "allowed"))
    labels = list(table["traffic"])
    y = np.arange(len(table))[::-1]  # first row at the top
    left = np.zeros(len(table))

    for column, name in segments:
        if column not in table:
            continue
        values = table[column].to_numpy(dtype=float)
        axes[0].barh(y, values, left=left, height=0.7,
                     color=STAGE_COLORS[name], label=name)
        left += values

    axes[0].set_yticks(y)
    axes[0].set_yticklabels(labels, fontsize=8.5)
    axes[0].set_xlabel("Share of flows (%)")
    axes[0].set_xlim(0, 100)
    axes[0].set_title("Which stage stopped the flow", fontsize=11)
    axes[0].legend(frameon=False, fontsize=8.5, ncol=4, loc="upper center",
                   bbox_to_anchor=(0.5, -0.12))
    axes[0].spines[["top", "right"]].set_visible(False)
    axes[0].grid(axis="x", alpha=0.3, linewidth=0.6)
    axes[0].set_axisbelow(True)

    # --- ablation -----------------------------------------------------------
    if len(ablation):
        x = np.arange(len(ablation))
        bars = axes[1].bar(x, ablation["catch_%"], 0.62, color="#55A868", label="catch")
        axes[1].bar_label(bars, fmt="%.1f", fontsize=7.5, padding=2)
        axes[1].set_ylabel("Adversarial rows stopped (%)")
        axes[1].set_ylim(0, 118)
        axes[1].set_xticks(x)
        axes[1].set_xticklabels(
            [s.replace("+", "\n+") for s in ablation["stages"]], fontsize=7.5
        )

        cost = axes[1].twinx()
        # Markers, not a line: the subsets on the x-axis have no order to
        # interpolate between, and joining them would imply a trend.
        cost.plot(x, ablation["fpr_%"], "o", color="#A63F2E", markersize=7,
                  markerfacecolor="none", markeredgewidth=1.6, label="FPR")
        cost.set_ylabel("Clean traffic dropped (%)", color="#A63F2E")
        cost.tick_params(axis="y", colors="#A63F2E")
        cost.set_ylim(0, max(float(ablation["fpr_%"].max()) * 1.6, 0.05))
        cost.spines[["top"]].set_visible(False)

        axes[1].set_title("Ablation: every subset of the three gates", fontsize=11)
        axes[1].spines[["top"]].set_visible(False)
        axes[1].grid(axis="y", alpha=0.3, linewidth=0.6)
        axes[1].set_axisbelow(True)
        handles = [plt.Rectangle((0, 0), 1, 1, color="#55A868"),
                   plt.Line2D([0], [0], color="#A63F2E", marker="o", linestyle="none",
                              markerfacecolor="none")]
        axes[1].legend(handles, ["catch (left axis)", "FPR (right axis)"],
                       frameon=False, fontsize=8.5, loc="lower left")
    else:
        axes[1].axis("off")

    fig.suptitle("Figure 7 - the AAD pipeline end to end", fontsize=12)
    fig.tight_layout()

    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path, dpi=200, bbox_inches="tight")
    plt.close(fig)
    log.info("wrote %s", out_path)
    return out_path
