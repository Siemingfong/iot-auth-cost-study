#!/usr/bin/env python3
"""
Regenerate the data figures of the manuscript in one consistent style.

Style: Springer artwork guidelines (vector PDF, embedded fonts, 84 mm single-column or
174 mm full-width, 8-9 pt text), Times-compatible serif font (STIX), Okabe-Ito
colour-blind-safe palette, and distinct markers/line styles so that every series is
also distinguishable in grayscale print.

Usage: python3 make_figures.py [--onchain ../onchain/results] [--offchain ../offchain/results] [--out out]
"""
import argparse, csv, json, os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import FuncFormatter, LogLocator, NullFormatter

MM = 1 / 25.4
plt.rcParams.update({
    "font.family": "STIXGeneral", "mathtext.fontset": "stix",
    "font.size": 8.5, "axes.labelsize": 8.5, "axes.titlesize": 8.5,
    "xtick.labelsize": 7.5, "ytick.labelsize": 7.5, "legend.fontsize": 7.2,
    "axes.linewidth": 0.6, "xtick.major.width": 0.6, "ytick.major.width": 0.6,
    "xtick.minor.width": 0.4, "ytick.minor.width": 0.4,
    "xtick.direction": "in", "ytick.direction": "in", "xtick.top": True, "ytick.right": True,
    "lines.linewidth": 1.2, "lines.markersize": 4.2,
    "legend.frameon": False, "pdf.fonttype": 42, "ps.fonttype": 42,
    "savefig.bbox": "tight", "savefig.pad_inches": 0.02,
})

# Okabe-Ito palette
C = {"K1": "#0072B2", "R1": "#E69F00", "BLS": "#009E73", "B2": "#CC79A7", "B3": "#D55E00", "T1": "#000000"}
STYLE = {
    "K1":  dict(color=C["K1"], marker="o", ls="-", mfc="white", label="K1  ECDSA secp256k1"),
    "R1":  dict(color=C["R1"], marker="s", ls="-", mfc="white", label="R1  ECDSA P-256"),
    "BLS": dict(color=C["BLS"], marker="^", ls="-.", mfc="white", label="BLS aggregate"),
    "B2":  dict(color=C["B2"], marker="v", ls="--", mfc="white", label="IBS small-exponent (B2)"),
    "B3":  dict(color=C["B3"], marker="D", ls="-", label="IBS pseudonym-grouped (B3)", markersize=3.6),
    "T1":  dict(color=C["T1"], marker="x", ls=":", label="T1 anchoring, no authentication"),
}
thousands = FuncFormatter(lambda v, _: f"{int(v):,}")


def read(path):
    with open(path) as f:
        return list(csv.DictReader(f))


def style_log_axes(ax):
    ax.set_xscale("log"); ax.set_yscale("log")
    ax.xaxis.set_major_locator(LogLocator(base=10))
    ax.yaxis.set_minor_formatter(NullFormatter())
    ax.grid(True, which="major", lw=0.4, color="0.85"); ax.grid(True, which="minor", lw=0.25, color="0.93")
    ax.set_axisbelow(True)


def fig_onchain(onchain, out):
    base = [r for r in read(os.path.join(onchain, "baselines_scaling.csv")) if r["ok"] == "true"]
    ibs = [r for r in read(os.path.join(onchain, "gas_scaling.csv")) if r["ok"] == "true"]
    anch = read(os.path.join(onchain, "anchoring_only.csv"))
    bres = json.load(open(os.path.join(onchain, "baselines_results.json")))
    ires = json.load(open(os.path.join(onchain, "gas_results.json")))
    series = {
        "K1": [(int(r["n"]), int(r["per_msg_gas"])) for r in base if r["scheme"] == "K1"],
        "R1": [(int(r["n"]), int(r["per_msg_gas"])) for r in base if r["scheme"] == "R1"],
        "BLS": [(int(r["n"]), int(r["per_msg_gas"])) for r in base if r["scheme"] == "BLS"],
        "B2": [(int(r["n"]), int(r["per_msg_gas"])) for r in ibs if r["method"].startswith("B2")],
        "B3": [(int(r["n"]), int(r["per_msg_gas"])) for r in ibs if r["method"].startswith("B3")],
        "T1": [(int(r["n"]), round(int(r["leaves_root_gas"]) / int(r["n"]))) for r in anch],
    }
    fig, (a, b) = plt.subplots(1, 2, figsize=(174 * MM, 64 * MM), gridspec_kw={"width_ratios": [1.45, 1]})

    # (a) gas per record
    for k in ("BLS", "B2", "B3", "R1", "K1", "T1"):
        a.plot(*zip(*sorted(series[k])), **STYLE[k])
    style_log_axes(a)
    a.set_xlim(0.8, 1300); a.set_ylim(800, 3_000_000)
    a.set_xticks([1, 10, 100, 1000]); a.set_xticklabels(["1", "10", "100", "1,000"])
    a.yaxis.set_major_formatter(thousands)
    a.set_xlabel("Records per transaction, $n$"); a.set_ylabel("Gas per record")
    a.legend(loc="upper center", ncol=2, handlelength=2.4, columnspacing=1.0, borderaxespad=0.2)
    a.text(0.02, 0.03, "(a)", transform=a.transAxes, fontweight="bold")

    # (b) largest batch under EIP-7825
    order = [("K1", bres["max_batch"]["K1"]), ("R1", bres["max_batch"]["R1"]),
             ("B3", ires["max_batch"]["B3 grouped small-exponent batch"]),
             ("B2", ires["max_batch"]["B2 small-exponent batch"]), ("BLS", bres["max_batch"]["BLS"])]
    names = {"K1": "K1", "R1": "R1", "B3": "IBS-B3", "B2": "IBS-B2", "BLS": "BLS"}
    hatches = {"K1": "", "R1": "////", "B3": "", "B2": "\\\\\\\\", "BLS": "...."}
    y = range(len(order))[::-1]
    for yi, (k, v) in zip(y, order):
        b.barh(yi, v, height=0.62, color=C[k] if k in ("K1", "B3") else "white",
               edgecolor=C[k], hatch=hatches[k], lw=0.9)
        b.text(v + 30, yi, f"{v:,}", va="center", fontsize=7.5)
    b.set_yticks(list(y)); b.set_yticklabels([names[k] for k, _ in order])
    b.set_xlim(0, 2150); b.xaxis.set_major_formatter(thousands)
    b.set_xlabel("Largest batch per transaction (records)")
    b.tick_params(axis="y", which="both", length=0); b.tick_params(axis="x", top=False)
    b.grid(True, axis="x", lw=0.4, color="0.85"); b.set_axisbelow(True)
    for s in ("top", "right"): b.spines[s].set_visible(False)
    b.text(0.97, 0.03, "(b)", transform=b.transAxes, ha="right", fontweight="bold")
    b.text(0.97, 0.13, "EIP-7825 cap: 16,777,216 gas", transform=b.transAxes, ha="right", fontsize=7, color="0.3")

    fig.tight_layout(w_pad=2.0)
    fig.savefig(os.path.join(out, "fig3_onchain_gas.pdf")); fig.savefig(os.path.join(out, "fig3_onchain_gas.png"), dpi=300)
    plt.close(fig)


def fig_pseudonyms(offchain, out):
    rows = read(os.path.join(offchain, "device_sweep.csv"))
    fig, ax = plt.subplots(figsize=(84 * MM, 58 * MM))
    for k, method in (("B2", "B2 small-exponent batch"), ("B3", "B3 grouped small-exponent batch")):
        pts = sorted((int(r["devices"]), float(r["total_ms"])) for r in rows if r["method"] == method)
        ax.plot(*zip(*pts), **STYLE[k])
    ax.set_xscale("log"); ax.set_xticks([1, 10, 100, 1000]); ax.set_xticklabels(["1", "10", "100", "1,000"])
    ax.set_ylim(0, 70); ax.set_xlim(0.7, 1500)
    ax.set_xlabel("Distinct pseudonyms in the batch, $m$"); ax.set_ylabel("Verification time (ms)")
    ax.grid(True, which="major", lw=0.4, color="0.85"); ax.set_axisbelow(True)
    n = rows[0]["n"]
    ax.legend(loc="lower right", handlelength=2.6, title=f"$n$ = {int(n):,} records, $Q_{{ID}}$ cached",
              title_fontsize=7.2)
    fig.tight_layout()
    fig.savefig(os.path.join(out, "fig4_ibs_pseudonyms.pdf")); fig.savefig(os.path.join(out, "fig4_ibs_pseudonyms.png"), dpi=300)
    plt.close(fig)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--onchain", default="../onchain/results")
    ap.add_argument("--offchain", default="../offchain/results")
    ap.add_argument("--out", default="out")
    a = ap.parse_args(); os.makedirs(a.out, exist_ok=True)
    fig_onchain(a.onchain, a.out)
    fig_pseudonyms(a.offchain, a.out)
    print("figures written to", a.out)


if __name__ == "__main__":
    main()
