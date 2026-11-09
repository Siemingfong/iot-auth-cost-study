# Authenticating IoT data on Ethereum after Pectra/Fusaka: code and data

Reproduces every number and figure in the manuscript.

```
onchain/                         (Node.js 20+; local EVM with Osaka rules)
  Baselines.sol.tpl              K1 (ecrecover), R1 (EIP-7951 P-256), BLS aggregate with
                                 RFC 9380 hash-to-curve on EIP-2537, anchoring-only (T0/T1)
  baselines_bench.mjs            gas for K1/R1/BLS + anchoring, max batch under EIP-7825
  MLAVVerifier.sol.tpl           MLAV-IBS verifier (individual, plain-sum, small-exponent, grouped)
  gasbench.mjs                   gas for MLAV-IBS
  plot_compare.py, plot_gas.py   figures
  results/                       CSV/JSON, generated .sol files, figures
figures/                         manuscript figures
  make_figures.py                Fig. 3 and 4 from the CSV results (vector PDF, Springer sizes)
  fig1_architecture.tex          Fig. 1 (TikZ)
  fig2_workflow.tex              Fig. 2 (TikZ)
offchain/                        (Python 3.10+)
  compare_schemes.py             device signing + aggregator verification for all designs
  mlav_ibs_bench.py              MLAV-IBS primitives, batch verifiers, pseudonym sweep
  legacy_2021_scheme.py          original MLAV signature (INSECURE; kept for the attacks)
  legacy_2021_attacks.py         key recovery from two signatures + batch cancellation
  plot_results.py                figures
  results/
```

## Run
```
cd onchain && npm install
node baselines_bench.mjs --out results     # ~10 min
node gasbench.mjs --out results            # ~10 min
python3 plot_compare.py results

cd ../offchain
pip install py_arkworks_bls12381 coincurve cryptography matplotlib
python3 compare_schemes.py --out results   # ~2 min
python3 mlav_ibs_bench.py --out results    # ~4 min
python3 legacy_2021_attacks.py

cd ../figures
python3 make_figures.py --out .           # Fig. 3 and 4
pdflatex fig1_architecture.tex && pdflatex fig2_workflow.tex
```
`--quick` gives a smoke test. Gas figures are deterministic under the given rules;
off-chain timings depend on the machine and must be re-measured on the machine
described in the paper (and signing on the Raspberry Pi).

## Off-chain benchmarks on GitHub Actions (ARM64 and x86-64)
`.github/workflows/offchain-bench.yml` runs `offchain/compare_schemes.py` and `offchain/mlav_ibs_bench.py`
on GitHub-hosted ARM64 (`ubuntu-24.04-arm`) and x86-64 (`ubuntu-24.04`) runners with the package versions used
in the manuscript, and records each machine's specification (`offchain/machine_info.py` → `machine.json`).
Start it from the Actions tab (Run workflow); results are uploaded as artifacts
`offchain-results-ARM64-<n>` and `offchain-results-X64-<n>`. GitHub-hosted runners are shared virtual
machines, so timings vary between runs; the scripts report medians.

### Results of the GitHub-hosted runs (Table 3 of the manuscript)
`offchain/results-github-arm64/` (Arm Neoverse-N2, 4 vCPUs) and `offchain/results-github-x64/` (AMD EPYC 9V74,
4 vCPUs) hold the full-mode results of workflow run 1, including each machine's `machine.json`.

## Device-side measurements on single-board computers
`offchain/run_device_bench.sh` runs the same off-chain benchmarks on a Raspberry Pi (64-bit OS) with one
command and records the board model, temperature and throttling state before and after. Step-by-step
instructions (in Traditional Chinese) are in [`docs/RASPBERRY_PI.md`](docs/RASPBERRY_PI.md).
