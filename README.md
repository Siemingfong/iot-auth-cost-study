# Authenticating IoT data on Ethereum after Pectra/Fusaka: code and data

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.24328819.svg)](https://doi.org/10.5281/zenodo.24328819)

Release v1.1, cited by the manuscript, is archived at Zenodo under DOI [10.5281/zenodo.24328819](https://doi.org/10.5281/zenodo.24328819); release v1.0 under [10.5281/zenodo.24277045](https://doi.org/10.5281/zenodo.24277045). The code is released under the MIT License (`LICENSE`); see `CITATION.cff` for how to cite it.

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

### Raspberry Pi Zero 2 W (Table 3 of the manuscript)
`offchain/results-device-pi-zero-2-w/` holds the full run of `run_device_bench.sh` on a Raspberry Pi Zero 2 W
(Cortex-A53 at 1 GHz, 64-bit Raspberry Pi OS, Python 3.13), measured by the co-authors on 14 November 2026.
`machine.json` and `machine_after.json` record the board, temperature and throttling state (0x0, no throttling)
before and after the run.

## Domain separation and replay protection (November 2026)
All four on-chain verifiers bind every signed message to the chain id and the verifier's address, and keep,
per device, the timestamp of its last accepted record: a record is accepted only if its timestamp is strictly
larger, which stops an aggregator from anchoring an old, validly signed record again. The slot is initialised
at registration, so unregistered devices fail the same check, and each device can be registered only once, so
the KGC cannot reset a device's timestamp or replace its key. Both harnesses test that a resubmitted batch, a
batch signed for another chain, a batch signed for another contract and a second registration of a device are all
rejected
(`replay_*` and `wrong_*` entries in `onchain/results/*.json`). All on-chain results in `onchain/results/` were
re-measured with these contracts. The off-chain timing scripts sign the record without the domain prefix,
which adds 64 bytes to the hashed input and does not measurably change signing or verification times.

### Raspberry Pi 4 Model B (Table 3 of the manuscript)
`offchain/results-device-pi-4/` holds 16 full runs of `run_device_bench.sh` on a Raspberry Pi 4 Model B
(Cortex-A72 at 1.8 GHz, 2 GB, 64-bit Raspberry Pi OS, Python 3.13), measured by the co-authors on 13 November
2026. Every reading reports `throttled=0x50000`: under-voltage and throttling had occurred since boot, but not at
the time of any reading. The 16 runs agree within 1% for most timings and within 10% for all, so none was
throttled; the manuscript reports their medians, computed by `python3 summarize_runs.py results-device-pi-4`
into `results-device-pi-4/summary_median.csv`.

## Before and after Pectra and Fusaka (Table 4 of the manuscript)
Both harnesses take `--fork cancun|prague|osaka` (default `osaka`). `onchain/results-cancun/` and
`onchain/results-prague/` hold the same transactions executed under the rules before Pectra (Cancun) and after
Pectra (Prague); `onchain/results/` holds the Osaka (Fusaka) run. Designs whose precompile does not exist under a
fork are reported as unsupported (R1 before Osaka; BLS and MLAV-IBS before Prague). Before Osaka there is no
per-transaction cap, so transactions are limited to the 36-million block gas limit and no largest batch is searched.

## Parallel aggregator throughput
`offchain/parallel_bench.py` measures batch-verification throughput with 1, 2 and 4 worker processes (each worker
verifies its own pre-signed batches of 1,000 records; throughput = records / slowest worker's time). It runs in the
GitHub Actions workflow and, on a Raspberry Pi, with `offchain/run_parallel_bench.sh` (see `docs/RASPBERRY_PI.md`).

### Further GitHub-hosted runs
`offchain/results-github-*-run2/` and `-run3/` hold workflow runs 2 and 3. GitHub assigns different machines to
different runs (run 1 used an AMD EPYC 9V74 x86-64 runner, runs 2 and 3 an Intel Xeon 6975P-C with two cores and
two hardware threads each). Run 3 includes the parallel aggregator throughput (`parallel.csv`, Table 4 of the
manuscript); Table 3 uses run 1.

### Parallel throughput on the Raspberry Pi boards (Table 4 of the manuscript)
`offchain/results-parallel-pi-4/` and `offchain/results-parallel-pi-zero-2-w/` hold `run_parallel_bench.sh` on the
Pi 4 Model B and the Pi Zero 2 W (16 November 2026); both report `throttled=0x0` before and after the run.

## Repeated runs and statistics
`offchain/run_repeated.sh device|parallel` repeats the device or parallel benchmark on a single-board computer
(`RUNS`, default 10; `PAUSE` seconds between runs, default 60) and `offchain/summarize_runs.py` reports, for every
timing, the number of runs, mean, standard deviation, coefficient of variation, median, quartiles, minimum, maximum
and spread, together with the throttling flags recorded before and after each run.

### Repeated runs on the Raspberry Pi boards (Tables 3 and 4 of the manuscript)
`offchain/batch-device-raspberry-pi-4-*/` and `offchain/batch-device-raspberry-pi-zero-2-w-*/` (10 single-core runs each), `offchain/batch-parallel-raspberry-pi-4-*/`
and `offchain/batch-parallel-raspberry-pi-zero-2-w-*/` (10 parallel runs each) were produced by `run_repeated.sh` on
17 November 2026; each holds the individual runs and `summary_stats.csv`. All 40 runs report `throttled=0x0` before
and after. The Pi 4 single-core batch replaces the 16 earlier runs in `results-device-pi-4/` (which report
`throttled=0x50000`, i.e. under-voltage since boot) and agrees with their medians within 0.3%. The manuscript reports the medians; coefficients of variation across runs are at most 2.3% (single-core)
and 1.1% (parallel throughput).

## Devices per batch (Table 2 of the journal version)
`node baselines_bench.mjs --quick --sweep --out results-device-sweep` registers 200 devices per design and measures a
batch of 200 records drawn from m = 1, 5, 10, 50 and 200 devices for K1, R1 and BLS
(`onchain/results-device-sweep/baselines_device_sweep.csv`); the MLAV-IBS values come from the existing device sweep
in `onchain/results/gas_device_sweep.csv`. With `--quick`, the other parts of the run are abbreviated; the device sweep
itself is complete.
