#!/usr/bin/env python3
"""
Off-chain cost of each authentication design, from the device's and the aggregator's view.

  K1   ECDSA/secp256k1   (libsecp256k1 via coincurve)          per-message verification
  R1   ECDSA/P-256       (OpenSSL via cryptography)            per-message verification
  BLS  BLS12-381, per-device keys, aggregate signature          e(sigma,-P2) * prod_j e(sum H(m_i), pk_j) = 1
  IBS  MLAV-IBS, pseudonym-grouped small-exponent batch (B3)   (from mlav_ibs_bench)

Reported: device signing time, aggregator verification time per message for a batch of
n messages from m devices, signature size. Usage: python3 compare_schemes.py [--quick] [--out DIR]
"""
import argparse, csv, json, os, secrets, statistics, time
import coincurve
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from py_arkworks_bls12381 import G1Point, G2Point, GT, Scalar
import mlav_ibs_bench as ibs

DST_BLS = b"MLAV-BENCH-BLS-SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_"
P2 = G2Point()


def rec(i):
    return b"CAM-RPI-V2|" + str(1_700_000_000 + i).encode() + b"|" + secrets.token_bytes(52)


def med(fn, reps):
    ts = []
    for _ in range(reps):
        t0 = time.perf_counter(); ok = fn(); ts.append(time.perf_counter() - t0)
        assert ok is not False
    return statistics.median(ts) * 1e3


# ------------------------------------------------------------------ K1
class K1:
    name, sig_bytes = "ECDSA secp256k1", 65
    def __init__(self, m): self.keys = [coincurve.PrivateKey() for _ in range(m)]; self.pubs = [k.public_key for k in self.keys]
    def sign(self, j, msg): return self.keys[j].sign_recoverable(msg)          # SHA-256 prehash inside
    def verify_batch(self, items):                                              # recover + compare
        return all(coincurve.PublicKey.from_signature_and_message(s, msg).format() == self.pubs[j].format() for j, msg, s in items)


# ------------------------------------------------------------------ R1
class R1:
    name, sig_bytes = "ECDSA P-256", 64
    def __init__(self, m):
        self.keys = [ec.generate_private_key(ec.SECP256R1()) for _ in range(m)]; self.pubs = [k.public_key() for k in self.keys]
    def sign(self, j, msg): return self.keys[j].sign(msg, ec.ECDSA(hashes.SHA256()))
    def verify_batch(self, items):
        for j, msg, s in items:
            self.pubs[j].verify(s, msg, ec.ECDSA(hashes.SHA256()))             # raises on failure
        return True


# ------------------------------------------------------------------ BLS (aggregate)
class BLS:
    name, sig_bytes = "BLS12-381 aggregate", 48       # per batch, not per message
    def __init__(self, m):
        self.sks = [ibs.rand_scalar() for _ in range(m)]; self.pks = [P2 * s for s in self.sks]
    def sign(self, j, msg): return G1Point.hash_to_curve(msg, DST_BLS) * self.sks[j]
    def aggregate(self, sigs):
        return G1Point.multiexp_unchecked(sigs, [Scalar(1)] * len(sigs))
    def verify_batch(self, items, agg):
        acc = {}
        for j, msg, _ in items:
            h = G1Point.hash_to_curve(msg, DST_BLS)
            acc[j] = h if j not in acc else acc[j] + h
        js = sorted(acc)
        return GT.pairing_check([agg] + [acc[j] for j in js], [-P2] + [self.pks[j] for j in js])


def run(sizes, m, reps):
    rows, sign_rows = [], []
    k1, r1, bls = K1(m), R1(m), BLS(m)
    kgc = ibs.KGC(); devs = [kgc.extract(f"farmer-{j}".encode()) for j in range(m)]
    msg = rec(0)
    sign_rows += [
        {"scheme": "K1", "sign_ms": round(med(lambda: k1.sign(0, msg), reps * 20), 4), "sig_bytes_per_msg": 65},
        {"scheme": "R1", "sign_ms": round(med(lambda: r1.sign(0, msg), reps * 20), 4), "sig_bytes_per_msg": 64},
        {"scheme": "BLS", "sign_ms": round(med(lambda: bls.sign(0, msg), reps * 20), 4), "sig_bytes_per_msg": 48},
        {"scheme": "IBS", "sign_ms": round(med(lambda: devs[0].sign(msg), reps * 20), 4), "sig_bytes_per_msg": 96},
    ]
    for r in sign_rows: print(f"  sign {r['scheme']:4s} {r['sign_ms']:.4f} ms")
    for n in sizes:
        msgs = [(i % m, rec(i)) for i in range(n)]
        it_k1 = [(j, x, k1.sign(j, x)) for j, x in msgs]
        it_r1 = [(j, x, r1.sign(j, x)) for j, x in msgs]
        it_bls = [(j, x, bls.sign(j, x)) for j, x in msgs]
        agg = bls.aggregate([s for _, _, s in it_bls])
        it_ibs = [devs[j].sign(x) for j, x in msgs]
        cases = {
            "K1": lambda: k1.verify_batch(it_k1),
            "R1": lambda: r1.verify_batch(it_r1),
            "BLS": lambda: bls.verify_batch(it_bls, agg),
            "IBS": lambda: ibs.batch_grouped(it_ibs, kgc, recompute=True),
            "IBS (Q cached)": lambda: ibs.batch_grouped(it_ibs, kgc, recompute=False),
        }
        for name, fn in cases.items():
            t = med(fn, reps)
            rows.append({"scheme": name, "n": n, "devices": m, "total_ms": round(t, 3), "per_msg_ms": round(t / n, 4)})
            print(f"  n={n:5d} {name:16s} {t:9.2f} ms  {t / n:.4f} ms/msg", flush=True)
    return rows, sign_rows


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--quick", action="store_true"); ap.add_argument("--out", default="results")
    a = ap.parse_args(); os.makedirs(a.out, exist_ok=True)
    sizes = [1, 10, 100] if a.quick else [1, 10, 100, 1000]
    rows, sign_rows = run(sizes, 10, 3 if a.quick else 7)
    for path, data in (("compare_verify.csv", rows), ("compare_sign.csv", sign_rows)):
        with open(os.path.join(a.out, path), "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(data[0])); w.writeheader(); w.writerows(data)
    from importlib.metadata import version
    json.dump({"coincurve": version("coincurve"), "cryptography": version("cryptography"),
               "py_arkworks_bls12381": version("py_arkworks_bls12381"), "devices": 10},
              open(os.path.join(a.out, "compare_env.json"), "w"), indent=2)


if __name__ == "__main__":
    main()
