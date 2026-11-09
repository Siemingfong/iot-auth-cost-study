#!/usr/bin/env python3
"""Reproduces the two flaws found in the 2021 IoP/MLAV signature design.

Attack 1 (key recovery): sigma = v*PrK1 + w*PrK2 is linear in the two private keys and
  v, w are public. Two signatures of one device give a 2x2 linear system over Z_r whose
  solution is (PrK1, PrK2); the attacker then signs arbitrary data for that device.
Attack 2 (batch cancellation): plain-sum batch verification accepts sigma_a + X and
  sigma_b - X, although both are individually invalid.
"""
import json
from legacy_2021_scheme import KGC, Device, make_messages, verify_multipairing, batch_naive, batch_set, P1, rand_scalar

kgc = KGC()
dev = kgc.extract(b"farmer-00001")
a = dev.sign(b"CAM", b"1", b"chk-a" * 6, b"seed-a")
b = dev.sign(b"CAM", b"2", b"chk-b" * 6, b"seed-b")
(va, wa), (vb, wb) = a.vw(), b.vw()
inv = (va * wb - vb * wa).inverse()
K1 = (a.sigma * wb - b.sigma * wa) * inv
K2 = (b.sigma * va - a.sigma * vb) * inv
forged = Device(dev.sid1, dev.sid2, dev.q, K1, K2).sign(b"FAKE", b"999", b"fake" * 8, b"fake-seed")

msgs = make_messages(kgc, 20, 5)
X = P1 * rand_scalar()
msgs[3].sigma = msgs[3].sigma + X
msgs[11].sigma = msgs[11].sigma - X

out = {
    "attack1_key_recovery": {"PrK1_recovered": K1 == dev.prk1, "PrK2_recovered": K2 == dev.prk2,
                             "forgery_accepted": verify_multipairing(forged, kgc)},
    "attack2_batch_cancellation": {"msg3_valid": verify_multipairing(msgs[3], kgc),
                                   "msg11_valid": verify_multipairing(msgs[11], kgc),
                                   "naive_batch_accepts": batch_naive(msgs, kgc),
                                   "small_exponent_batch_accepts": batch_set(msgs, kgc)},
}
print(json.dumps(out, indent=2))
json.dump(out, open("legacy_attacks_result.json", "w"), indent=2)
