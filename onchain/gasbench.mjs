// MLAV-IBS on-chain gas benchmark on a local EVM (ethereumjs, Osaka rules incl. EIP-2537,
// EIP-7623 calldata floor and EIP-7825 per-transaction gas cap).
// Usage: node gasbench.mjs [--quick] [--out results]
import fs from 'node:fs'
import crypto from 'node:crypto'
import solc from 'solc'
import { bls12_381 } from '@noble/curves/bls12-381.js'
import { keccak_256 } from '@noble/hashes/sha3.js'
import { AbiCoder, Interface } from 'ethers'
import { createVM, runTx } from '@ethereumjs/vm'
import { Common, Hardfork, Mainnet } from '@ethereumjs/common'
import { createFeeMarket1559Tx } from '@ethereumjs/tx'
import { createBlock } from '@ethereumjs/block'
import { Account, Address, bytesToHex, hexToBytes, privateToAddress } from '@ethereumjs/util'

const QUICK = process.argv.includes('--quick')
const OUT = process.argv.includes('--out') ? process.argv[process.argv.indexOf('--out') + 1] : 'results'
fs.mkdirSync(OUT, { recursive: true })

const G1 = bls12_381.G1.Point, G2 = bls12_381.G2.Point
const R = bls12_381.fields.Fr.ORDER
const DST = 'MLAV-IoP-V01-H1_BLS12381G1_XMD:SHA-256_SSWU_RO_'
const TX_GAS_CAP = 16_777_216n   // EIP-7825
const abi = AbiCoder.defaultAbiCoder()

// ------------------------------------------------------------------ encoding helpers
const hex = (b) => Buffer.from(b).toString('hex')
const fp = (x) => x.toString(16).padStart(128, '0')                        // 64-byte field element
const encG1 = (P) => { const a = P.toAffine(); return fp(a.x) + fp(a.y) }  // 128 bytes
const encG2 = (P) => { const a = P.toAffine(); return fp(a.x.c0) + fp(a.x.c1) + fp(a.y.c0) + fp(a.y.c1) }
const words4 = (h) => [0, 1, 2, 3].map(i => '0x' + h.slice(64 * i, 64 * i + 64))
const randScalar = () => (BigInt('0x' + crypto.randomBytes(64).toString('hex')) % (R - 1n)) + 1n
const kec = (hexStr) => '0x' + hex(keccak_256(hexToBytes(hexStr)))
const modR = (h) => BigInt(h) % R

// ------------------------------------------------------------------ scheme (off-chain side)
function setupKGC() {
  const s = randScalar()
  return { s, Ppub1: G1.BASE.multiply(s), Ppub2: G2.BASE.multiply(s) }
}

function extract(kgc, idx) {
  const t = randScalar()
  const sid1 = G1.BASE.multiply(t)
  const mask = keccak_256(hexToBytes('0x' + encG1(sid1.multiply(kgc.s))))
  const rid = Buffer.alloc(32); rid.write(`farmer-${idx}`)
  const sid2 = Buffer.from(rid.map((b, i) => b ^ mask[i]))
  const q = bls12_381.G1.hashToCurve(Buffer.concat([Buffer.from(sid1.toBytes(true)), sid2]), { DST })
  const qh = encG1(q)
  return { idx, qPt: q, qh, commit: kec('0x' + qh), sk: q.multiply(kgc.s) }
}

function sign(dev, i) {
  const ct = '0x' + crypto.randomBytes(32).toString('hex')
  const ts = BigInt(1_700_000_000 + i)
  const chk = '0x' + crypto.randomBytes(32).toString('hex')
  const seed = '0x' + crypto.randomBytes(20).toString('hex')
  const r = randScalar()
  const U = dev.qPt.multiply(r)
  const uh = encG1(U)
  const h = modR(kec(abi.encode(['bytes32', 'bytes32', 'uint64', 'bytes32', 'bytes20', 'bytes32[4]'],
    [dev.commit, ct, ts, chk, seed, words4(uh)])))
  const V = dev.sk.multiply((r + h) % R)
  return { ct, ts, chk, seed, uh, vPt: V, vh: encG1(V) }
}

// ------------------------------------------------------------------ compile & deploy
function compile(kgc) {
  const src = fs.readFileSync('MLAVVerifier.sol.tpl', 'utf8')
    .replace('{{P2}}', encG2(G2.BASE))
    .replace('{{NPPUB2}}', encG2(kgc.Ppub2.negate()))
  const input = { language: 'Solidity', sources: { 'MLAVVerifier.sol': { content: src } },
    settings: { optimizer: { enabled: true, runs: 200 }, viaIR: true, evmVersion: 'cancun',
      outputSelection: { '*': { '*': ['abi', 'evm.bytecode.object'] } } } }
  const out = JSON.parse(solc.compile(JSON.stringify(input)))
  const errs = (out.errors || []).filter(e => e.severity === 'error')
  if (errs.length) { console.error(errs.map(e => e.formattedMessage).join('\n')); process.exit(1) }
  const c = out.contracts['MLAVVerifier.sol'].MLAVVerifier
  return { abi: c.abi, bytecode: c.evm.bytecode.object, source: src }
}

const common = new Common({ chain: Mainnet, hardfork: Hardfork.Osaka })
const vm = await createVM({ common })
const pk = hexToBytes('0x' + '11'.repeat(32))
const sender = new Address(privateToAddress(pk))
await vm.stateManager.putAccount(sender, new Account(0n, 10n ** 30n))
let nonce = 0n
// non-zero block number so that anchoring writes are real zero->non-zero SSTOREs
const block = createBlock({ header: { number: 23_000_000n, gasLimit: 60_000_000n, baseFeePerGas: 1n, timestamp: 1_780_000_000n } }, { common })

async function send(to, data, gasLimit = TX_GAS_CAP) {
  const tx = createFeeMarket1559Tx({ nonce: nonce, to, data, gasLimit, maxFeePerGas: 10n ** 10n,
    maxPriorityFeePerGas: 1n, value: 0n }, { common }).sign(pk)
  const r = await runTx(vm, { tx, block, skipBlockGasLimitValidation: true, skipHardForkValidation: true })
  nonce++
  return { gas: r.totalGasSpent, ok: r.execResult.exceptionError === undefined,
           err: r.execResult.exceptionError?.error, addr: r.createdAddress, calldataBytes: data.length }
}

// ------------------------------------------------------------------ experiment
const kgc = setupKGC()
const C = compile(kgc)
fs.writeFileSync(`${OUT}/MLAVVerifier.sol`, C.source)
const iface = new Interface(C.abi)
const dep = await send(undefined, hexToBytes('0x' + C.bytecode))
if (!dep.ok) throw new Error('deploy failed ' + dep.err)
const target = dep.addr
console.log('deployed, gas', dep.gas)

const MAXDEV = 200
const devices = []
const regGas = []
for (let j = 0; j < MAXDEV; j++) {
  const d = extract(kgc, j); devices.push(d)
  const r = await send(target, hexToBytes(iface.encodeFunctionData('registerDevice', [j, words4(d.qh)])))
  if (!r.ok) throw new Error('register failed'); regGas.push(Number(r.gas))
}
console.log('device registration gas', regGas[1])

const devTuple = (d) => [d.idx, words4(d.qh)]
function makeBatch(n, m) {
  const ds = devices.slice(0, m)
  const msgs = []
  for (let i = 0; i < n; i++) { const pos = i % m; msgs.push({ pos, ...sign(ds[pos], i) }) }
  return { ds, msgs }
}
const msgTuple = (x) => [x.pos, x.ct, x.ts, x.chk, x.seed, words4(x.uh), words4(x.vh)]

async function batchTx(b, mode) {
  const data = iface.encodeFunctionData('submitBatch', [b.ds.map(devTuple), b.msgs.map(msgTuple), mode])
  return send(target, hexToBytes(data))
}
async function individualTxs(b) {
  let total = 0n, cd = 0
  for (const x of b.msgs) {
    const data = iface.encodeFunctionData('submitIndividual', [devTuple(b.ds[x.pos]), msgTuple(x)])
    const r = await send(target, hexToBytes(data))
    if (!r.ok) throw new Error('individual failed ' + r.err)
    total += r.gas; cd += r.calldataBytes
  }
  return { gas: total, ok: true, calldataBytes: cd }
}

const results = { environment: {
  evm: '@ethereumjs/vm ' + JSON.parse(fs.readFileSync('node_modules/@ethereumjs/vm/package.json')).version,
  hardfork: 'osaka', solc: solc.version(), optimizer_runs: 200, via_ir: true, tx_gas_cap: Number(TX_GAS_CAP) },
  deploy_gas: Number(dep.gas), register_device_gas: regGas[1], tests: {}, scaling: [], device_sweep: [], anchoring: [] }

// ---- correctness / attack tests on-chain
{
  const b = makeBatch(20, 5)
  results.tests.valid = {}
  for (const [mode, name] of [[0, 'naive'], [1, 'set'], [2, 'grouped']])
    results.tests.valid[name] = (await batchTx(b, mode)).ok
  const bad = makeBatch(20, 5)
  bad.msgs[7].vh = encG1(bad.msgs[7].vPt.add(G1.BASE))
  results.tests.single_invalid_rejected = {}
  for (const [mode, name] of [[0, 'naive'], [1, 'set'], [2, 'grouped']])
    results.tests.single_invalid_rejected[name] = !(await batchTx(bad, mode)).ok
  const atk = makeBatch(20, 5)
  const X = G1.BASE.multiply(randScalar())
  atk.msgs[3].vh = encG1(atk.msgs[3].vPt.add(X))
  atk.msgs[11].vh = encG1(atk.msgs[11].vPt.subtract(X))
  const one = { ds: atk.ds, msgs: [atk.msgs[3]] }
  results.tests.cancellation_attack = {
    msg3_individual_accepted: (await batchTx(one, 1)).ok,
    naive_batch_ACCEPTS: (await batchTx(atk, 0)).ok,
    set_batch_accepts: (await batchTx(atk, 1)).ok,
    grouped_batch_accepts: (await batchTx(atk, 2)).ok }
  const ind = makeBatch(1, 1)
  results.tests.individual_valid = (await individualTxs(ind)).ok
  console.log(JSON.stringify(results.tests, null, 1))
}

// ---- scaling, m = 10 devices
const SIZES = QUICK ? [1, 10, 50] : [1, 10, 50, 100, 200, 300, 400, 500, 600]
const M = 10
for (const n of SIZES) {
  const b = makeBatch(n, Math.min(n, M))
  const rows = []
  if (n <= 200) rows.push(['V individual (n txs)', await individualTxs(b)])
  for (const [mode, name] of [[0, 'B1 naive batch (insecure)'], [1, 'B2 small-exponent batch'], [2, 'B3 grouped small-exponent batch']]) {
    const r = await batchTx(makeBatch(n, Math.min(n, M)), mode)   // fresh batch: no warm/duplicate root slot
    rows.push([name, r.ok ? r : { ...r, gas: null }])
  }
  for (const [name, r] of rows) {
    const g = r.gas === null ? null : Number(r.gas)
    results.scaling.push({ n, devices: Math.min(n, M), method: name, total_gas: g,
      per_msg_gas: g === null ? null : Math.round(g / n), calldata_bytes: r.calldataBytes, ok: r.ok })
    console.log(`n=${String(n).padStart(4)} ${name.padEnd(34)} ${g === null ? 'FAILED (gas cap)' : g.toLocaleString().padStart(12) + '  ' + Math.round(g / n).toLocaleString() + '/msg'}`)
  }
}

// ---- largest batch that fits under the EIP-7825 per-transaction cap (binary search, m = 10)
results.max_batch = {}
if (!QUICK) {
  for (const [mode, name] of [[0, 'B1 naive batch (insecure)'], [1, 'B2 small-exponent batch'], [2, 'B3 grouped small-exponent batch']]) {
    let lo = 100, hi = 1200
    while (hi - lo > 5) {
      const mid = Math.floor((lo + hi) / 2)
      const r = await batchTx(makeBatch(mid, M), mode)
      if (r.ok) lo = mid; else hi = mid
    }
    results.max_batch[name] = lo
    console.log(`max n under cap  ${name.padEnd(34)} ~${lo}`)
  }
}

// ---- device sweep, n fixed
const NS = QUICK ? 50 : 200
for (const m of [1, 5, 10, 50, 200].filter(x => x <= NS)) {
  for (const [mode, name] of [[1, 'B2 small-exponent batch'], [2, 'B3 grouped small-exponent batch']]) {
    const r = await batchTx(makeBatch(NS, m), mode)
    results.device_sweep.push({ n: NS, devices: m, method: name, total_gas: Number(r.gas), per_msg_gas: Math.round(Number(r.gas) / NS), ok: r.ok })
    console.log(`sweep n=${NS} m=${String(m).padStart(3)} ${name.padEnd(34)} ${Number(r.gas).toLocaleString()}`)
  }
}

// ---- anchoring only: one slot per record vs Merkle root
for (const n of QUICK ? [10, 100] : [10, 100, 500]) {
  const h = Array.from({ length: n }, () => '0x' + crypto.randomBytes(32).toString('hex'))
  const each = await send(target, hexToBytes(iface.encodeFunctionData('anchorEach', [h])))
  const root = await send(target, hexToBytes(iface.encodeFunctionData('anchorRoot', [h])))
  results.anchoring.push({ n, each_slot_gas: Number(each.gas), merkle_root_gas: Number(root.gas) })
  console.log(`anchor n=${n} each=${Number(each.gas).toLocaleString()} root=${Number(root.gas).toLocaleString()}`)
}

fs.writeFileSync(`${OUT}/gas_results.json`, JSON.stringify(results, null, 2))
const csv = (rows) => [Object.keys(rows[0]).join(','), ...rows.map(r => Object.values(r).join(','))].join('\n')
fs.writeFileSync(`${OUT}/gas_scaling.csv`, csv(results.scaling))
fs.writeFileSync(`${OUT}/gas_device_sweep.csv`, csv(results.device_sweep))
fs.writeFileSync(`${OUT}/gas_anchoring.csv`, csv(results.anchoring))
console.log('written to', OUT)
