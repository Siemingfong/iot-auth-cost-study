// Live-network backend for baselines_bench.mjs and gasbench.mjs (--live): the harness builds exactly the same
// transactions; only send/call/deploy go to a JSON-RPC endpoint instead of the EthereumJS VM, and gas is read from
// the receipts. Every transaction is first simulated with eth_call: one that would revert (the negative tests) or
// exceed the EIP-7825 cap is reported as rejected without being sent, so it costs nothing.
// Environment: HOODI_RPC_URL, HOODI_PRIVATE_KEY (a new wallet used only for this), optional EXPECT_CHAIN_ID
// (default 560048, Hoodi), DRY_RUN=1 (checks only).
import fs from 'node:fs'
import { JsonRpcProvider, Wallet, formatEther } from 'ethers'

const CAP = 16_777_216n
const hex = (u8) => '0x' + Buffer.from(u8).toString('hex')

export async function makeLive({ out, plannedGas }) {
  const RPC = process.env.HOODI_RPC_URL, KEY = process.env.HOODI_PRIVATE_KEY
  if (!RPC || !KEY) { console.error('Set HOODI_RPC_URL and HOODI_PRIVATE_KEY'); process.exit(1) }
  const provider = new JsonRpcProvider(RPC, undefined, { polling: true, pollingInterval: 3000 })
  const wallet = new Wallet(KEY, provider)
  const chainId = (await provider.getNetwork()).chainId
  const expect = BigInt(process.env.EXPECT_CHAIN_ID || '560048')
  if (chainId === 1n) { console.error('Refusing to run on Ethereum mainnet.'); process.exit(1) }
  if (chainId !== expect) { console.error(`Chain ID ${chainId} is not the expected ${expect}.`); process.exit(1) }
  // the measurements must run under the Osaka rules: a plain transfer costs exactly 21,000 gas there (EIP-2780 of
  // Glamsterdam lowers it), and Glamsterdam blocks carry a block-access-list commitment in the header
  const transferGas = await provider.estimateGas({ from: wallet.address, to: wallet.address, value: 0n })
  const rawHead = await provider.send('eth_getBlockByNumber', ['latest', false])
  const balKeys = Object.keys(rawHead).filter(k => /accesslist/i.test(k))
  let client = ''; try { client = await provider.send('web3_clientVersion', []) } catch {}
  const env = { chainId: chainId.toString(), block: parseInt(rawHead.number, 16), gasLimit: parseInt(rawHead.gasLimit, 16),
    baseFee: parseInt(rawHead.baseFeePerGas, 16), client, transferGas: Number(transferGas), headerKeys: Object.keys(rawHead) }
  console.log(`chain ${chainId}, block ${env.block}, gas limit ${env.gasLimit}, base fee ${env.baseFee} wei, client ${client}`)
  if (transferGas !== 21000n || balKeys.length) {
    console.error(`This network no longer runs the Osaka rules (transfer ${transferGas} gas, header fields ${balKeys.join(',') || 'none'}); stopping.`)
    process.exit(1)
  }
  const fee = await provider.getFeeData(), bal = await provider.getBalance(wallet.address)
  const price = fee.maxFeePerGas ?? fee.gasPrice
  const need = BigInt(plannedGas) * price
  console.log(`wallet ${wallet.address}, balance ${formatEther(bal)} ETH; planned ~${Math.round(plannedGas / 1e6)}M gas, ~${formatEther(need)} ETH at ${price} wei/gas`)
  if (bal < need) { console.error(`Balance too low: need about ${formatEther(need)} ETH. Fund the wallet from a Hoodi faucet.`); process.exit(1) }
  if (process.env.DRY_RUN) { console.log('DRY_RUN: stopping before any transaction.'); process.exit(0) }

  const txs = []
  // nonces are tracked here rather than fetched for every transaction, which can return a stale value
  let nonce = await provider.getTransactionCount(wallet.address, 'pending')
  fs.mkdirSync(out, { recursive: true })
  const save = () => fs.writeFileSync(`${out}/live_transactions.json`, JSON.stringify({ environment: env, transactions: txs }, null, 2))
  async function send(to, data, _gasLimit, label = '') {
    const req = { from: wallet.address, to: to ? to.toString() : null, data: hex(data) }
    const rpcReq = to ? { from: req.from, to: req.to, data: req.data } : { from: req.from, data: req.data }
    let est
    // simulate and estimate against the latest mined block explicitly: without a block tag, a node may use a pending
    // state that does not yet include the previous transaction, so a replay would be simulated as valid
    try {
      await provider.send('eth_call', [rpcReq, 'latest'])
      est = BigInt(await provider.send('eth_estimateGas', [rpcReq, 'latest']))
    } catch (e) {
      txs.push({ label, to: req.to, sent: false, reason: 'reverts (eth_call)', calldata: data.length }); save()
      return { gas: 0, ok: false, err: 'reverts (eth_call)', addr: undefined, calldataBytes: data.length }
    }
    if (est > CAP) {
      txs.push({ label, to: req.to, sent: false, reason: `above the cap (estimate ${est})`, calldata: data.length }); save()
      return { gas: 0, ok: false, err: 'above cap', addr: undefined, calldataBytes: data.length }
    }
    const gasLimit = est * 12n / 10n > CAP ? CAP : est * 12n / 10n
    const tx = await wallet.sendTransaction({ to: req.to, data: req.data, gasLimit, nonce })
    nonce++
    let rc
    try { rc = await tx.wait() } catch (e) {
      // reverted on-chain although the simulation passed: record it and report a rejection instead of aborting
      rc = e.receipt ?? await provider.getTransactionReceipt(tx.hash)
    }
    txs.push({ label, hash: tx.hash, block: rc.blockNumber, to: req.to, gasUsed: Number(rc.gasUsed), status: rc.status, calldata: data.length }); save()
    return { gas: Number(rc.gasUsed), ok: rc.status === 1, err: rc.status === 1 ? undefined : 'reverted', addr: rc.contractAddress ?? undefined, calldataBytes: data.length }
  }
  async function call(to, data) {
    const r = await provider.call({ to: to.toString(), data: hex(data) })
    return { returnValue: Uint8Array.from(Buffer.from(r.slice(2), 'hex')), executionGasUsed: null }
  }
  return { send, call, chainId, env }
}
