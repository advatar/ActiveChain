# Kanalen demo merchant

Work in progress: [issue #844](https://github.com/advatar/ActiveChain/issues/844),
[draft PR #845](https://github.com/advatar/ActiveChain/pull/845).

## Merchant account

- Name: Kanalen Coffee
- Product: Demo coffee (no physical goods)
- Proposed price: 5 ACT; network fee displayed separately before approval
- Network: Kanalen testnet, protocol 1 / RPC schema 4
- Chain: `b12c1c316717e9669cec36f7632a9080702c57a3125d90c72154f8a7298e4f0b095e6cfe944bd2c9f6535b4c927782f1`
- Genesis: `a836c4d201cda6ba33a01aa48011cf5f4d6acdfd1ec409d322dc1b56ed3552a25dcb158e0b1ec0352728653d315d477c`
- Merchant principal: `23cfa78e90c6566bc708752e2079a0c5f6ec030eff3b9e83a36ccee673aca3b7412de87592b6c34579803d1bd4480bae`

A fresh ML-DSA-44 receiver key was generated with `activechain-wallet derive` on
2026-09-09. Its private directory is
`~/Library/Application Support/ActiveChain/DemoMerchant/kanalen-844` on the development Mac
(directory mode 0700, key mode 0600). No seed or private key is stored in this repository or
embedded in the customer app. The merchant key has not been enrolled on chain. The public
principal can receive coins, but no demo purchase has been submitted or verified yet.

## Spending prerequisite

The current iOS app provisions local custody and receives faucet coins. It does not enroll
its cash signing key in finalized chain state. `TransactionIngress::register_session` rejects
unknown authorization keys before transfer admission. The finalized identity-key installation
API exists, but its production integration is absent; its callers in the wallet, RPC and
consensus suites use test-only finality verifiers.

[P-100](../spec/protocol/P-100-testnet-wallet-operator.md) requires the node to resolve the
sender's signing key from finalized chain state. Checkout must preserve this boundary. A key
supplied alongside a payment, a synthetic accepted proof, or a manually patched cash snapshot
is not a replacement for finalized enrollment.

The outstanding product decision is whether wallet-key ownership is sufficient for demo
spending or whether enrollment also requires composite identity credentials. The first choice
still needs a real finalized registration path; it does not waive chain verification. The second
also needs trusted demo issuers and the missing credential enrollment flow.

## Acceptance

The completed demo must review the canonical merchant, price, fee, chain and expiry; sign with
the customer's existing native custody; persist exact signed bytes before submission; resolve
ambiguous submission and relaunch without a second purchase; and display paid only after native
proofs establish the exact merchant output and customer change. Live acceptance must spend real
faucet-funded testnet coins. An accepted RPC submission alone is not payment success.

Initial verification: pinned TLS RPC healthy at height 19,612 with zero seconds of staleness;
all 13 wallet CLI tests passed. These checks qualify merchant account preparation only, not an
end-to-end checkout. Full candidate qualification and integration remain outstanding.
