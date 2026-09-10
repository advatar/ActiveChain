# Kanalen demo merchant

Work in progress: [issue #844](https://github.com/advatar/ActiveChain/issues/844),
[draft PR #845](https://github.com/advatar/ActiveChain/pull/845).

## Merchant account

- Name: Kanalen Coffee
- Product: Demo coffee (no physical goods)
- Price: 5 ACT; network fee: 0.001 ACT, displayed before approval
- Network: Kanalen testnet, protocol 1 / RPC schema 5
- Chain: `b12c1c316717e9669cec36f7632a9080702c57a3125d90c72154f8a7298e4f0b095e6cfe944bd2c9f6535b4c927782f1`
- Genesis: `a836c4d201cda6ba33a01aa48011cf5f4d6acdfd1ec409d322dc1b56ed3552a25dcb158e0b1ec0352728653d315d477c`
- Merchant principal: `23cfa78e90c6566bc708752e2079a0c5f6ec030eff3b9e83a36ccee673aca3b7412de87592b6c34579803d1bd4480bae`

A fresh ML-DSA-44 receiver key was generated with `activechain-wallet derive` on
2026-09-09. Its private directory is
`~/Library/Application Support/ActiveChain/DemoMerchant/kanalen-844` on the development Mac
(directory mode 0700, key mode 0600). No seed or private key is stored in this repository or
embedded in the customer app. The merchant key has not been enrolled on chain. The public
principal received a verified 5 ACT demo purchase at block 20926 on 2026-09-10.
The retained customer wallet shows 94.999 ACT after its 0.001 ACT fee and relaunch.

## Spending prerequisite

Before this change, the schema 4 iOS app provisioned local custody and received faucet coins
without enrolling its cash signing key in finalized chain state. `TransactionIngress::register_session` rejects
unknown authorization keys before transfer admission. The finalized identity-key installation
API exists, but its production integration is absent; its callers in the wallet, RPC and
consensus suites use test-only finality verifiers.

[P-100](../spec/protocol/P-100-testnet-wallet-operator.md) requires the node to resolve the
sender's signing key from finalized chain state. Checkout must preserve this boundary. A key
supplied alongside a payment, a synthetic accepted proof, or a manually patched cash snapshot
is not a replacement for finalized enrollment.

The user selected wallet-key enrollment on 2026-09-10. Composite identity credentials are
optional for spending. Enrollment must be signed by the key whose native principal owns the
funded cells, bound to this chain and an expiry, and finalized in consensus before a later
payment. It cannot overwrite a registered key or reset its nonce. The wallet must verify
certificate-backed enrollment evidence before presenting the key as enrolled.

## Acceptance

The completed demo must review the canonical merchant, price, fee, chain and expiry; sign with
the customer's existing native custody; persist exact signed bytes before submission; resolve
ambiguous submission and relaunch without a second purchase; and display paid only after native
proofs establish the exact merchant output and customer change. Live acceptance must spend real
faucet-funded testnet coins. An accepted RPC submission alone is not payment success.

Initial verification: pinned TLS RPC healthy at height 19,612 with zero seconds of staleness;
all 13 wallet CLI tests passed. These checks qualify merchant account preparation only, not an
end-to-end checkout. Full candidate qualification and integration remain outstanding.

The candidate implements a native Shop tab, explicit first-enrollment action, canonical
payment review, durable signed-action retry and certificate-backed merchant/change proofs.
RPC schema 5 was deployed on 2026-09-10 at revision `b5dac305`, preserving the chain and
wallet state. The existing user wallet received a finalized 100 ACT faucet grant at block
20890. A live check exposed and corrected a Swift record-decoding mismatch; the wallet now
displays the actual total and both 50 ACT cells. The first fresh-wallet flow exposed two server finalization/retry bugs and a client receipt
mapping mismatch. Release `c14db3d4` restored finalization and enrolled that wallet at block
20916. The corrected client verified its purchase at block 20926 without resubmission.
A clean automated acceptance rerun and final qualification remain.

## Candidate app flow

Create or open a Kanalen wallet and request faucet funding.
Open **Shop**, choose **Register wallet key**, and approve with the existing wallet custody.
Registration proves ownership of the funded address; no identity credential is required.
Wait for verified enrollment and a later healthy block, then choose **Buy demo coffee**.
Review Kanalen Coffee's address, 5 ACT price, 0.001 ACT fee and expiry before confirming.
The receipt appears only after native verification of finality, the merchant output and change.
A pending action is saved before submission and retried with exactly the same signed bytes
across relaunch. A second purchase cannot replace an unresolved one.

Local qualification covers the production Swift/Rust signing transcripts and a Rust scenario
that rejects spending before enrollment and in its block, then pays the merchant in a later
block, persists finality evidence and rejects replay. This does not replace the outstanding
clean automated live iOS purchase rerun. Deployment access is restored and the public
schema 5 RPC is healthy. Development checks now target changed boundaries and build only
the required iOS wallet library/simulator slice; full qualification waits for the settled flow.
