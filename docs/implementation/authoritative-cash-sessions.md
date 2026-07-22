# Authoritative bounded cash sessions

Cash transfers cannot define their own spend allowance. A validator first admits a canonical
`AuthorizedCashSessionGrantV1` envelope signed by the sender's finalized ML-DSA-44 cash key. The
grant binds the chain, signer, session identifier, validity interval, and maximum amount including
fees.

Each authorization lane stores grants in strict session-ID order. Transfer admission requires the
referenced grant to exist, be active at the execution height, cover the request expiry, and retain
enough budget for `amount + fee`. The ingress constructs the complete next ledger, nonce, replay
sets, and session spend on a clone. It exposes that state only after every check succeeds.

Validator networking accepts grants and transfers only through their canonical typed envelopes.
Durable registration and transfer methods write the complete version-2 ingress snapshot using a
temporary file, `fsync`, and atomic rename before publishing it in memory. Restart therefore
restores the exact grant and consumed spend; malformed snapshots, wrong-chain snapshots, failed
publishes, unknown sessions, wrong keys, expired grants, and over-budget spends fail closed.

The remaining proof task is deliberately separate: CashAIR must bind these exact pre/post budget
values and arithmetize non-wrapping bounded subtraction. Until that constraint table lands, the
direct runtime check remains authoritative and the specialized CashAIR roadmap gate remains open.
