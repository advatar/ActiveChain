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
Durable key installation, session registration, transfer, and economics methods write the complete
version-3 ingress snapshot using a
temporary file, `fsync`, and atomic rename before publishing it in memory. Restart therefore
restores the exact grant and consumed spend; malformed snapshots, wrong-chain snapshots, failed
publishes, unknown sessions, wrong keys, expired grants, and over-budget spends fail closed.
The RPC faucet adapter reloads the monotonic finalized index immediately before admission and
persists this snapshot before returning a transaction identifier. If rename may have completed but
directory durability cannot be confirmed, the in-process ingress is poisoned until restart; it
cannot continue from an ambiguous pre-state.

Replay storage is bounded without weakening rejection. Once finality is beyond a session expiry,
the session budget and consumed-session entry may be removed because its signed requests are both
expired and below the lane's monotonic next nonce. Spent-input markers may be removed because spent
Coin Cells are absent from the committed UTXO set. Crash-point tests cover temporary creation,
write, file sync, rename, and directory sync and require recovery to expose exactly the complete old
or complete new snapshot.

CashAIR derives its canonical admission witness by reexecuting this exact authoritative ingress on
a clone. Its dedicated 128-row bit trace proves `amount + fee = spend`, `pre + spend = post`, and
`post + remaining = signed maximum`. Boolean bit constraints and zero terminal carries rule out
field-modulus aliases, integer overflow, and over-budget subtraction. Six exact 64-bit limbs of a
domain-separated SHAKE commitment bind the remaining canonical witness context (chain, signer,
session, height, and grant window) into the proof transcript. Direct runtime reexecution remains the
authoritative comparison boundary while the other specialized CashAIR tables remain open.
