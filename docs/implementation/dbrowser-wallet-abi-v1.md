# dBrowser wallet ABI v1

The wallet ABI separates discovery, policy evaluation, user approval, signing, and submission.
Applications receive finalized owner/asset proofs and a canonical intent preview; they cannot ask
the wallet to sign opaque bytes or bypass the approval boundary.

Key callbacks run inside the wallet's secure storage boundary and return only a signature over the
canonical chain, asset, recipient, amount, fee, nonce, policy, and expiry-bound intent. The wallet
must reject unknown assets, stale proofs, wrong-chain intents, policy-denied actions, replayed
nonces, and callback requests that omit the approval token. Submission returns a proof-bearing
reference and never a local optimistic balance.
