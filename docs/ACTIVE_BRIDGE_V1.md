# ActiveBridge application boundary v1

ActiveBridge is an application protocol over native asset actions. It does not introduce a second
consensus ledger or trust a bridge operator's database.

## Settlement objects

- A payment intent binds source principal, destination principal, AssetId, amount, nonce, expiry,
  fee policy, and recipient network.
- A swap intent binds both legs, asset/amount pairs, hashlock or threshold authorization, expiry,
  and a one-shot settlement nonce.
- A merchant receipt binds the finalized transaction/action ID, exact asset and amount, recipient,
  policy revision, and finality evidence commitment.

## Cross-network state

External-chain observations are `pending` until a configured proof verifier and finality policy
accept them. `invalid`, `expired`, and `reorged` observations cannot settle a leg. A timeout may
refund only when the original intent's expiry and refund authority are satisfied; it cannot mint
or duplicate value.

Raw invoices, customer data, and payment metadata remain off-chain. On-chain commitments are
minimal and independently verifiable against trusted network parameters.

Operators may choose supported routes and fees, but cannot override AssetId, amount, nonce,
finality, or authorization bindings.
