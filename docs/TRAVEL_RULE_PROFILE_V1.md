# Off-chain Travel Rule profile v1

Travel Rule payloads are exchanged between regulated counterparties off-chain. ActiveChain stores
only commitments and admission outcomes, never names, addresses, or institution payloads.

The signed binding covers chain ID, genesis commitment, transaction/action ID, AssetId, exact
amount, originator and beneficiary commitments, screening decision commitment, policy revision,
nonce, expiry, and counterparty acknowledgement. Any substitution invalidates the binding.

Counterparties retain the payload under their jurisdictional retention policy and return an
acknowledgement commitment. `pending` means no transfer authorization; `accepted` permits the
application action; `rejected`, `expired`, and `mismatch` are terminal and cannot be retried with
the same nonce. Requests are replay-safe and versioned so jurisdiction-specific fields can be
added without changing consensus bytes.

Disclosure is limited to the counterparty and authorized evidence workflow. Breach, deletion,
access, and FIU-reporting procedures remain provider-operated and are represented by bounded
commitments and audit references.
