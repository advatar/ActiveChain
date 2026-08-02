# P-040: Public action envelopes, fee tickets, and nonce channels

- Status: Draft 0.2
- Protocol version: Development
- Issues: <https://github.com/advatar/ActiveChain/issues/7>, <https://github.com/advatar/ActiveChain/issues/337>

## 1. Scope

This revision defines the public development envelope admitted by the single-node semantic devnet.
It binds a versioned transfer, fungible issuer, or corporate-action payload to one chain, public
sender, validity interval, exact nonce channel, one-shot fee ticket, multidimensional resource
ceiling, and authorization-evidence commitment.

Protected payloads, cryptographic signature verification, fee markets, networking, and consensus are later refinements. The public envelope is not a substitute for P-041 privacy or production authentication.

## 2. Resource vectors

Version 1 keeps six independent unsigned `u64` dimensions:

```text
ResourceVector {
    policy_steps
    object_reads
    object_writes
    vm_gas
    events
    encoded_bytes
}
```

Vectors compare componentwise. An actual or declared vector fits a ceiling only when every component is less than or equal to the corresponding ceiling. No implementation may silently exchange unused capacity in one dimension for another.

`ResourcePricesV1` contains one `u64` price per corresponding unit. A charge is the checked `u128` sum of all six `usage * price` products. Overflow is an admission or block error, never wrapping arithmetic.

## 3. Fee tickets

A fee ticket contains a unique object identifier, payer, reserved amount, expiry height, issuance nonce, and permitted resource vector. Its canonical identifier is consumed once when an envelope is admitted, including when the underlying semantic transfer later returns a failure receipt.

The envelope maximum resource vector MUST fit within the ticket permission. At block admission, the maximum resource charge under the chain's deterministic price vector plus the one-unit non-refundable ticket-admission charge MUST not exceed the reserved amount. Tickets with zero reservation are invalid. A ticket whose expiry precedes the block height is invalid.

The development chain state contains at most 64 fee accounts, ordered by payer. Each account retains a `u128` spendable balance and an exact `u64 next_nonce`. The ticket payer MUST equal the public action sender until an authenticated sponsorship profile is specified. Admission requires the ticket nonce to equal the account nonce and the account balance to cover the complete reservation. The actual resource charge plus the admission charge is debited and the account nonce advances atomically with action admission, including semantic or resource-limit failure. Missing accounts, insufficient balances, replayed nonces, gaps, and nonce exhaustion fail closed. `DevnetBlock` schema 2 binds the canonical commitment of the complete input `ChainState` into the block identifier; `BlockReceipt` schema 2 binds both that input commitment and the complete successor-state commitment into the receipt root.

## 4. Validity and replay protection

`ValidityIntervalV1` is an inclusive `[valid_from, valid_until]` block-height interval with `valid_from <= valid_until`. Both the enclosing block height and the transfer transaction's declared height MUST be inside the interval, and the transaction height MUST equal the block height.

A nonce channel is keyed by `(sender, u16 channel)` and stores one `u64 next_sequence`. Admission requires exact equality:

```text
supplied < next  -> Replay
supplied > next  -> SequenceGap
supplied = next  -> next + 1
next = u64::MAX  -> SequenceExhausted
```

The channel advances and the fee ticket is consumed for every admitted action, even if deterministic transfer semantics fail. Rejected block structure or admission leaves the input chain state unchanged because block application is pure.

The ticket expiry MUST equal the envelope `valid_until`, and the inclusive interval may span at most seven height increments (`valid_until - valid_from <= 7`). A consumed identifier is retained through its expiry height and pruned only before applying a later height. Since a block contains at most 32 actions, no conforming state can retain more than `32 * (7 + 1) = 256` identifiers. After identifier pruning, the durable payer nonce continues to reject replay.

`ChainState` schema 4 stores fee accounts, each consumed identifier's expiry, the authoritative
multi-asset ledger, and its exact-once corporate-action registry. Schema 3 migrates by preserving
the complete asset policy and Coin Cell ledger and initializing an empty corporate-action registry.
The standalone `ConsensusAssetLedgerV1` envelope advances to schema 2 with the same lossless
schema-1 migration rule. `ActionPayloadV2` advances to schema 2 for the corporate-action variant.
Bounded schema-1 migration is allowed only for an empty legacy replay set and requires the operator
to supply canonical fee accounts. A non-empty schema-1 replay set lacks expiry and payer-nonce
evidence and MUST fail closed.

## 5. Public action envelope

`ActionEnvelopeV1` contains, in canonical field order:

```text
protocol_version = 1
chain_id
sender
fee_ticket
nonce_channel
sequence
validity
maximum_resources
payload_commitment
ActionPayloadV2 payload
authorization_commitment
```

`payload_commitment` is the P-002 canonical-value commitment to the exact typed payload. Every
transfer command's policy request actor MUST be `Principal(sender)`; issuer payloads bind the
sender to their declared issuer or authority. A corporate action additionally requires
`authorization_commitment` to equal its declared threshold-approval commitment, and execution
admits its identifier exactly once against the current policy commitment, authority set, and
half-open finalized-height window. Private actors require a later protected-envelope profile. The
fee payer MUST equal the sender in this development profile.

The authorization commitment binds evidence checked by an external development adapter. This draft does not claim to verify a signature and MUST NOT be used as production authentication.

## 6. Action identifiers and ordering

The transaction identifier is the P-002 commitment to the complete canonical action envelope under domain `ACTION_ID = 0x0005`, wrapped as `TransactionId`. It therefore binds fees, nonce, validity, payload, sender, chain, and evidence.

A development block orders envelopes by strictly increasing transaction identifier. Duplicate or decreasing identifiers invalidate the block before publication. This is a deterministic development order, not the protected ordering protocol of P-041.

## 7. Canonical types and bounds

```text
FeeTicketV1      type 0x0070, schema 1, max body       176 bytes
ActionEnvelopeV1 type 0x0071, schema 1, max body 1,265,778 bytes
NonceChannelV1   type 0x0072, schema 1, max body        58 bytes
ChainState        type 0x007b, schema 4, bounded fee accounts, expiring replay records,
                  native asset ledger, and exact-once corporate-action registry
DevnetBlock       type 0x0073, schema 2, full pre-chain-state commitment
BlockReceipt      type 0x0074, schema 2, full pre/post-chain-state commitments
```

Resource vectors and prices are fixed 48-byte nested values. A validity interval is fixed at 16 bytes. The envelope maximum follows from the exact P-030 transfer-transaction bound.

## 8. Required properties

```text
same envelope                         -> same action identifier
payload field change                  -> different payload/action commitment
wrong chain, height, actor, or payload commitment -> rejection
exact next sequence                   -> advances once
repeated sequence                     -> replay rejection
future sequence                       -> gap rejection
reused ticket identifier              -> rejection
missing/unfunded payer or bad fee nonce -> rejection
ticket validity longer than seven heights -> rejection
expired replay entry                  -> prune only after expiry
actual resource dimension over limit  -> semantic resource-limit receipt
fee/resource arithmetic overflow      -> typed rejection
```

The Lean executable model fixes exact nonce advancement and replay/gap precedence. Rust produces the same frozen boundary table.

## 9. Compatibility

Changing resource dimensions, field order, action-ID domain, sequence semantics, ticket-consumption timing, actor binding, or interval inclusivity requires a protocol/schema version change.
