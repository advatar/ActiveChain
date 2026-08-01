# Native issuer operations v1

Native assets use a finalized issuer lifecycle; no smart-contract wrapper is required to make a
EUR, USD, bond, fund share, or commodity claim legible to wallets and validators.

## Lifecycle and authority

1. **Register:** an issuer publishes the asset definition, decimals, supply cap, redemption and
   reserve-policy commitments, jurisdiction profiles, and a threshold-controlled authority set.
2. **Issue:** minting consumes an issuer-approved issuance intent and creates Coin Cells for the
   declared asset. The transition proves `post_supply = pre_supply + mint - burn`.
3. **Transfer:** ordinary transfers preserve `AssetId`, policy commitments, and required private
   evidence. A wallet cannot substitute a symbol or decimals value.
4. **Redeem:** a burn intent consumes the holder's cells and produces a receipt bound to the exact
   amount, issuer, redemption policy, and finalized transaction.
5. **Pause/recover:** a bounded emergency capability can pause new issuance or redemption, but
   cannot rewrite prior receipts or seize arbitrary holders. Recovery requires the declared
   threshold and an expiry/reason code.
6. **Retire:** an asset may retire only when supply is zero or the declared wind-down procedure is
   satisfied; the registry retains the immutable history.

Issuer, reserve, compliance, and emergency roles are separate attenuated capabilities. Reserve
attestations and KYC material remain off-chain; only their signed commitments and verifier versions
are public. A regulated profile can constrain operations without changing the asset identifier or
granting universal chain-wide freeze authority.

Before submitting a corporate action, operators use `dry-run-corporate-action` with the exact
canonical policy, current exact-once registry, action envelope, and finalized height. Successful
preflight returns the action identity and canonical post-registry. The issuer console reconstructs
its review from that same accepted transition; stale, replayed, cross-policy, and cross-authority
actions fail before a wallet approval can be requested.

Application execution uses `DurableCorporateActionRegistry`: it applies the same policy and
authority checks to a cloned registry, fsyncs and atomically replaces the canonical snapshot, and
only then advances live memory. Restart restores the exact action identities; replay, corrupt
storage, and write failure fail closed.

## Declared holder controls

Holder freeze and clawback are absent unless a canonical
`FungibleExceptionalControlPolicyV1` declares them and its commitment is the immutable asset
definition `policy_hash`. Each action binds the asset, holder, destination, declared policy,
authority set, approval and reason commitments, exact amount, expected holder-control revision,
and half-open execution window. Freeze blocks the ordinary transfer path. Clawback operates on one
exact Coin Cell and may change only its owner; origin, asset identity, amount, and creation height
are conserved. Freeze/unfreeze revisions are stored in a bounded registry canonically ordered
by exact asset and holder, and the successor registry is synchronized and atomically replaced
before acknowledgement. Replay, cross-binding, corrupt restart state, capacity, and failed writes
fail closed. This state-only boundary rejects clawback. `DurableClawbackState` instead validates
and persists the exact Coin Cell and matching holder-control revision as one combined snapshot;
it preserves origin, asset, amount, and creation height while changing only ownership and revision.
The authoritative `DurableFungibleClawbackLedger` boundary additionally persists the complete
canonically ordered fungible Coin Cell set with that revision, preserves the target `CoinCellId`
and every unrelated record, and advances memory only after the synchronized atomic replacement
succeeds. These primitives establish protocol mechanics, not the legal authority to exercise them.

Ordinary fungible transfers execute directly against the authoritative `FungibleCoinCellSet`.
Admission requires the exact registered asset policy and matching unfrozen holder state. Each
declared input is resolved by the `CoinCellId` derived from its immutable origin and must equal the
authoritative record byte-for-byte. The pure transition consumes all exact inputs, preserves every
unrelated record, and creates one recipient output whose origin and ID derive from the canonical
transfer. Missing or substituted inputs, replay, wrong or inactive policy, frozen holders, output
collision, and malformed ordering fail without returning a successor set.
`DurableFungibleTransferLedger` applies that pure transition to a clone and synchronizes and
atomically replaces the complete successor set before memory or acknowledgement advances. Restart
therefore restores both the new root and replay rejection; corrupt storage and failed writes fail
closed without changing the live authoritative root.

The native issuer CLI exposes `control-policy`, `holder-control-state`, `control-action`, and
`dry-run-control`. Freeze and unfreeze preflight return the exact post-state. Clawback additionally
requires a canonical input Coin Cell and returns both the conserved post-cell and revisioned
post-state; omission or substitution of that cell is rejected.

The issuer-console holder-control review executes the same transition before rendering. Wallet
facts show the declared policy and authority, approval and reason commitments, holder and
destination, exact amount, revision and freeze state before/after, Coin Cell ownership movement,
and half-open window. The wallet action remains bound to the exact approval commitment.
