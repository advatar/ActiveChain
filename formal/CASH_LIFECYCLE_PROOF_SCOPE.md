# Native cash lifecycle refinement proof scope

Status: mechanically checked bounded model and Rust/Lean differential trace; not whole-system
certification.

`formal/lean/ActiveChain/CashLifecycle.lean` proves that reward redemption, shielding, unshielding,
and restart preserve native supply, and that reward identifiers and shielded nullifiers are
one-shot. Authorized issuance is the only modeled operation that increases supply.

The production `CashLedger` trace independently performs real native genesis construction,
formula- and policy-bound issuance, accumulator-backed reward redemption, canonical encode/decode
restart, privacy-proof-bound shielding and unshielding, and replay attempts. Its state projection
must match `CashLifecycleTable.lean` byte-for-byte.

The trace assumes the production ML-DSA/finality admission boundary has already authenticated the
settlement inputs. It does not prove cryptographic unforgeability, accumulator collision
resistance, filesystem durability, arbitrary concurrent batches, or block-level finality binding.

Run the focused gate with:

```sh
bash scripts/check-cash-lifecycle-refinement.sh
```
