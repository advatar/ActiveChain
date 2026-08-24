# DCN finalized-evidence settlement and reputation

Issue [#828](https://github.com/advatar/ActiveChain/issues/828) qualifies the narrow G8.1 accounting boundary. A DCN `GenerationAttestation` must already be `VERIFIED`, anchored through `dcn.generation-attestation.evidence-anchor.v1`, and finalized by Actum before this transition can execute. Actum finality does not replace DCN proof verification.

## Accounting-first boundary

The qualified implementation is an integer-denominated deterministic accounting ledger, not a token or a second blockchain. One atomic transition:

1. independently verifies the native Actum finality envelope for the exact DCN evidence anchor;
2. verifies the configured settlement authority, payer, executor, chain, unit, agreement, policy, and assurance class;
3. derives a deterministic idempotency identity from the evidence commitment, agreement, and settlement-policy version;
4. debits the payer and credits the executor with checked `u128` arithmetic;
5. writes one canonical `SettlementRecordV1`; and
6. appends one policy-versioned `ReputationEventV1` containing auditable facts rather than an opaque score.

Duplicate delivery of the exact instruction returns the original record without moving value again. A conflicting instruction under the same idempotency identity is rejected. Failed transitions do not mutate in-memory or durable state.

Settlement objects contain commitments and principals, not prompt text, response text, private K/V state, proof bytes, credentials, or storage URLs. The authorization-scope commitment is carried explicitly so an application can bind its tenant/audience policy without publishing private scope data.

Only `SettlementAssuranceClassV1::Cryptographic` is supported. Unsupported assurance classes fail canonical decoding and are not payable by default.

## Actum anchoring and trust boundary

The accounting state is committed canonically after every transition. The qualification fixture anchors the first 256 bits of the 384-bit state commitment, under the versioned domain:

```text
dcn.generation-attestation.settlement-state.v1
```

through the existing `DigestAnchorStatementV1` consensus path. The complete 384-bit accounting and state commitments remain in the canonical settlement record and fixture report; the anchor digest is an explicitly versioned 256-bit projection.

This is finalized accounting evidence, not native-token payment finality. Actum consensus finalizes the resulting accounting-state commitment. A future native cash-rail integration would require a separate qualified transition that atomically combines the same evidence gate with an Actum-native asset transfer.

## Query and recovery

The ledger exposes deterministic queries from evidence to settlements, settlement identity to its record, account to settlements, and executor to raw reputation events. Its canonical snapshot validates the complete accounting-commitment chain and event correspondence when reopened. Durable writes use a synced temporary file plus atomic rename, and exact duplicate settlement remains idempotent after process and RPC restart.

## Qualification fixture

The real three-validator fixture starts by reproducing the exact G8 anchor:

- evidence commitment `sha256:ca136341911241af68064f3f4a3cd1a77422776ed7903864de40c05dc41e9c89`;
- finalized evidence action `81214352a75a47db1f71ce45b7ecbabdd2c56a6ce5ab9bfa2488017b6831b50a41c4493e067a184b192fd665a0dd83a3`;
- finalized evidence height `2`.

It then settles 125 integer units from a 1,000-unit payer account to a 50-unit executor account, proves balance conservation at 1,050 units, retries after RPC/process restart without a duplicate debit, anchors the resulting accounting state, and obtains three-validator finality at height 3.

Run it with pinned Rust:

```sh
output=$(mktemp -d /tmp/actum-dcn-settlement.XXXXXX)
rm -r "$output"
RUSTUP_TOOLCHAIN=1.97.1 \
  scripts/qualify-dcn-evidence-settlement.sh "$output"
```

The milestone does not claim public cryptocurrency, regulatory payment finality, market-wide reputation, staking, rewards, recursive aggregation, or token economics.
