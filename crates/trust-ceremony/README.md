# `activechain-trust-ceremony`

Offline construction and signing of `SignedActumVerifierTrustBundleV1`.

`provision-work-proof-verifier.sh` requires operator-supplied `signed-trust-bundle.bin` and
`trust-signer-set.bin`, and `actum-work-proof-trust-bootstrap` only consumes them. This crate
produces them without ever placing a signing key on a verifier host.

The repository does not choose production trust authority. These tools encode what an operator
decided and fail closed when that decision would not satisfy the frozen bundle semantics.

## Ceremony

```text
offline signer host          build host                    verifier host
-------------------          ----------                    -------------
actum-trust-keygen
  secret seed (0600)  ─┐
  public key hex ──────┼──▶ actum-trust-signer-set
                       │      trust-signer-set.bin ────────────────────┐
                       │                                               │
                       │    actum-trust-bundle prepare                 │
                       │      unsigned body + bundle_id                │
                       │             │                                 │
  actum-trust-bundle sign ◀──────────┘                                 │
    detached signature ──────▶ actum-trust-bundle assemble             │
                                 signed-trust-bundle.bin ──────────────┤
                                                                       ▼
                                                    provision-work-proof-verifier.sh
```

The secret seed never leaves the signer host. `sign` takes the canonical body, not a handed-over
digest, so a signer recomputes the identity it authorizes and can `inspect` it first.

## Bootstrap, 1-of-1

```sh
actum-trust-keygen root.seed root.pub
printf '[{"public_key_hex":"%s","valid_from_sequence":1,"valid_until_sequence":64}]\n' \
  "$(cat root.pub)" > signers.json
actum-trust-signer-set trust-signer-set.bin 1 1 signers.json

# Pin exactly what the deployed build verifies against.
actum-work-proof-trust-bootstrap --emit-trust-inputs > proof.json

actum-trust-bundle prepare body.bin spec.json proof.json finality.bundle receipt.bin \
  trust-signer-set.bin
actum-trust-bundle sign root.sig.json root.seed body.bin
actum-trust-bundle assemble signed-trust-bundle.bin body.bin trust-signer-set.bin \
  "$(($(date +%s) * 1000))" root.sig.json
```

`spec.json` carries only decisions no artifact can supply:

```json
{
  "bundle_sequence": 1,
  "policy_id_hex": "…96 hex…",
  "policy_revision": 1,
  "issued_at_ms": 0,
  "not_before_ms": 0,
  "not_after_ms": 0
}
```

Checkpoint identity is never typed by hand. `prepare` derives `chain_id`, `genesis_commitment`,
`protocol_revision`, `checkpoint_height`, `checkpoint_block_id`, `checkpoint_state_root`,
`checkpoint_finality_commitment`, and `validator_set_root` from the same finality bundle and block
receipt the verifier consumes. A hand-entered checkpoint is the most likely way to produce a bundle
that signs cleanly and then rejects every real anchor.

## Threshold

`build_signer_set` accepts any N-of-M within `MAX_TRUST_SIGNERS`. For a 2-of-3 set, list three
public keys and pass threshold `2`; `assemble` requires at least the threshold count, rejects a
signer outside the set, rejects duplicates, and verifies the result with the same
`verify_trust_bundle_bootstrap` the verifier host runs before writing anything to disk.

Signer identity is `SHA3-384("ACTUM-TRUST-SIGNER-ID-V1" ‖ public_key)`, so a set cannot mislabel
which key a signer holds and any party can recompute it offline. This is the tool's convention,
not a protocol requirement — the frozen rules only require non-zero, unique, sorted identities.

## What this crate does not do

- It does not choose signer custody, rotation cadence, or bundle lifetime.
- It does not transport secrets; moving `body.bin` and the detached signature is an operator step.
- It does not rotate trust. A deployed root transitions only through
  `verify_trust_bundle_transition`, never by replacing `trust.bin` with a new package.
