# Trust ceremony design v1

How to run a threshold trust ceremony for an ActiveChain network, and why the
parts that look like friction are the parts doing the work.

A verifier trust bundle says which proof system, which verifier revision, and
which chain checkpoint the Actum verifier will accept. Signing one is the act
that makes a network's verification story true. A chain runs without a bundle —
what needs one is the verifier trust path — so a ceremony is never on the
critical path of standing a network up, and should never be rushed to unblock
one.

## The property that makes it worth doing

A 2-of-3 exists so that no single person, machine, or compromise can issue a
bundle. Every design decision below follows from protecting that, and each of
the plausible shortcuts destroys it:

| shortcut | what it actually produces |
|---|---|
| one tool holds all three seeds | a 1-of-1 wearing a costume |
| signers sign a digest handed to them | the coordinator chooses what they signed |
| review shows some fields | a signature over the fields it did not show |
| the same host prepares and signs | one compromise reaches both |

## Roles

Three roles, and they must be different machines. Whether they are different
people is a policy decision; whether they are different machines is not.

- **Build host** — prepares the unsigned body from real chain artifacts and
  assembles the result. Holds no signing key.
- **Signers** — each holds one seed, reviews the body, and returns a detached
  signature. Never sees another signer's key.
- **Coordinator** — tracks who has signed and verifies each signature as it
  arrives. Holds no signing key; may be the build host.

## The flow

Already implemented by `actum-trust-bundle`, whose four subcommands exist
precisely so that only one of them needs secret material:

```
prepare   build host    unsigned body + bundle id, derived from a real
                        finality bundle and execution snapshot
   │
   ├─────────────▶ inspect   any host      human review of what will be signed
   │
sign      offline host  detached signature; the seed never leaves the host
   │
assemble  build host    verifies the threshold and writes a deployable bundle
```

Two properties of this are load-bearing and easy to lose in a rewrite.

**The signer signs a body, not a digest.** `sign` takes the canonical body and
recomputes the bundle id itself. A signer handed a 48-byte digest is signing
whatever the requester chose; a signer given the body can check what it says. If
a future interface offers "just paste the bundle id", it has removed the point of
having signers.

**Assembly re-verifies rather than trusts.** `assemble_bootstrap` rejects
unknown signers, rejects duplicates, and runs the same verification the
deployment host will run — so a bundle that would be refused on deployment is
never written to disk.

## What a signer must be shown

The signature covers the whole body, so a review that shows part of it is a
review of nothing in particular. `render_body` shows every field, and a test
fails if a field is added without appearing there.

The rotation fields deserve their own treatment and now get it. A bundle may
name the signer set that *replaces* the current one:

```
next_signer_set_id, next_signer_set_revision,
next_signer_threshold, next_signer_activation_sequence
```

Handing signing authority to another set is the most consequential thing a
bundle can say, and until this revision it was invisible in review — a signer
could approve a rotation without ever seeing it. Rotations are now announced in
words, the absence of one is stated explicitly so silence is never the signal,
and the review says plainly not to sign unless the signer recognises the
incoming set.

## Key custody

Currently a seed is a file, which is honest for a testnet and not sufficient for
anything else. In rising order of strength:

1. **Seed file on an offline host.** What exists. Adequate while the bundle
   governs a test network and the loss of one is an inconvenience.
2. **Secure Enclave per signer**, reusing the wallet's custody architecture —
   the seed is wrapped by a device key and unwrapped only under user presence.
   Separate machines, separate enclaves; the operator console must never hold
   them, which is why it orchestrates rather than signs.
3. **Hardware tokens**, if signers are distinct people in distinct places.

Whatever the mechanism, the invariant is the same: no host holds more than one
seed, and the coordinating host holds none.

## Coordination

`trust_ceremony::coordinator` tracks a ceremony across the days it may take.
It accepts a signature only after verifying it against that signer's public key
over this exact payload, so a rejection names the responsible party rather than
surfacing later as an opaque assembly failure. A second signature from a signer
who has already contributed is recorded as `AlreadySigned` and does **not**
advance the threshold — counting a repeat would let one party satisfy a 2-of-3
alone.

Outstanding: the coordinator is in-memory. A ceremony spanning sessions needs
its state to be durable in the shape of the other durable registries here —
canonical snapshot, atomic replace, fail-closed restart.

## Transport

The body and the signatures are public: the body is what is being authorized,
and a signature is only useful with the key it verifies against. Nothing here
needs confidentiality. What it needs is **integrity and provenance** — a signer
must be sure the body they reviewed is the body that gets assembled, and the
bundle id gives them that for free, since it is derived from the body they hold.

Practically: move files on removable media or over any channel, and have each
signer confirm the bundle id they signed matches the one assembly reports. A
mismatch means someone substituted a body.

## What is deliberately not automated

Not caution — arithmetic. Automating the signing step means one program holds
every seed, and a 2-of-3 whose keys live in one place is a 1-of-1. The operator
console can prepare, display, collect, verify, assemble and activate. It cannot
sign, and no amount of convenience justifies changing that.

## Outstanding

- Durable coordinator state across sessions.
- A rotation ceremony procedure: rotation is expressible today, but the human
  process for approving one is not written down.
- Secure Enclave custody for signers, reusing the wallet's architecture.
- A proof scope. Threshold soundness — that no accepted sequence of signatures
  satisfies a threshold of *k* with fewer than *k* distinct signers — is
  stateable and currently defended by tests rather than proof. See
  [#802](https://github.com/advatar/ActiveChain/issues/802).
