# Wallet distribution and the public transfer path

Two gaps that writing the integrator guide exposed. Both are the difference
between a testnet that demonstrates and one an outsider can actually use, and
neither is a documentation problem.

## The order matters

The transfer path comes first. A signed wallet that cannot spend is still not
usable for anything an integrator would call a payment; a spendable wallet
handed over by hand is already testable. Signing makes distribution
respectable, but it does not make the product work.

## Gap 1 — there is no public way to spend

This is the more consequential of the two, and it is easy to miss because the
faucet works. `RpcRequest` today is exactly:

```
Status, AnchorServiceStatus, Get, List,
SubmitAnchor, SubmitAnchorAction, ResolveAnchor,
RequestFaucet, RequestAuthorizedFaucet, ResolveFaucet, FaucetTerms
```

Reads, anchors, faucet, status. **Value enters a wallet only through the faucet
and can never leave it.** The two-cell grant fixed in #799 made a grant
*spendable in the kernel's terms* — a holder of one cell cannot transfer at all,
because a transfer needs an input plus a distinct fee reserve — but nothing
exposes that capability over the wire. The wallet's "Transfers disabled until
finalized wallet state is available" notice reads like the reason; it is not.
That gate is conditional on `isVerified` and is correct behaviour. Even a
verified wallet has nothing to call.

### Most of the machinery already exists

This is a plumbing job, not a design job:

| piece | where |
|---|---|
| signed transfer envelope | `AuthorizedCashTransferV1`, wallet-core |
| session model that bounds spend | `AuthorizedCashSessionGrantV1`, wallet-core |
| verification of that envelope | `rpc-server/src/lib.rs:866`, already decoding it |
| delivery into a block | the faucet's own spool → round → block route |
| client-side construction | `activechain-wallet transfer` and `grant-session` |

The RPC server already verifies exactly this envelope; it is wired to faucet
settlement rather than exposed. What is missing is the entry point and the
policy that governs it.

### Work

1. **`RpcRequest::SubmitAuthorizedTransfer { envelope }`**, with a response
   carrying an accepted/rejected taxonomy modelled on `FaucetRejectionV1`.
   Reuse that vocabulary rather than inventing a second one — an integrator
   should not have to learn two rejection languages.
2. **Reuse the existing verification.** A second verifier for the same envelope
   is how two implementations drift into disagreeing about what is valid.
3. **A public spool, separate from the faucet's**, with its own depth cap that
   fails closed when full. The faucet's quota model — per-recipient,
   per-source, and global windows — is the precedent to follow; a public path
   needs at least per-source rate limiting, because unlike the faucet there is
   no operator key gating who may submit.
4. **Schema revision 4.** Adding a request variant changes the wire, and the
   wallet pins the revision exactly (`schemaRevision: 3` today, checked against
   the node's `Status`). Node and wallet must therefore ship together — this is
   the one part that forces a coordinated release rather than a rolling one.
5. **Let the wallet send.** Keep the `isVerified` gate; what changes is that a
   verified wallet now has a working send behind it.

### What must not be lost

The kernel already guarantees that no transfer mints value or spends a cell
twice. The new surface is *admission*: the property to state is that no
envelope reaching the spool was unauthorized, and that a full spool refuses
rather than drops. That belongs in the same proof-scope conversation as
[#802](https://github.com/advatar/ActiveChain/issues/802), not in a separate
one.

## Gap 2 — there is no installable wallet

Current state, from the project settings and CI:

- `DEVELOPMENT_TEAM = L2AF8KFX35` is set, so an Apple identity exists.
- `CODE_SIGN_IDENTITY = "iPhone Developer"` — a *development* identity, which
  cannot be used for external distribution.
- No `codesign`, `notarytool`, or `stapler` invocation appears anywhere in CI.
  The Apple stage builds and reproduces distributions; it never signs one for
  anybody else's machine.

What external installation requires differs by platform, and neither is
optional:

- **macOS outside the App Store** needs a Developer ID Application identity,
  the hardened runtime, notarization through `notarytool`, and a stapled
  ticket. Skipping the staple appears to work on the build machine and then
  fails on a first launch without network — the worst failure to debug
  remotely, because it reproduces nowhere.
- **iOS** has no unsigned path at all. TestFlight with an external group is the
  only route that does not involve collecting UDIDs.

### Work

1. Provision a Developer ID Application certificate and store it as CI secrets
   (p12 plus password).
2. **Create a dedicated temporary keychain per job**, unlock it there, and
   delete it at the end. Do not sign from the login keychain. This session lost
   hours to exactly that dependency: a launchd agent cannot unlock the login
   keychain, and the formal stage failed on `error getting credentials` after
   proving every model. Signing must not reintroduce the same coupling.
3. Gate signing and notarization on a **tag**, not on every push. Notarization
   is a network round trip to Apple that can fail independently of the build,
   and it must never be able to fail the deterministic kernel qualification.
4. Publish the stapled artifact with its SHA-256, so the onboarding guide can
   tell an integrator what to verify rather than asking them to trust a link.

## Risks worth naming

**A coordinated release is a new failure mode.** Revision 4 means a wallet
built against it cannot talk to a node still serving 3, and vice versa. This
session already saw that exact breakage in the benign direction — the wallet
pinned 3 against a node serving 2 and simply could not connect. Plan the
sequence explicitly: deploy the node, then release the wallet.

**Signing secrets on a self-hosted runner** are a real expansion of what a
compromise of that machine reaches. The temporary-keychain discipline limits
the window but does not remove the exposure.

**Rate limiting a public write path is the load-bearing part.** The faucet is
protected by an operator key and a quota; a public submission endpoint has
neither by default. Getting the bounds wrong turns the spool into the denial-of-
service surface for the whole chain.
