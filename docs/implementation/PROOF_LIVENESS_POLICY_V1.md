# Proof liveness policy v1

Proof-carrying validity remains the authoritative v1.1+ rule. This policy defines what happens
when proof suppliers are unavailable; it does not allow an invalid transition to finalize.

1. **Normal:** a block carries a valid proof bound to its exact header, state roots, protocol
   revision, and verifier profile. Validators check the proof before voting.
2. **Grace period:** after a bounded outage threshold, validators may re-execute the transition
   and retain the candidate locally, but must not finalize it as proof-qualified. The candidate is
   tagged pending-proof and expires at the configured height/time bound.
3. **Recovery:** a valid proof for the exact candidate may arrive during the grace period. It is
   checked against the same commitment and can then enter the ordinary finality path.
4. **Degraded mode:** if the grace period expires, the network may continue ordering only under an
   explicitly advertised development profile. Degraded blocks are not eligible for production
   finality, value-bearing receipts, or the proof-carrying validity claim.
5. **Safety:** validator re-execution is a liveness aid, never a substitute for proof verification
   after proof-required activation. A malicious or unavailable prover can delay finality, but cannot
   make an invalid state authoritative.

The release manifest must publish the outage threshold, grace bound, degraded-mode flag, verifier
revision, and recovery rules. Changing any of these is a protocol upgrade, not an operator toggle.
