# ActiveChain PQ peer-session proof scope

Status: development protocol model and trace-aligned Rust implementation; not cryptographic
certification or whole-transport verification.

The executable Tamarin theory is
`formal/tamarin/activechain_pq_session.spthy`. It models the intended combined boundary between
ML-DSA-authenticated validator peers, ML-KEM-style session establishment, and a protected first
application message. Its purpose is to make the chain/epoch transcript, suite-selection, replay,
and key-compromise assumptions mechanically visible before that boundary is frozen in the wire
protocol.

## Model boundary

The model uses Tamarin's perfect symbolic signing primitive for ML-DSA-44. ML-KEM-768 is
abstracted by a suite-distinct perfect public-key encryption equation: the initiator encapsulates a
fresh KEM secret to the responder's fresh per-challenge decapsulation public key, and only the
matching private key can recover it. Separate `kempk`/`kemenc` constructors prevent symbolic
ML-DSA/ML-KEM key substitution, matching the runtime's pinned suites and disjoint key lengths.
The usable session key is the ideal hash of a dedicated KDF domain, that KEM secret, and the full
signed transcript. Perfect symmetric encryption represents the protected envelope. These are
Dolev-Yao abstractions; the model does not prove FIPS 203, FIPS 204, the RustCrypto
implementations, or a computational reduction for ActiveChain's SHAKE-based stream, KDF, and tag
construction.

An accepted session transcript binds all of:

- session version `ACTIVECHAIN-PQ-SESSION-V2` and protocol revision;
- chain identity and validator-set epoch;
- fixed suites `ML-DSA-44` and `ML-KEM-768`;
- initiator and responder identities;
- fresh client and server nonces;
- a responder challenge identifier derived from the complete context and fresh material; and
- the responder's ephemeral ML-KEM public key; and
- the encapsulated shared-secret ciphertext.

The responder authenticates the complete client-finish transcript. The initiator accepts only a
responder-signed server finish containing key confirmation over that same transcript-derived key.
The model has no accepting rule for a classical or alternate suite. Linear challenge,
confirmation, and receive-right facts permit replayable network bytes while preventing a concrete
session or its first protected message from being accepted twice.

The protected-message slice is deliberately bounded to `sequence-1`. Its associated data contains
the chain, epoch, session identifier, both peers, protocol domain, and sequence. General unbounded
sequence advancement and crash recovery remain implementation and proof obligations.

## Explicit compromise assumptions

Three adversarial reveal rules are present:

- revealing a peer's long-term signing key permits impersonation from that point;
- revealing a session's ephemeral ML-KEM decapsulation key exposes that session's recorded
  ciphertext; the model does not prove key erasure or forward secrecy; and
- revealing an established session key defeats that session's confidentiality and message
  authenticity.

The session-key reveal rule is available only after responder establishment, and that provenance
is mechanically checked. Signing-key and ML-KEM-key compromise can occur at any time. The verified
acceptance-path lemmas describe checks performed by the modeled state machine; they are not claims
that authentication survives compromise.

## Mechanically verified lemmas

Tamarin 1.12.0 completed all eleven all-traces proofs with successful well-formedness checks:

- `accepted_transcript_is_context_bound_and_ml_dsa_verified` (2 steps);
- `initiator_checks_responder_identity_and_key_confirmation` (2 steps);
- `no_suite_downgrade_is_accepted` (2 steps);
- `responder_accepts_a_session_once` (15 steps);
- `protected_acceptance_checks_session_context_and_tag` (2 steps);
- `protected_envelope_is_accepted_once` (9 steps); and
- `explicit_session_key_reveal_requires_an_established_session` (3 steps);
- `responder_acceptance_authenticates_initiator` (9 steps);
- `initiator_acceptance_authenticates_responder` (7 steps);
- `honest_session_protected_acceptance_has_a_sender` (16 steps); and
- `honest_established_secret_requires_compromise_to_leak` (13 steps).

The final complete strengthened V2 proof run took approximately 45 seconds on the local machine and
fits a 300-second process bound:

```sh
perl -e '$seconds=shift; alarm $seconds; exec @ARGV' 300 \
  tamarin-prover formal/tamarin/activechain_pq_session.spthy \
    --prove --auto-sources --derivcheck-timeout=120
```

`--auto-sources` asks Tamarin to generate and prove its message-source typing lemma before the
correspondence goals; it is a proof-search aid, not an additional protocol assumption. CI uses this
invocation specifically for this theory and enforces the 300-second per-invocation process bound.

These lemmas establish fail-closed suite admission, exact acceptance-path context checks, bounded
replay consumption, explicit session-key reveal provenance, non-injective peer authentication,
origin authentication for the first protected message, and symbolic secrecy for an honestly
established session.

Responder acceptance has either a prior initiator finish with the exact session, context,
transcript, and derived key, or a prior compromise of that initiator's signing key. Initiator
acceptance has a prior exact responder acceptance unless the responder's signing key was
compromised first. That exception is intentionally sufficient: an attacker holding the identity
signing key can generate and sign its own ephemeral KEM challenge. The ephemeral KEM exchange
provides session secrecy and key confirmation, not a second independent responder identity.
Because a modeled session-key reveal requires a prior responder acceptance, it is already covered
by the first branch.

Protected-message origin and session secrecy are stated for a matching honest initiator finish and
responder acceptance. This condition matters: a party that has stolen an initiator signing key can
encapsulate its own known KEM secret and establish an attacker-known session without breaking
ML-KEM. Such an attacker-originated session is not an honest-session secrecy counterexample.

## Counterexamples that changed the target design

The first session model used the raw KEM output directly as the usable session key. Tamarin found a
22-step counterexample to initiator authentication: after compromise of both peers' signing keys,
an attacker replayed one honest KEM ciphertext into a second signed transcript, established an
alias session with the same raw secret, revealed the alias session key, and forged confirmation
for the original session without compromising the ML-KEM key. Deriving the session key from the
KEM secret and the complete transcript prevents this cross-session alias. The revised
correspondence theorem verifies in 28 steps.

An early protected-message theorem required only an initiator-finish event with the same session
identifier. Tamarin found a 21-step counterexample in which a compromised initiator signing key
caused the responder to accept a different transcript for that identifier. The corrected theorem
requires the honest finish and responder acceptance to agree on the exact transcript and derived
key. It then verifies in 17 steps. Both counterexamples remain part of the proof record; they are
retained as design evidence rather than claims beyond the modeled boundary.

## Rust trace alignment and remaining gaps

`crates/consensus-runtime/src/pq_session.rs` implements the modeled V2 sequence: a fresh client
hello, responder-signed challenge with a fresh ephemeral ML-KEM-768 recipient, signed client
finish, transcript-bound KDF, signed responder key confirmation, and session-bound protected
frames. Its transcript additionally binds explicit timestamps and the exact numeric protocol
revision. Durable bounded session identifiers and protected send/receive high-water marks reject
restart replay; session keys are not persisted.

This is trace alignment, not proof that the Rust parser or cryptography refines the symbolic
model. Tamarin abstracts the numeric revision as one literal, treats the challenge identifier as
fresh instead of SHAKE-derived, omits timestamps and bounded clock skew, and models one protected
message rather than the implementation's durable sequence machine. Deterministic vectors and
negative Rust tests cover the byte-level constants and parser boundary separately. The proof must
therefore be described as verification of the symbolic session design, with implementation
conformance supported by tests—not as verification of the entire live transport.

## Unverified boundaries

The following are outside this scoped model:

- computational IND-CCA, EUF-CMA, and multi-user reductions for ML-KEM and ML-DSA;
- injective agreement beyond the model's one-shot session acceptance and every ordering of
  long-term and session-key compromise;
- forward secrecy, post-compromise security, key rotation, and secure erasure;
- malformed ciphertext behavior, canonical byte decoding, downgrade behavior across real upgrade
  windows, and cross-version parser differentials;
- unbounded protected-message sequencing, concurrent sessions, restart persistence, packet loss,
  reordering, denial of service, and liveness;
- randomness quality, constant-time behavior, cache/power/timing side channels, memory disclosure,
  and supply-chain compromise; and
- consensus safety, finality, validator-set transitions, application authorization, DA, execution,
  and economics, which have separate proof scopes.

Independent cryptographic and formal-methods review remains mandatory before a
non-developmental security claim.
