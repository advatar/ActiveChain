# ActiveChain PQ peer-session proof scope

Status: development protocol model; not cryptographic certification and not yet a proof of the
deployed Rust transport.

The executable Tamarin theory is
`formal/tamarin/activechain_pq_session.spthy`. It models the intended combined boundary between
ML-DSA-authenticated validator peers, ML-KEM-style session establishment, and a protected first
application message. Its purpose is to make the chain/epoch transcript, suite-selection, replay,
and key-compromise assumptions mechanically visible before that boundary is frozen in the wire
protocol.

## Model boundary

The model uses Tamarin's perfect symbolic signing primitive for ML-DSA-44. ML-KEM-768 is
abstracted by perfect public-key encryption: the initiator encapsulates a fresh shared secret to
the responder's registered decapsulation public key, and only the matching private key can recover
it. Perfect symmetric encryption represents the protected envelope. These are Dolev-Yao
abstractions; the model does not prove FIPS 203, FIPS 204, the RustCrypto implementations, or a
computational reduction for ActiveChain's SHAKE-based stream and tag construction.

An accepted session transcript binds all of:

- protocol version `ACTIVECHAIN-PQ-SESSION-V1`;
- chain identity and validator-set epoch;
- fixed suites `ML-DSA-44` and `ML-KEM-768`;
- initiator and responder identities;
- fresh client and server nonces;
- a fresh responder-selected session identifier; and
- the encapsulated shared-secret ciphertext.

The responder authenticates the complete client-finish transcript. The initiator accepts only a
responder-signed server finish containing key confirmation over that same transcript. The model
has no accepting rule for a classical or alternate suite. Linear challenge, confirmation, and
receive-right facts permit replayable network bytes while preventing a concrete session or its
first protected message from being accepted twice.

The protected-message slice is deliberately bounded to `sequence-0`. Its associated data contains
the chain, epoch, session identifier, both peers, protocol domain, and sequence. General unbounded
sequence advancement and crash recovery remain implementation and proof obligations.

## Explicit compromise assumptions

Three adversarial reveal rules are present:

- revealing a peer's long-term signing key permits impersonation from that point;
- revealing the responder's static ML-KEM decapsulation key exposes recorded past ciphertexts;
  consequently this model makes no forward-secrecy claim; and
- revealing an established session key defeats that session's confidentiality and message
  authenticity.

The session-key reveal rule is available only after responder establishment, and that provenance
is mechanically checked. Signing-key and ML-KEM-key compromise can occur at any time. The verified
acceptance-path lemmas describe checks performed by the modeled state machine; they are not claims
that authentication survives compromise.

## Mechanically verified lemmas

Tamarin 1.12.0 completed all seven all-traces proofs with successful well-formedness checks:

- `accepted_transcript_is_context_bound_and_ml_dsa_verified` (2 steps);
- `initiator_checks_responder_identity_and_key_confirmation` (2 steps);
- `no_suite_downgrade_is_accepted` (2 steps);
- `responder_accepts_a_session_once` (15 steps);
- `protected_acceptance_checks_session_context_and_tag` (2 steps);
- `protected_envelope_is_accepted_once` (9 steps); and
- `explicit_session_key_reveal_requires_an_established_session` (3 steps).

The final complete proof run took approximately 70 seconds on the local machine and fits a
180-second process bound:

```sh
perl -e '$seconds=shift; alarm $seconds; exec @ARGV' 180 \
  tamarin-prover formal/tamarin/activechain_pq_session.spthy \
    --prove --derivcheck-timeout=60
```

These lemmas establish fail-closed suite admission, exact acceptance-path context checks, bounded
replay consumption, and explicit session-key reveal provenance. They do not establish complete
injective agreement or computational secrecy.

## Rust conformance gaps

The model is a target contract and is currently stronger than the implementation:

1. `PeerHandshake::signing_payload` binds its domain, sender, and 32-byte challenge, but does not
   bind the chain identity, epoch, responder identity, KEM public key, selected suites, or a full
   bidirectional transcript.
2. `ProtectedEnvelope` implements ML-KEM-768 encapsulation plus a SHAKE256 stream and tag, but its
   encoded `ACPE1` envelope does not carry a canonical chain/epoch/session/suite context. Associated
   data is an untyped byte slice supplied by each caller, so the required context is not enforced
   structurally.
3. The runtime does not yet implement the combined challenge, KEM ciphertext, signed client
   finish, responder key confirmation, and established-session state represented here.
4. Replay high-water state applies to signed consensus envelopes, not to a durable, chain-bound
   KEM session identifier and protected-message sequence across restart.
5. The static ML-KEM recipient design has no forward secrecy. Achieving forward secrecy requires
   an ephemeral or ratcheted PQ construction, key erasure semantics, new vectors, and a new proof.

Until these gaps are implemented and checked against deterministic transcript vectors, the proof
must not be described as verification of the live peer transport.

## Unverified boundaries

The following are outside this scoped model:

- computational IND-CCA, EUF-CMA, and multi-user reductions for ML-KEM and ML-DSA;
- strong/injective peer agreement under every ordering of long-term and session-key compromise;
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
