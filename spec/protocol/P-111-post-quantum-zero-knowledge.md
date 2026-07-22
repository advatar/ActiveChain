# P-111 — Post-quantum zero-knowledge profile

Status: development profile; third-party audit pending.

## Purpose

ActiveChain PQ-ZK v1 proves execution of an approved private-action relation while revealing only
the relation identifier and its explicitly committed public output. The profile is intended for
private billboard actions first and is reusable by later shielded-object relations.

## Pinned proof system

The only conforming v1 engine is RISC Zero zkVM 3.0.5 using its default succinct zk-STARK receipt.
Implementations MUST use the exact guest image identifier published by the `activechain-pq-zk-methods`
crate. They MUST enable `disable-dev-mode`; fake receipts, execution-only sessions, Groth16 receipts,
and receipts produced by any other guest image are non-conforming.

The v1 security argument is transparent and hash based: the zk-STARK uses polynomial commitments,
Fiat–Shamir, and FRI rather than elliptic-curve pairings or a trusted setup. “Post-quantum” is a
conditional claim: it assumes the security of the pinned STARK construction and its hash functions
against quantum attackers. It is not a claim of unconditional security or NIST certification.

## Statement binding

The guest MUST:

1. read the entire private witness from the zkVM private input channel;
2. validate the complete relation with checked arithmetic and strict bounds;
3. commit a versioned public statement to the receipt journal; and
4. halt without committing a valid statement if any relation check fails.

The host verifier MUST verify the cryptographic receipt against the exact pinned image identifier,
strictly decode the journal, and compare every journal byte to the caller-supplied public statement.
It MUST reject trailing bytes, unknown versions, mismatched image identifiers, and all receipt kinds
other than the configured transparent succinct receipt.

For a billboard post, the statement binds the chain, asset, anchor, prior nullifier, successor permit
commitment, post identifier and content, height, exact fee, dummy flag, and policy revision. The
witness contains the prior and successor permit openings and nullifier key. A successful proof MUST
enforce the same transition predicate as the reference verifier.

## Privacy and metadata

The receipt does not publish the private input or execution trace. Proof size, proving time, guest
image identity, and the explicitly journaled statement remain public and can leak coarse metadata.
Applications MUST NOT place secrets in the journal or logs. Side-channel resistance of the host,
wallet, operating system, and proving service is outside this protocol.

The v1 conformance relation publishes SHA3-256 of its secret. It proves private preimage knowledge,
but the digest is not a hiding commitment for low-entropy inputs: callers MUST use an independently
random secret or an application commitment with sufficient blinding. The billboard relation will
retain its existing 384-bit randomized permit commitments rather than hash human-authored content.

## Versioning and domain separation

The profile identifier is the ASCII string `ACTIVECHAIN-PQ-ZK-RISC0-STARK-V1`. Public journals begin
with this identifier. Verification separately binds the receipt to the 32-byte guest image
identifier. Any guest change creates a new image identifier and requires an explicit protocol
revision. Application hashes retain their application domain tags; the proof receipt does not
replace canonical application commitments.

## Verification evidence and claim limits

Repository tests MUST include a real local proof, exact image verification, public-input substitution
rejection, malformed receipt rejection, and differential relation fixtures. Machine-checked models
cover the stated application invariants, not the cryptographic implementation, compiler, zkVM, FRI,
hash functions, or hardware. Until an independent audit covers the pinned dependency, guest relation,
host verifier, integration, and formal-proof scope, public material MUST say “third-party audit
pending” and MUST NOT say “audited,” “production ready,” or “formally verified cryptography.”

## Normative references

- Ben-Sasson et al., *Scalable, transparent, and post-quantum secure computational integrity*.
- Ben-Sasson et al., *Fast Reed–Solomon Interactive Oracle Proofs of Proximity*.
- RISC Zero zkVM 3.0.5 source and proof-system specification.
