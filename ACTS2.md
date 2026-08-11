Yes. The correct abstraction is not a commit protocol but a verifiable state-transition protocol.

Git commits are one possible implementation because they bind content, parents, authorship, and metadata. But Git also imports assumptions that do not belong in the generic protocol: repositories, trees, branches, textual diffs, commit objects, and developer workflows.

The generic primitive is:

S_i \xrightarrow{\;A_i\;} S_{i+1}

Where:

* S_i is a commitment to the artifact before the edit.
* A_i is a verifiable claim about the act that caused the transition.
* S_{i+1} is a commitment to the artifact after the edit.

1. The abstraction: a Verifiable Mutation

I would define an ACTS domain primitive called something like:

ArtifactMutationV1 — a signed claim that a principal, acting through an identified application and under specified authority, transformed one or more committed artifact states into one or more new committed states.

It is narrower than ActRecordV1, but maps directly into it.

ArtifactMutationV1
├── mutation_id
├── context_id
├── artifact_id
├── parent_mutations[]
├── prior_states[]
├── resulting_states[]
├── actor
├── acting_software
├── authority
├── operation
├── evidence
├── sequence
├── time_evidence
├── privacy_policy
└── signature

The mutation ID is derived from the canonical record:

mutation\_id = H(\text{canonical ArtifactMutationV1})

This produces a content-addressed causal graph without assuming Git, filesystems, blockchains, or even conventional files.

2. The protocol should prove five different things

“Proving an edit” is actually several independent claims.

State integrity

The protocol binds the state before and after the mutation:

prior_state_commitment
resulting_state_commitment

For a simple file:

H(file bytes)

For structured or very large artifacts, this may instead be:

* a Merkle root;
* a chunk tree;
* a canonical document-model commitment;
* a directory-tree commitment;
* a database-state root;
* a media-project manifest root.

The protocol must not prescribe one universal hashing layout. It should prescribe a typed commitment envelope:

StateCommitment {
    algorithm
    representation_profile
    digest
    size
    media_type?
}

The representation_profile is critical. A hash of raw bytes is not the same claim as a hash of a normalized document model.

Causal continuity

The record must bind itself to the preceding history:

parent_mutations[]
prior_states[]
sequence
context_id

This detects:

* rewriting of recorded history;
* deletion of an intermediate recorded transition;
* rollback to an earlier recorded state;
* unacknowledged branching;
* ambiguous merges.

Unlike a linear hash chain, parent arrays naturally support branching, merging, concurrent edits, and collaborative documents.

Attribution

The mutation is signed by an authenticated principal:

actor
acting_software
device_or_runtime
signature

These should remain separate.

A human, an application, an AI agent, and a device are not interchangeable identities. For example:

actor: Alice
acting_agent: ResearchAgent-17
acting_software: AcmeEditor 4.2
device: device principal 0x...

The signature says who issued the claim. Credentials and attestations say what confidence the verifier should place in that identity.

Authority

The protocol must show why the actor was permitted to modify the artifact:

capability_chain
role_or_delegation
policy_commitment
policy_decision
approval_reference?

This distinguishes:

* “Alice edited the file”;
* “Alice was authorized to edit the file”;
* “an agent edited it under a capability delegated by Alice”;
* “the application performed an autosave without making a substantive user decision.”

This is where ACTS becomes much stronger than signed commits.

Existence and ordering

A signature alone does not reliably prove when a mutation existed or whether a signer created conflicting histories.

That requires one or more of:

* signed checkpoints;
* independent witnesses;
* transparency logs;
* secure monotonic counters;
* trusted timestamping;
* Actum anchoring;
* consensus finality.

These should remain separate assurance dimensions.

3. Do not make semantic diffs mandatory

A generic protocol should commit to the before and after state, but it should not require a universal diff representation.

A mutation can optionally contain:

operation = {
    profile: "text.patch.v1",
    commitment: H(patch),
    disclosed_payload?: patch
}

Or:

operation = {
    profile: "logic.project.edit.v1",
    type: "track.region.move",
    commitment: H(private operation details)
}

The semantic operation can be:

* fully disclosed;
* encrypted;
* selectively disclosed;
* committed but withheld;
* omitted entirely.

The core proof remains valid as long as the transition binds the prior and resulting states.

This matters because the same byte-level change may represent very different acts:

* changing a sentence;
* updating an embedded timestamp;
* modifying metadata;
* rendering an audio effect;
* regenerating a model file;
* autosaving a temporary state.

ACTS should support domain semantics without pretending there is one universal ontology of edits.

4. “Every edit” requires four assurance levels

The phrase “every edit” needs careful definition. MadeMark’s watcher cannot necessarily see every logical editing operation. It sees observable filesystem transitions.

I would make recording mode explicit.

Recording mode	What it proves
Native transactional	The application declared each logical mutation as it occurred
Native state	The application declared each committed or saved state
Mediated	A controlled storage layer observed every state transition passing through it
External observation	A watcher observed filesystem or artifact changes after they occurred

These should map to epistemic types:

native transactional → declaration
native saved state   → declaration
mediated storage     → observation with strong coverage
external watcher     → observation
reconstructed diff   → inference

This is a crucial limitation:

A hash chain can prove that recorded edits were not altered without detection. It cannot, by itself, prove that no unrecorded edit occurred.

To claim completeness, the verifier needs evidence that all mutation paths were mediated. That might come from:

* application-native instrumentation;
* exclusive write access through the recorder;
* an operating-system filesystem extension;
* a trusted execution environment;
* a controlled collaborative-editing server;
* signed application attestations about recorder activation.

The assurance vector should therefore include something like:

recording_completeness:
    unknown | observational | application_asserted | mediated | hardware_enforced

5. A minimal implementation-independent protocol

The protocol can be reduced to six objects.

1. RecordingContext

Defines the provenance boundary.

RecordingContextV1 {
    context_id
    controller
    artifact_scope
    recorder_principals[]
    authority_policy
    creation_time
    nonce
}

Examples:

* this file;
* this Logic project;
* this folder;
* this patient record;
* this software release;
* this design workspace.

2. ArtifactDescriptor

Gives a stable logical identity independent of its current bytes.

ArtifactDescriptorV1 {
    artifact_id
    context_id
    artifact_type
    creation_mutation
    optional_names[]
}

A path is merely mutable metadata. It must not be the artifact identity.

3. StateCommitment

Commits to an artifact state.

StateCommitmentV1 {
    artifact_id
    representation_profile
    hash_algorithm
    digest
    byte_length?
}

4. ArtifactMutation

Binds the transition, authorship, and authority.

ArtifactMutationV1 {
    protocol_version
    context_id
    mutation_id
    parent_mutations[]
    prior_states[]
    resulting_states[]
    actor_principal
    application_principal
    agent_principal?
    device_principal?
    authority_reference
    operation_commitment?
    operation_type?
    sequence
    local_time?
    recorder_counter?
    evidence_refs[]
    signature
}

5. Checkpoint

Efficiently commits to many mutations.

MutationCheckpointV1 {
    context_id
    previous_checkpoint?
    mutation_set_root
    ordered_feed_head?
    artifact_state_root
    sequence_range
    recorder_principal
    signature
}

The checkpoint may use a Merkle tree or accumulator. Actum anchors checkpoint commitments, not necessarily every keystroke or autosave.

6. Receipt

Adds outside evidence.

CheckpointReceiptV1 {
    checkpoint_id
    receipt_type
    issuer
    observed_at
    inclusion_or_finality_proof
    signature
}

Receipt types might include:

* witness receipt;
* transparency-log inclusion;
* timestamp receipt;
* Actum finality receipt;
* secure-device counter attestation.

6. The graph is more fundamental than the feed

MadeMark currently has per-root append-only feeds. Those are useful operationally, but the generic model should be a causal mutation graph.

A feed is one ordered projection of that graph.

Mutation A ──→ Mutation B ──→ Mutation D
        └────→ Mutation C ──┘

This supports:

* concurrent editing;
* offline work;
* branches;
* merges;
* conflict preservation;
* partial synchronization;
* multiple recorders;
* imported states;
* derived artifacts.

A merge should not erase disagreement. It should declare:

parents: [B, C]
prior_states: [state_B, state_C]
resulting_state: state_D
operation_type: merge

When conflicts remain, those conflicts become evidence-bearing objects rather than being silently resolved.

7. How it fits ACTS

I would not put ArtifactMutationV1 beside ActRecordV1 as a competing root object.

Instead:

ActRecordV1
└── domain_profile: "artifact.mutation.v1"
    └── profile_payload: ArtifactMutationV1

The mapping is straightforward:

Artifact mutation	ACTS
actor/application/device	actor and execution principals
capability	authority chain
prior state	input commitment
resulting state	effect commitment
semantic operation	declared act
parent mutation	caused-by / depends-on
signature	supporting evidence
checkpoint receipt	witness or finality evidence

The resulting act might read:

Application principal X, operating for actor Y under capability Z, declared that it transformed committed artifact state A into state B. This declaration was included in checkpoint C, witnessed by W, and anchored in finalized Actum transaction T.

That sentence is precise. It does not overclaim that:

* the signer was honest;
* the semantic description was true;
* no unrecorded state existed;
* the content was lawful or correct;
* the human mentally intended every consequence.

8. What MadeMark should contribute

MadeMark’s current design can become the first implementation profile.

MadeMark event
    → ArtifactMutationV1 or supporting observation
MadeMark feed
    → local ordered projection of the mutation graph
MadeMark signed checkpoint
    → MutationCheckpointV1
MadeMark witness response
    → CheckpointReceiptV1
.mmevidence
    → Act Bundle v1
MadeMark filesystem watcher
    → external-observation recorder mode

MadeMark-specific elements should remain adapters:

* root paths;
* filesystem event names;
* inode or file identifiers;
* Finder metadata;
* platform-specific observation details;
* current action enums;
* local identity-directory formats.

The abstraction keeps MadeMark useful without allowing its implementation choices to define ACTS.

9. Relationship to signed Git commits

A signed Git commit can be imported as evidence for an artifact mutation:

GitCommitEvidenceV1 {
    commit_oid
    tree_oid
    parent_oids[]
    signature
    repository_context?
}

The adapter would map:

Git parent tree  → prior state commitment
Git result tree  → resulting state commitment
Git author       → declared actor
Git signer       → signing principal
Git commit       → operation evidence

But ACTS should preserve the distinction between author and signer. Git often conflates provenance claims in ways that are acceptable for development workflows but inadequate for regulated or agentic execution.

A Git commit is therefore a good evidence profile, not the protocol itself.

10. The protocol’s core statement

I would express the generic specification this way:

The Artifact Mutation Protocol records a causally ordered graph of signed claims about transformations between committed artifact states. It binds each recorded transformation to its actor, execution environment, authority, prior state, resulting state, and supporting evidence. Checkpoints and independent receipts provide tamper evidence, existence evidence, and ordering assurance. The protocol does not claim completeness unless the recording environment supplies independently verifiable evidence that all mutation paths were mediated.

That is the implementation-independent abstraction behind MadeMark.

The central conceptual shift for ACTS is:

A file history is not fundamentally a sequence of commits. It is a graph of authorized, attributable state transitions whose claims have different epistemic strength.

This also suggests a clean hierarchy:

ActRecordV1
├── ArtifactMutationV1
├── ArtifactDerivationV1
├── ArtifactApprovalV1
├── ArtifactReleaseV1
└── ArtifactRevocationV1

MadeMark can then prove not only that a file changed, but how that mutation relates to approvals, derivations, exports, releases, and consequential acts elsewhere in the system.
