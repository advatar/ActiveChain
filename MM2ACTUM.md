I agree with the thesis, with one important refinement:

  > Actum should become the verification layer for consequential acts, while MadeMark remains a provenance recorder and composer above it.

  Actum should adopt MadeMark’s epistemology—how it represents history, evidence, uncertainty, approval, and causation—not simply copy MadeMark’s
  file-oriented schemas.

  ## What Actum already has

  Actum is much closer to this future than its “chain” framing suggests. It already has first-class:

  - stable principals with key rotation and recovery;
  - issuer-signed credentials and assurance levels;
  - attenuated capabilities for human and agent delegation;
  - canonical wallet intents;
  - deterministic APL policy evaluation;
  - versioned objects and state transitions;
  - public and privately proven computation;
  - receipts with inclusion, state, and finality evidence;
  - independently authenticated agent principals;
  - explicit chain, genesis, nonce, budget, and replay binding.

  That already answers much of:

  > Who was permitted to cause which state transition, under which policy, with which credentials, and what finalized?

  MadeMark is stronger in a different area:

  > How do we assemble a comprehensible, portable history around a real-world process—including events that never occur on-chain?

  That is what Actum should learn from.

  # What Actum should adopt from MadeMark

  ## 1. A first-class causal act graph

  Actum currently has canonical actions and finalized receipts, but a transaction receipt primarily answers what executed.

  It should also support an application-level ActRecordV1 answering why it executed:

  ActRecord
  ├── act ID
  ├── actor principal
  ├── acting device/application/agent
  ├── authority and capability
  ├── declared intent
  ├── interpreted intent
  ├── policy and policy decision
  ├── inputs and prior state
  ├── approvals
  ├── computation/model execution
  ├── resulting effects
  ├── supporting evidence
  ├── parent and caused acts
  └── finalization receipt

  MadeMark’s signed, hash-linked event feeds demonstrate the useful pattern:

  - stable event IDs;
  - ordered sequences;
  - previous-event hashes;
  - typed actors and devices;
  - context references;
  - evidence references;
  - approval references;
  - periodic signed checkpoints.

  Actum should generalize this from “events concerning a folder” into “acts concerning state.”

  The essential addition is causal relationships:

  - requestedBy
  - interpretedFrom
  - authorizedBy
  - approvedBy
  - evaluatedUnder
  - executedBy
  - produced
  - supersedes
  - compensatesFor
  - dependsOn

  A list of transactions is history. A graph of these relationships is provenance.

  ## 2. Separate fact, claim, observation, and inference

  MadeMark is deliberately conservative about evidence. It distinguishes recorded events from linked evidence and assigns confidence rather than
  pretending every observation is truth.

  Actum needs the same discipline. Every provenance assertion should identify its epistemic type:

   Type           Meaning
  ━━━━━━━━━━━━━  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   Fact           Directly verified by the protocol
  ─────────────  ───────────────────────────────────────────────────
   Attestation    Asserted and signed by a named issuer
  ─────────────  ───────────────────────────────────────────────────
   Observation    Reported by a device, service, oracle, or witness
  ─────────────  ───────────────────────────────────────────────────
   Declaration    Claimed by an actor about itself
  ─────────────  ───────────────────────────────────────────────────
   Inference      Derived by software or an AI model
  ─────────────  ───────────────────────────────────────────────────
   Decision       Output of an identified policy or authority
  ─────────────  ───────────────────────────────────────────────────
   Effect         State transition actually finalized

  For example:

  - “Principal P signed the action” is a protocol fact.
  - “P is Johan Sellström” is an issuer-backed identity claim.
  - “The human appeared attentive” is an observation or inference.
  - “Policy 3.2 permitted the payment” is a reproducible decision.
  - “Funds transferred” is a finalized effect.

  This would prevent Actum from confusing cryptographic validity with semantic truth.

  ## 3. Explicit assurance and confidence

  MadeMark’s most important conceptual lesson is that evidence must not silently upgrade itself.

  Actum already expresses this well in its credential architecture:

  self-issued assertion
  ≠ TLS-notarized observation
  ≠ authorized issuer credential
  ≠ EUDI PID

  That principle should apply across all provenance—not just identity.

  An Actum verifier should return structured conclusions such as:

  Actor authentication: cryptographically verified
  Human identity: EUDI PID verified
  Agent identity: registered principal
  Agent software: publisher-attested
  Model identity: self-declared
  Policy execution: deterministically reproduced
  Human approval: device-signed, user-presence asserted
  External input: issuer-attested
  Execution: finalized
  Intent fidelity: not independently established

  This is much more useful than one green “verified” badge.

  ## 4. Portable proof bundles

  MadeMark packages enough material for a third party to verify a history without access to the originating application or service.

  Actum should define an application-neutral portable act bundle containing:

  - canonical act records;
  - relevant principal states;
  - credentials or selective-disclosure presentations;
  - capability chains;
  - policy commitments and, where appropriate, policy bodies;
  - policy evaluation receipts;
  - input and output commitments;
  - approvals;
  - execution receipts;
  - inclusion/state/finality proofs;
  - revocation and credential-status evidence;
  - application-specific evidence;
  - verifier version requirements.

  The bundle should work offline and should not require an Actum account.

  That matters enormously for:

  - courts and disputes;
  - audits;
  - insurance;
  - cross-company handoffs;
  - regulatory retention;
  - long-term archives;
  - migrations to future infrastructure.

  A ledger API is not a durable provenance format. A self-contained verification package can be.

  ## 5. Local-first provenance with optional settlement

  MadeMark records useful history even when no external ledger is available. Actum should adopt that property for broader workflow provenance.

  Not every act belongs in consensus. Applications and agents should be able to maintain signed local or organizational act feeds, checkpoint
  them, and later:

  - anchor a digest;
  - settle a consequential transition;
  - publish selected disclosures;
  - prove predicates about the private history;
  - attach the history commitment to an Actum action.

  This creates a sensible hierarchy:

  High-volume local observations
          ↓
  Signed application checkpoints
          ↓
  Selective proofs and approvals
          ↓
  Consequential Actum action
          ↓
  Finalized Actum receipt

  Putting every AI tool call or workflow event on-chain would be expensive, privacy-destructive, and structurally unnecessary. Actum should
  finalize important commitments and effects, not ingest the entire world’s logs.

  ## 6. Checkpoint and witness semantics

  MadeMark separates three ideas that are frequently collapsed:

  - the author signed a history;
  - an independent witness observed a checkpoint;
  - an external ledger finalized a commitment.

  Actum should preserve these distinctions.

  An Actum finalization proves that a commitment entered finalized Actum state. It does not automatically prove that every off-chain claim inside
  that commitment is true.

  A provenance result should say:

  > This workflow bundle existed in this form by this finalized block, was signed by these principals, and contains these issuer attestations.

  It should not say:

  > Therefore every statement inside the bundle is objectively true.

  That semantic honesty will be crucial if Actum becomes trusted infrastructure.

  ## 7. Human approval as its own act

  MadeMark treats approvals as evidence-bearing events rather than Boolean fields. Actum should do the same.

  A meaningful approval should bind:

  - approver principal and credential assurance;
  - exact proposed act;
  - human-readable presentation commitment;
  - material effects;
  - policy version;
  - amount, recipient, resources, and limits;
  - requested and approved times;
  - user-presence method;
  - expiry;
  - any conditions;
  - whether AI generated or recommended the proposal.

  This distinction matters:

  AI proposed payment
  ≠ wallet displayed payment
  ≠ human approved exact payment
  ≠ policy authorized payment
  ≠ payment finalized

  All five can be cryptographically linked without pretending they are the same event.

  ## 8. Intent provenance

  This is the largest opportunity—but also the easiest place to overclaim.

  Actum should represent at least three different values:

  1. Expressed intent
     What the person actually supplied: text, speech commitment, signed UI selection, or structured request.

  2. Interpreted intent
     The structured action an agent or application derived from it.

  3. Authorized intent
     The exact canonical action the user, capability, and policy authorized.

  For example:

  Expressed:
  “Pay Anna the same amount as last month.”

  Interpreted:
  Transfer 4,200 SEK to account commitment X.

  Authorized:
  Canonical transfer T, including amount, recipient, fee ceiling,
  expiry, policy, and nonce.

  Executed:
  Receipt R finalized with effects E.

  The provenance record must retain the transformation between these stages. Otherwise a signature on the final transaction proves authorization
  but cannot explain whether the agent interpreted the user correctly.

  Actum should never claim to cryptographically prove a person’s internal mental intention. It can prove:

  - what was expressed;
  - how software interpreted it;
  - what was presented for approval;
  - what was authorized;
  - what executed.

  That is already transformative.

  ## 9. AI and agent execution manifests

  MadeMark records AI collaboration context, but Actum can make this much more rigorous.

  An agent act should be able to commit to:

  - agent principal;
  - operator or delegating principal;
  - model provider and model/version commitment;
  - system-policy commitment;
  - tool definitions and versions;
  - input commitments;
  - retrieved-data commitments;
  - tool calls;
  - outputs;
  - policy checks;
  - human intervention;
  - capability used;
  - resource and monetary budget;
  - execution environment attestation;
  - resulting external acts;
  - parent trace or workflow ID.

  Raw prompts and private chain-of-thought should not be required. The goal is a reproducible accountability boundary, not universal disclosure
  of hidden reasoning.

  For AI, the useful question is less “show every token of thought” and more:

  > Given these committed inputs, tools, policies, credentials, approvals, and model identity, what action was proposed and what effect was
  > authorized?

  ## 10. Multi-party feeds and conflict preservation

  MadeMark preserves independently signed participant histories and represents conflicts explicitly instead of rewriting them into a falsely
  unified narrative.

  Actum should adopt this for cross-organization workflows.

  A mortgage process might include independently controlled feeds from:

  - applicant;
  - bank;
  - identity issuer;
  - credit provider;
  - valuation service;
  - AI underwriting agent;
  - human reviewer;
  - payment rail;
  - regulator or auditor.

  No single participant should be able to silently rewrite the combined history. Contradictions should remain signed, attributable branches or
  claims.

  Consensus can establish ordering and final state. It cannot make disagreeing parties agree about off-chain facts.

  ## 11. Redaction and selective disclosure as core architecture

  MadeMark’s portable evidence model recognizes that complete histories often cannot be shared.

  Actum should support:

  - commitment-only references;
  - selective field disclosure;
  - credential predicate proofs;
  - policy-result proofs;
  - membership proofs for included acts;
  - non-disclosure of unrelated workflow branches;
  - pairwise or policy-scoped identifiers;
  - proof that required approvals occurred without revealing all participants;
  - proof that a process followed an approved policy without exposing proprietary policy details.

  This is essential for provenance to span healthcare, finance, employment, government, and autonomous agents.

  ## 12. Interoperability profiles, not replacement standards

  Your layered model is exactly right. Actum should not replace C2PA, W3C VC, EUDI, SCITT, in-toto, Sigstore, or industry evidence formats.

  It should define canonical adapters or profiles:

  C2PA manifest            → object transformation evidence
  W3C VC / EUDI credential → actor or role assurance
  in-toto / SLSA           → software supply-chain evidence
  SCITT receipt             → transparency evidence
  OpenTelemetry trace      → operational observation
  Actum capability         → delegated authority
  APL decision             → policy authorization
  Actum receipt            → finalized effect

  Actum’s role is to bind these heterogeneous proofs into one verifiable act—not absorb every standard into consensus.

  # What Actum should not adopt

  Several MadeMark details should remain outside Actum’s core:

  - filesystem paths and folder-root concepts;
  - MadeMark’s local self-declared identity directory;
  - arbitrary string detail maps;
  - application-specific action enums;
  - UI summaries as authoritative semantics;
  - complete raw workflow logs;
  - C2PA parsing inside consensus;
  - model prompts or private reasoning;
  - provider-specific evidence formats;
  - a universal ontology of every possible human act.

  Actum’s own principal, credential, capability, policy, and receipt models are already stronger than MadeMark’s local identity model. The flow
  should generally be MadeMark adopting Actum identity and authority—not Actum adopting MadeMark’s self-declared names.

  # Where the protocol boundary should sit

  Actum’s architecture guide already gives the correct warning: every consensus-level feature brings canonical encoding, boundedness,
  compatibility, formal modeling, migration, and audit obligations.

  Therefore I would divide the design into three layers:

  ### Consensus core

  Keep only what validators must agree upon:

  - act commitment;
  - actor and authority;
  - policy commitment;
  - input-state commitment;
  - declared effects;
  - execution result;
  - final receipt;
  - optional parent/root provenance commitment.

  ### Actum provenance protocol

  A canonical, independently verifiable format outside consensus:

  - causal act graph;
  - intent transformations;
  - approvals;
  - evidence and assurance;
  - agent/model/tool manifests;
  - external standard references;
  - selective disclosure;
  - portable bundles.

  ### Domain profiles

  Schemas for specific workflows:

  - AI agent action;
  - payment;
  - mortgage decision;
  - clinical decision;
  - software release;
  - media lifecycle;
  - procurement;
  - legal approval;
  - autonomous-device action.

  Only stable primitives that multiple unrelated profiles require should graduate into the consensus protocol.

  # The defining abstraction

  I would define Actum’s central abstraction approximately as:

  > A verifiable act is a canonical claim that an authenticated principal, acting under specified authority and policy, transformed committed
  > inputs into declared effects, with independently checkable evidence linking intent, authorization, execution, and finality.

  That is materially bigger than blockchain transactions and materially more useful than file provenance.

  The product-level question would no longer be:

  > “Is this object authentic?”

  It becomes:

  > “What caused this state to exist, who had authority to cause it, what evidence and policy justified it, and can I independently verify the
  > answer?”

  That is a credible infrastructure layer for the coming agent economy.

  ## My recommended first move

  Before adding more consensus semantics, Actum should specify an off-chain Actum Act Bundle v1 and implement one end-to-end profile:

  Human request
  → agent interpretation
  → capability check
  → policy decision
  → exact human approval
  → Actum action
  → finalized effect
  → portable offline-verifiable bundle

  Use a real payment or controlled object transfer, include an externally issued identity credential, and make every assurance boundary visible
  in the verifier.

  That single vertical slice would demonstrate identity, intent, delegation, policy, AI agency, execution, and finality together. It would also
  reveal which fields truly deserve promotion into Actum’s protocol core.

  MadeMark’s greatest contribution to Actum is therefore not file provenance. It is the lesson that a trustworthy history must preserve who
  claimed what, based on which evidence, with what confidence, under which authority—and must remain independently understandable after the
  originating application disappears.

