#![forbid(unsafe_code)]

//! Transparent STARK constraints over the canonical CashAIR execution trace.
//!
//! This first algebraic tranche proves counter progression, outcome booleanity, failed-row
//! atomicity, row count, and pre/post Coin Cell root binding. The cryptographic and membership
//! tables required by `CASH.md` remain separate, explicit roadmap gates.

use activechain_cash_kernel::{AuthenticatedCashAirProofV1, CashAirProof};
use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
    decode_envelope, encode_envelope,
};
use activechain_protocol_types::{CoinCellSetRoot, Digest384};
use winterfell::{
    AcceptableOptions, Air, AirContext, Assertion, AuxRandElements, BatchingMethod,
    CompositionPoly, CompositionPolyTrace, ConstraintCompositionCoefficients,
    DefaultConstraintCommitment, DefaultConstraintEvaluator, DefaultTraceLde, EvaluationFrame,
    FieldExtension, PartitionOptions, Proof, ProofOptions, Prover, StarkDomain, Trace, TraceInfo,
    TracePolyTable, TraceTable, TransitionConstraintDegree,
    crypto::{DefaultRandomCoin, MerkleTree, hashers::Blake3_256},
    math::{FieldElement, ToElements, fields::f128::BaseElement},
    matrix::ColMatrix,
};

mod session;
mod shake;
pub use session::{
    CashSessionProofError, CashSessionStarkProof, prove_authorized_session, prove_session_budget,
    verify_session_budget,
};
pub use shake::{
    AuthenticatedCashShakeStarkProof, BatchedShake256StarkProof,
    MAX_AUTHENTICATED_SHAKE_PERMUTATIONS_PER_CHUNK,
    MAX_AUTHENTICATED_SHAKE_PERMUTATIONS_PER_COMPOSITE, MAX_CASH_SHAKE_MESSAGE, Shake256StarkProof,
    authenticated_cash_shake_permutation_count, prove_authenticated_cash_shake, prove_shake256_384,
    prove_shake256_384_batch, verify_authenticated_cash_shake, verify_shake256_384,
    verify_shake256_384_batch,
};

/// Registered CashAIR suite identifier. The composite suite explicitly consists
/// of this Winterfell parent plus the SHAKE permutation suite below; callers must
/// persist this identifier with any proof envelope.
pub const CASH_AIR_PARENT_SUITE_ID: u32 = 0xCA50_0101;
pub const CASH_AIR_COMPOSITE_SUITE_ID: u32 = 0xCA50_0201;
pub const MAX_CASH_AIR_PROOF_BYTES: usize = 1 << 20;
pub const MAX_CASH_AIR_COMPOSITE_BYTES: usize = 8 << 20;

/// Canonical byte envelope for the Winterfell CashAIR parent proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CashAirReceiptV1 {
    pub suite_id: u32,
    pub trace: CashAirProof,
    pub proof_bytes: Vec<u8>,
}

impl CashAirReceiptV1 {
    pub fn new(trace: CashAirProof, proof_bytes: Vec<u8>) -> Result<Self, &'static str> {
        if proof_bytes.is_empty() || proof_bytes.len() > MAX_CASH_AIR_PROOF_BYTES {
            return Err("CashAIR proof byte length is outside the registered bound");
        }
        Ok(Self { suite_id: CASH_AIR_PARENT_SUITE_ID, trace, proof_bytes })
    }

    pub fn verify_bytes(bytes: &[u8]) -> Result<(), &'static str> {
        let envelope: Self = decode_envelope(bytes).map_err(|_| "malformed CashAIR receipt")?;
        if envelope.suite_id != CASH_AIR_PARENT_SUITE_ID {
            return Err("unregistered CashAIR receipt suite");
        }
        verify_bytes(&envelope.proof_bytes, &envelope.trace)
    }

    pub fn encode_envelope(&self) -> Result<Vec<u8>, EncodeError> {
        encode_envelope(self)
    }
}

impl CanonicalEncode for CashAirReceiptV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.suite_id.encode(e)?;
        self.trace.encode(e)?;
        e.write_bytes(&self.proof_bytes, MAX_CASH_AIR_PROOF_BYTES)
    }
}
impl CanonicalDecode for CashAirReceiptV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let suite_id = u32::decode(d)?;
        if suite_id != CASH_AIR_PARENT_SUITE_ID {
            return Err(DecodeError::InvalidValue("unregistered CashAIR receipt suite"));
        }
        let trace = CashAirProof::decode(d)?;
        let proof_bytes = d.read_bytes(MAX_CASH_AIR_PROOF_BYTES)?.to_vec();
        if proof_bytes.is_empty() {
            return Err(DecodeError::InvalidValue("empty CashAIR proof"));
        }
        Ok(Self { suite_id, trace, proof_bytes })
    }
}
impl CanonicalType for CashAirReceiptV1 {
    const TYPE_TAG: u16 = 0x00a0;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 4 + CashAirProof::MAX_ENCODED_LEN + 4 + MAX_CASH_AIR_PROOF_BYTES;
}

/// Canonical byte envelope for an authenticated parent plus SHAKE mutation proofs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedCashAirReceiptV1 {
    pub suite_id: u32,
    pub trace: AuthenticatedCashAirProofV1,
    pub parent_proof_bytes: Vec<u8>,
    pub mutation_proof_bytes: Vec<Option<Vec<u8>>>,
}

impl AuthenticatedCashAirReceiptV1 {
    pub fn new(
        trace: AuthenticatedCashAirProofV1,
        parent_proof_bytes: Vec<u8>,
        mutation_proof_bytes: Vec<Option<Vec<u8>>>,
    ) -> Result<Self, &'static str> {
        if parent_proof_bytes.is_empty() || mutation_proof_bytes.len() != trace.mutations().len() {
            return Err("inconsistent authenticated CashAIR receipt");
        }
        Ok(Self {
            suite_id: CASH_AIR_COMPOSITE_SUITE_ID,
            trace,
            parent_proof_bytes,
            mutation_proof_bytes,
        })
    }

    pub fn encode_envelope(&self) -> Result<Vec<u8>, EncodeError> {
        encode_envelope(self)
    }

    pub fn verify_bytes(bytes: &[u8]) -> Result<(), &'static str> {
        let envelope: Self = decode_envelope(bytes).map_err(|_| "malformed authenticated CashAIR receipt")?;
        if envelope.suite_id != CASH_AIR_COMPOSITE_SUITE_ID {
            return Err("unregistered authenticated CashAIR suite");
        }
        let parent = Proof::from_bytes(&envelope.parent_proof_bytes)
            .map_err(|_| "malformed authenticated CashAIR parent proof")?;
        let public = authenticated_public_inputs(&envelope.trace)?;
        let mut mutation_shake = Vec::with_capacity(envelope.mutation_proof_bytes.len());
        for bytes in envelope.mutation_proof_bytes {
            mutation_shake.push(bytes.map(|value| {
                crate::shake::AuthenticatedCashShakeStarkProof::decode_bytes(&value)
            }).transpose()?);
        }
        verify_authenticated_composite(
            AuthenticatedCashCompositeStarkProof {
                parent: CashStarkProof { proof: parent, public },
                mutation_shake,
            },
            &envelope.trace,
        )
    }
}

impl CanonicalEncode for AuthenticatedCashAirReceiptV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.suite_id.encode(e)?;
        self.trace.encode(e)?;
        e.write_bytes(&self.parent_proof_bytes, MAX_CASH_AIR_PROOF_BYTES)?;
        e.write_length(self.mutation_proof_bytes.len(), 1024)?;
        for proof in &self.mutation_proof_bytes {
            match proof {
                None => 0_u8.encode(e)?,
                Some(bytes) => {
                    1_u8.encode(e)?;
                    e.write_bytes(bytes, MAX_CASH_AIR_PROOF_BYTES)?;
                }
            }
        }
        Ok(())
    }
}
impl CanonicalDecode for AuthenticatedCashAirReceiptV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let suite_id = u32::decode(d)?;
        if suite_id != CASH_AIR_COMPOSITE_SUITE_ID {
            return Err(DecodeError::InvalidValue("unregistered authenticated CashAIR suite"));
        }
        let trace = AuthenticatedCashAirProofV1::decode(d)?;
        let parent_proof_bytes = d.read_bytes(MAX_CASH_AIR_PROOF_BYTES)?.to_vec();
        if parent_proof_bytes.is_empty() {
            return Err(DecodeError::InvalidValue("empty authenticated parent proof"));
        }
        let count = d.read_length(1024)?;
        if count != trace.mutations().len() {
            return Err(DecodeError::InvalidValue("authenticated proof row count mismatch"));
        }
        let mut mutation_proof_bytes = Vec::with_capacity(count);
        for _ in 0..count {
            mutation_proof_bytes.push(match u8::decode(d)? {
                0 => None,
                1 => Some(d.read_bytes(MAX_CASH_AIR_PROOF_BYTES)?.to_vec()),
                _ => return Err(DecodeError::InvalidValue("invalid authenticated proof option")),
            });
        }
        Ok(Self { suite_id, trace, parent_proof_bytes, mutation_proof_bytes })
    }
}
impl CanonicalType for AuthenticatedCashAirReceiptV1 {
    const TYPE_TAG: u16 = 0x00a1;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 4 + AuthenticatedCashAirProofV1::MAX_ENCODED_LEN
        + 4 + MAX_CASH_AIR_PROOF_BYTES + 2
        + 1024 * (1 + 4 + MAX_CASH_AIR_PROOF_BYTES);
}

const TRACE_WIDTH: usize = 15;
const STEP: usize = 0;
const APPLIED: usize = 1;
const REJECTED: usize = 2;
const ACTIVE: usize = 3;
const ACCEPTED: usize = 4;
const ROOT_0: usize = 5;
const INPUT_VALUE: usize = 8;
const OUTPUT_VALUE: usize = 9;
const FEE: usize = 10;
const AUTHENTICATED_MODE: usize = 11;
const AUTHENTICATED_ROOT_0: usize = 12;

#[derive(Clone, Debug)]
pub struct CashStarkPublicInputs {
    pre_root: [BaseElement; 3],
    post_root: [BaseElement; 3],
    applied: BaseElement,
    rejected: BaseElement,
    authenticated_mode: BaseElement,
    authenticated_pre_root: [BaseElement; 3],
    authenticated_post_root: [BaseElement; 3],
    authenticated_row_roots: Vec<[BaseElement; 3]>,
}

impl ToElements<BaseElement> for CashStarkPublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        self.pre_root
            .into_iter()
            .chain(self.post_root)
            .chain([self.applied, self.rejected, self.authenticated_mode])
            .chain(self.authenticated_pre_root)
            .chain(self.authenticated_post_root)
            .chain(self.authenticated_row_roots.iter().flatten().copied())
            .collect()
    }
}

pub struct CashAir {
    context: AirContext<BaseElement>,
    public: CashStarkPublicInputs,
}

impl Air for CashAir {
    type BaseField = BaseElement;
    type PublicInputs = CashStarkPublicInputs;

    fn new(trace_info: TraceInfo, public: Self::PublicInputs, options: ProofOptions) -> Self {
        assert_eq!(trace_info.width(), TRACE_WIDTH);
        let mut degrees = vec![
            TransitionConstraintDegree::new(1),
            TransitionConstraintDegree::new(2),
            TransitionConstraintDegree::new(2),
            TransitionConstraintDegree::new(2),
            TransitionConstraintDegree::new(2),
            TransitionConstraintDegree::new(2),
            TransitionConstraintDegree::new(2),
            TransitionConstraintDegree::new(2),
            TransitionConstraintDegree::new(2),
            TransitionConstraintDegree::new(2),
            TransitionConstraintDegree::new(2),
            TransitionConstraintDegree::new(2),
            TransitionConstraintDegree::new(2),
            TransitionConstraintDegree::new(2),
            TransitionConstraintDegree::new(1),
            TransitionConstraintDegree::new(2),
            TransitionConstraintDegree::new(2),
            TransitionConstraintDegree::new(2),
        ];
        degrees[10] = TransitionConstraintDegree::new(1);
        let assertions = 22 + public.authenticated_row_roots.len() * 3;
        Self { context: AirContext::new(trace_info, degrees, assertions, options), public }
    }

    fn evaluate_transition<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        _periodic_values: &[E],
        result: &mut [E],
    ) {
        let current = frame.current();
        let next = frame.next();
        let one = E::ONE;
        result[0] = next[STEP] - current[STEP] - next[ACTIVE];
        result[1] = next[APPLIED] - current[APPLIED] - next[ACTIVE] * next[ACCEPTED];
        result[2] = next[REJECTED] - current[REJECTED] - next[ACTIVE] * (one - next[ACCEPTED]);
        result[3] = next[ACTIVE] * (next[ACTIVE] - one);
        result[4] = next[ACTIVE] * (one - current[ACTIVE]);
        result[5] = next[ACCEPTED] * (next[ACCEPTED] - one);
        result[6] = next[ACCEPTED] * (one - next[ACTIVE]);
        let rejected = one - next[ACCEPTED];
        for limb in 0..3 {
            result[7 + limb] = rejected * (next[ROOT_0 + limb] - current[ROOT_0 + limb]);
        }
        result[10] = next[INPUT_VALUE] - next[OUTPUT_VALUE] - next[FEE];
        result[11] = rejected * next[INPUT_VALUE];
        result[12] = rejected * next[OUTPUT_VALUE];
        result[13] = rejected * next[FEE];
        result[14] = next[AUTHENTICATED_MODE] - current[AUTHENTICATED_MODE];
        for limb in 0..3 {
            result[15 + limb] = rejected
                * (next[AUTHENTICATED_ROOT_0 + limb] - current[AUTHENTICATED_ROOT_0 + limb]);
        }
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let last = self.trace_length() - 1;
        let mut assertions = vec![
            Assertion::single(STEP, 0, BaseElement::ZERO),
            Assertion::single(APPLIED, 0, BaseElement::ZERO),
            Assertion::single(REJECTED, 0, BaseElement::ZERO),
            Assertion::single(ACTIVE, 0, BaseElement::ONE),
            Assertion::single(ACCEPTED, 0, BaseElement::ZERO),
            Assertion::single(APPLIED, last, self.public.applied),
            Assertion::single(REJECTED, last, self.public.rejected),
            Assertion::single(ACTIVE, last, BaseElement::ZERO),
            Assertion::single(AUTHENTICATED_MODE, 0, self.public.authenticated_mode),
            Assertion::single(AUTHENTICATED_MODE, last, self.public.authenticated_mode),
        ];
        for limb in 0..3 {
            assertions.push(Assertion::single(ROOT_0 + limb, 0, self.public.pre_root[limb]));
            assertions.push(Assertion::single(ROOT_0 + limb, last, self.public.post_root[limb]));
        }
        for limb in 0..3 {
            assertions.push(Assertion::single(
                AUTHENTICATED_ROOT_0 + limb,
                0,
                self.public.authenticated_pre_root[limb],
            ));
            assertions.push(Assertion::single(
                AUTHENTICATED_ROOT_0 + limb,
                last,
                self.public.authenticated_post_root[limb],
            ));
        }
        for (offset, root) in self.public.authenticated_row_roots.iter().enumerate() {
            for (limb, value) in root.iter().copied().enumerate() {
                assertions.push(Assertion::single(AUTHENTICATED_ROOT_0 + limb, offset + 1, value));
            }
        }
        assertions
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }
}

struct CashProver {
    options: ProofOptions,
}

impl Prover for CashProver {
    type BaseField = BaseElement;
    type Air = CashAir;
    type Trace = TraceTable<BaseElement>;
    type HashFn = Blake3_256<BaseElement>;
    type VC = MerkleTree<Self::HashFn>;
    type RandomCoin = DefaultRandomCoin<Self::HashFn>;
    type TraceLde<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultTraceLde<E, Self::HashFn, Self::VC>;
    type ConstraintCommitment<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintCommitment<E, Self::HashFn, Self::VC>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintEvaluator<'a, Self::Air, E>;

    fn get_pub_inputs(&self, trace: &Self::Trace) -> CashStarkPublicInputs {
        let last = trace.length() - 1;
        let authenticated_mode = trace.get(AUTHENTICATED_MODE, 0);
        let mut authenticated_row_roots = Vec::new();
        if authenticated_mode == BaseElement::ONE {
            let mut row = 1;
            while row < last && trace.get(ACTIVE, row) == BaseElement::ONE {
                authenticated_row_roots
                    .push(core::array::from_fn(|limb| trace.get(AUTHENTICATED_ROOT_0 + limb, row)));
                row += 1;
            }
        }
        CashStarkPublicInputs {
            pre_root: [trace.get(ROOT_0, 0), trace.get(ROOT_0 + 1, 0), trace.get(ROOT_0 + 2, 0)],
            post_root: [
                trace.get(ROOT_0, last),
                trace.get(ROOT_0 + 1, last),
                trace.get(ROOT_0 + 2, last),
            ],
            applied: trace.get(APPLIED, last),
            rejected: trace.get(REJECTED, last),
            authenticated_mode,
            authenticated_pre_root: core::array::from_fn(|limb| {
                trace.get(AUTHENTICATED_ROOT_0 + limb, 0)
            }),
            authenticated_post_root: core::array::from_fn(|limb| {
                trace.get(AUTHENTICATED_ROOT_0 + limb, last)
            }),
            authenticated_row_roots,
        }
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }

    fn new_trace_lde<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        trace_info: &TraceInfo,
        main_trace: &ColMatrix<Self::BaseField>,
        domain: &StarkDomain<Self::BaseField>,
        partition_options: PartitionOptions,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>) {
        DefaultTraceLde::new(trace_info, main_trace, domain, partition_options)
    }

    fn build_constraint_commitment<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        trace: CompositionPolyTrace<E>,
        columns: usize,
        domain: &StarkDomain<Self::BaseField>,
        partitions: PartitionOptions,
    ) -> (Self::ConstraintCommitment<E>, CompositionPoly<E>) {
        DefaultConstraintCommitment::new(trace, columns, domain, partitions)
    }

    fn new_evaluator<'a, E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        air: &'a Self::Air,
        randomness: Option<AuxRandElements<E>>,
        coefficients: ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, randomness, coefficients)
    }
}

pub struct CashStarkProof {
    proof: Proof,
    public: CashStarkPublicInputs,
}

pub struct AuthenticatedCashCompositeStarkProof {
    parent: CashStarkProof,
    mutation_shake: Vec<Option<AuthenticatedCashShakeStarkProof>>,
}

impl AuthenticatedCashCompositeStarkProof {
    #[must_use]
    pub const fn suite_id() -> u32 {
        CASH_AIR_COMPOSITE_SUITE_ID
    }
    #[must_use]
    pub fn mutation_proof_count(&self) -> usize {
        self.mutation_shake.iter().filter(|proof| proof.is_some()).count()
    }
}

impl CashStarkProof {
    #[must_use]
    pub const fn suite_id() -> u32 {
        CASH_AIR_PARENT_SUITE_ID
    }
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.proof.to_bytes()
    }
}

pub fn prove(trace: &CashAirProof) -> Result<CashStarkProof, &'static str> {
    let execution = build_trace(trace, None)?;
    let public = public_inputs(trace.public())?;
    let prover = CashProver { options: proof_options() };
    let proof = prover.prove(execution).map_err(|_| "CashAIR proving failed")?;
    Ok(CashStarkProof { proof, public })
}

pub fn prove_authenticated_parent(
    trace: &AuthenticatedCashAirProofV1,
) -> Result<CashStarkProof, &'static str> {
    let execution = build_trace(trace.execution(), Some(trace))?;
    let public = authenticated_public_inputs(trace)?;
    let prover = CashProver { options: proof_options() };
    let proof = prover.prove(execution).map_err(|_| "authenticated CashAIR proving failed")?;
    Ok(CashStarkProof { proof, public })
}

pub fn prove_authenticated_composite(
    trace: &AuthenticatedCashAirProofV1,
) -> Result<AuthenticatedCashCompositeStarkProof, &'static str> {
    enforce_authenticated_composite_permutation_limit(trace)?;
    let parent = prove_authenticated_parent(trace)?;
    let mut mutation_shake = Vec::with_capacity(trace.mutations().len());
    for mutation in trace.mutations() {
        mutation_shake.push(mutation.as_ref().map(prove_authenticated_cash_shake).transpose()?);
    }
    Ok(AuthenticatedCashCompositeStarkProof { parent, mutation_shake })
}

pub fn verify_authenticated_composite(
    proof: AuthenticatedCashCompositeStarkProof,
    trace: &AuthenticatedCashAirProofV1,
) -> Result<(), &'static str> {
    enforce_authenticated_composite_permutation_limit(trace)?;
    if proof.mutation_shake.len() != trace.mutations().len() {
        return Err("authenticated CashAIR composite row count mismatch");
    }
    let expected_public = authenticated_public_inputs(trace)?;
    if proof.parent.public.to_elements() != expected_public.to_elements() {
        return Err("authenticated CashAIR parent public inputs mismatch");
    }
    verify_trace_structure(proof.parent)?;
    for (row_proof, mutation) in proof.mutation_shake.iter().zip(trace.mutations()) {
        match (row_proof, mutation) {
            (Some(row_proof), Some(mutation)) => {
                verify_authenticated_cash_shake(row_proof, mutation)?;
            }
            (None, None) => {}
            _ => return Err("authenticated CashAIR composite row/proof mismatch"),
        }
    }
    Ok(())
}

fn enforce_authenticated_composite_permutation_limit(
    trace: &AuthenticatedCashAirProofV1,
) -> Result<usize, &'static str> {
    let total = trace.mutations().iter().flatten().try_fold(0_usize, |total, mutation| {
        total
            .checked_add(authenticated_cash_shake_permutation_count(mutation)?)
            .ok_or("authenticated CashAIR permutation count overflow")
    })?;
    ensure_authenticated_composite_permutation_total(total)
}

fn ensure_authenticated_composite_permutation_total(total: usize) -> Result<usize, &'static str> {
    if total > MAX_AUTHENTICATED_SHAKE_PERMUTATIONS_PER_COMPOSITE {
        Err("authenticated CashAIR composite exceeds permutation budget")
    } else {
        Ok(total)
    }
}

/// Verifies the bounded CashAIR trace structure. This is not a complete
/// Coin Cell validity proof: membership and cryptographic tables remain outside
/// this tranche and are enforced by the authenticated composite path.
pub fn verify_trace_structure(proof: CashStarkProof) -> Result<(), &'static str> {
    winterfell::verify::<
        CashAir,
        Blake3_256<BaseElement>,
        DefaultRandomCoin<Blake3_256<BaseElement>>,
        MerkleTree<Blake3_256<BaseElement>>,
    >(proof.proof, proof.public, &AcceptableOptions::MinConjecturedSecurity(100))
    .map_err(|_| "CashAIR verification failed")
}

/// Compatibility alias; new callers should use `verify_trace_structure`.
pub fn verify(proof: CashStarkProof) -> Result<(), &'static str> {
    verify_trace_structure(proof)
}

pub fn verify_bytes(bytes: &[u8], trace: &CashAirProof) -> Result<(), &'static str> {
    let proof = Proof::from_bytes(bytes).map_err(|_| "malformed CashAIR STARK proof")?;
    verify_trace_structure(CashStarkProof { proof, public: public_inputs(trace.public())? })
}

fn build_trace(
    proof: &CashAirProof,
    authenticated: Option<&AuthenticatedCashAirProofV1>,
) -> Result<TraceTable<BaseElement>, &'static str> {
    if authenticated.is_some_and(|value| value.mutations().len() != proof.rows().len()) {
        return Err("authenticated CashAIR mutation count mismatch");
    }
    let length = (proof.rows().len() + 2).next_power_of_two().max(8);
    let mut trace = TraceTable::new(TRACE_WIDTH, length);
    let mut current_root = root_elements(proof.public().pre_cells())?;
    trace.set(STEP, 0, BaseElement::ZERO);
    trace.set(APPLIED, 0, BaseElement::ZERO);
    trace.set(REJECTED, 0, BaseElement::ZERO);
    trace.set(ACTIVE, 0, BaseElement::ONE);
    trace.set(ACCEPTED, 0, BaseElement::ZERO);
    trace.set(INPUT_VALUE, 0, BaseElement::ZERO);
    trace.set(OUTPUT_VALUE, 0, BaseElement::ZERO);
    trace.set(FEE, 0, BaseElement::ZERO);
    set_root(&mut trace, 0, current_root);
    let authenticated_mode = BaseElement::new(u128::from(authenticated.is_some()));
    let mut authenticated_root =
        authenticated
            .map(|value| digest_elements(value.pre_root().into_digest()))
            .transpose()?
            .unwrap_or(current_root);
    trace.set(AUTHENTICATED_MODE, 0, authenticated_mode);
    set_authenticated_root(&mut trace, 0, authenticated_root);
    let mut applied = 0_u64;
    let mut rejected = 0_u64;
    for (offset, row) in proof.rows().iter().enumerate() {
        let index = offset + 1;
        if row.accepted() {
            applied += 1;
        } else {
            rejected += 1;
        }
        current_root = root_elements(row.post_cells())?;
        trace.set(STEP, index, BaseElement::new(index as u128));
        trace.set(APPLIED, index, BaseElement::new(applied.into()));
        trace.set(REJECTED, index, BaseElement::new(rejected.into()));
        trace.set(ACTIVE, index, BaseElement::ONE);
        trace.set(ACCEPTED, index, BaseElement::new(u128::from(row.accepted())));
        for value in [row.input_value(), row.output_value(), row.fee()] {
            if u128::from(value) > u64::MAX as u128 {
                return Err("CashAIR value exceeds the 64-bit range");
            }
        }
        trace.set(INPUT_VALUE, index, BaseElement::new(row.input_value().into()));
        trace.set(OUTPUT_VALUE, index, BaseElement::new(row.output_value().into()));
        trace.set(FEE, index, BaseElement::new(row.fee().into()));
        set_root(&mut trace, index, current_root);
        trace.set(AUTHENTICATED_MODE, index, authenticated_mode);
        if let Some(authenticated) = authenticated {
            match (row.accepted(), &authenticated.mutations()[offset]) {
                (true, Some(mutation)) => {
                    authenticated_root = digest_elements(mutation.post_root().into_digest())?
                }
                (false, None) => {}
                _ => return Err("authenticated CashAIR row/mutation mismatch"),
            }
        } else {
            authenticated_root = current_root;
        }
        set_authenticated_root(&mut trace, index, authenticated_root);
    }
    for index in proof.rows().len() + 1..length {
        trace.set(STEP, index, BaseElement::new(proof.rows().len() as u128));
        trace.set(APPLIED, index, BaseElement::new(applied.into()));
        trace.set(REJECTED, index, BaseElement::new(rejected.into()));
        trace.set(ACTIVE, index, BaseElement::ZERO);
        trace.set(ACCEPTED, index, BaseElement::ZERO);
        trace.set(INPUT_VALUE, index, BaseElement::ZERO);
        trace.set(OUTPUT_VALUE, index, BaseElement::ZERO);
        trace.set(FEE, index, BaseElement::ZERO);
        set_root(&mut trace, index, current_root);
        trace.set(AUTHENTICATED_MODE, index, authenticated_mode);
        set_authenticated_root(&mut trace, index, authenticated_root);
    }
    Ok(trace)
}

fn public_inputs(public: &activechain_cash_kernel::CashAirPublicInputs) -> Result<CashStarkPublicInputs, &'static str> {
    Ok(CashStarkPublicInputs {
        pre_root: root_elements(public.pre_cells())?,
        post_root: root_elements(public.post_cells())?,
        applied: BaseElement::new(public.applied().into()),
        rejected: BaseElement::new(public.rejected().into()),
        authenticated_mode: BaseElement::ZERO,
        authenticated_pre_root: root_elements(public.pre_cells())?,
        authenticated_post_root: root_elements(public.post_cells())?,
        authenticated_row_roots: Vec::new(),
    })
}

fn authenticated_public_inputs(proof: &AuthenticatedCashAirProofV1) -> Result<CashStarkPublicInputs, &'static str> {
    let mut public = public_inputs(proof.execution().public())?;
    public.authenticated_mode = BaseElement::ONE;
    public.authenticated_pre_root = digest_elements(proof.pre_root().into_digest())?;
    public.authenticated_post_root = digest_elements(proof.post_root().into_digest())?;
    let mut current = public.authenticated_pre_root;
    public.authenticated_row_roots = Vec::with_capacity(proof.mutations().len());
    for mutation in proof.mutations() {
        if let Some(mutation) = mutation {
            current = digest_elements(mutation.post_root().into_digest())?;
        }
        public.authenticated_row_roots.push(current);
    }
    Ok(public)
}

fn root_elements(root: CoinCellSetRoot) -> Result<[BaseElement; 3], &'static str> {
    digest_elements(root.into_digest())
}

fn digest_elements(digest: Digest384) -> Result<[BaseElement; 3], &'static str> {
    let bytes = digest.as_bytes();
    let mut result = [BaseElement::ZERO; 3];
    for (index, slot) in result.iter_mut().enumerate() {
        let mut limb = [0_u8; 16];
        limb.copy_from_slice(&bytes[index * 16..(index + 1) * 16]);
        // The f128 modulus is slightly below 2^128. Rejecting rather than
        // reducing keeps the digest-to-field encoding injective.
        let value = u128::from_be_bytes(limb);
        const F128_MODULUS: u128 = u128::MAX - (45_u128 << 40) + 2;
        if value >= F128_MODULUS {
            return Err("digest limb is not canonically representable in CashAIR field");
        }
        *slot = BaseElement::new(value);
    }
    Ok(result)
}

fn set_authenticated_root(trace: &mut TraceTable<BaseElement>, row: usize, root: [BaseElement; 3]) {
    for (limb, value) in root.into_iter().enumerate() {
        trace.set(AUTHENTICATED_ROOT_0 + limb, row, value);
    }
}

fn set_root(trace: &mut TraceTable<BaseElement>, row: usize, root: [BaseElement; 3]) {
    for (limb, value) in root.into_iter().enumerate() {
        trace.set(ROOT_0 + limb, row, value);
    }
}

fn proof_options() -> ProofOptions {
    ProofOptions::new(
        40,
        8,
        16,
        FieldExtension::None,
        8,
        31,
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    )
}

#[cfg(test)]
mod tests {
    use activechain_cash_kernel::{
        CashLedger, CashTransferV1, CoinMintTransition, CoinTransfer, EpochEconomicsTransition,
        GenesisAllocation, GenesisEconomy, NativeAssetDefinition, prove_authenticated_cash_air,
        prove_cash_air,
    };
    use activechain_protocol_types::{ChainId, CoinCellId, Digest384, PrincipalId};

    use super::{
        AuthenticatedCashAirReceiptV1, AuthenticatedCashCompositeStarkProof, BaseElement,
        CashAirReceiptV1, CashStarkProof,
        CASH_AIR_COMPOSITE_SUITE_ID, CASH_AIR_PARENT_SUITE_ID, prove,
        prove_authenticated_composite, prove_authenticated_parent, verify,
        verify_authenticated_composite,
    };
    use activechain_canonical_codec::decode_envelope;

    fn digest(byte: u8) -> Digest384 {
        Digest384::new([byte; 48])
    }

    #[test]
    fn registered_suite_ids_are_distinct() {
        assert_ne!(CASH_AIR_PARENT_SUITE_ID, CASH_AIR_COMPOSITE_SUITE_ID);
        assert_ne!(CASH_AIR_PARENT_SUITE_ID, crate::shake::CASH_AIR_SHAKE_SUITE_ID);
        assert_eq!(CashStarkProof::suite_id(), CASH_AIR_PARENT_SUITE_ID);
        assert_eq!(AuthenticatedCashCompositeStarkProof::suite_id(), CASH_AIR_COMPOSITE_SUITE_ID);
    }

    fn principal(byte: u8) -> PrincipalId {
        PrincipalId::new(digest(byte))
    }

    fn settlement(pre_supply: u128, issuance: u128, epoch: u64) -> EpochEconomicsTransition {
        EpochEconomicsTransition::new(
            epoch,
            pre_supply,
            5_000,
            0,
            0,
            issuance,
            issuance,
            issuance * 2,
            0,
            digest(20),
            digest(21),
            digest(22),
            digest(23),
            pre_supply + issuance,
        )
        .unwrap()
    }

    fn fixture() -> (CashLedger, CashTransferV1) {
        let definition = NativeAssetDefinition::new(
            ChainId::new(digest(1)),
            b"ACT".to_vec(),
            18,
            1_000,
            150,
            digest(2),
            digest(3),
            digest(4),
        )
        .unwrap();
        let economy = GenesisEconomy::new(
            definition,
            vec![
                GenesisAllocation::new(principal(10), 700, 100).unwrap(),
                GenesisAllocation::new(principal(12), 100, 0).unwrap(),
            ],
            100,
        )
        .unwrap();
        let mut ledger = CashLedger::from_genesis(&economy).unwrap();
        ledger
            .apply_mint(
                &CoinMintTransition::new(digest(2), principal(10), 50, 1, 1).unwrap(),
                &settlement(1_000, 50, 1),
            )
            .unwrap();
        ledger
            .apply_mint(
                &CoinMintTransition::new(digest(2), principal(12), 50, 2, 2).unwrap(),
                &settlement(1_050, 50, 2),
            )
            .unwrap();
        let mut transfers = [principal(10), principal(12)]
            .into_iter()
            .map(|owner| {
                let ids = ledger
                    .cells()
                    .as_slice()
                    .iter()
                    .filter(|record| record.cell().owner() == owner)
                    .map(|record| record.id())
                    .collect::<Vec<CoinCellId>>();
                CoinTransfer::new(owner, principal(30), vec![ids[0]], ids[1], 25, 1, 20).unwrap()
            })
            .collect::<Vec<_>>();
        transfers.sort_by_key(|transfer| transfer.inputs()[0]);
        (ledger, CashTransferV1::new(transfers).unwrap())
    }

    #[test]
    fn specialized_stark_proves_the_direct_cash_trace() {
        let (ledger, batch) = fixture();
        let (trace, _) = prove_cash_air(&ledger, &batch, 3, 16).unwrap();
        let proof = prove(&trace).unwrap();
        let bytes = proof.to_bytes();
        verify(proof).unwrap();
        super::verify_bytes(&bytes, &trace).unwrap();
        assert!(super::verify_bytes(&bytes[..bytes.len() - 1], &trace).is_err());
        let mut tampered = bytes.clone();
        let midpoint = tampered.len() / 2;
        tampered[midpoint] ^= 1;
        assert!(super::verify_bytes(&tampered, &trace).is_err());
        let receipt = CashAirReceiptV1::new(trace.clone(), bytes).unwrap();
        let encoded = receipt.encode_envelope().unwrap();
        assert_eq!(CashAirReceiptV1::verify_bytes(&encoded), Ok(()));
        let mut trailing = encoded;
        trailing.push(0);
        assert!(CashAirReceiptV1::verify_bytes(&trailing).is_err());
    }

    #[test]
    fn substituted_public_outcome_is_rejected() {
        let (ledger, batch) = fixture();
        let (trace, _) = prove_cash_air(&ledger, &batch, 3, 16).unwrap();
        let mut proof = prove(&trace).unwrap();
        proof.public.applied += BaseElement::new(1);
        assert!(verify(proof).is_err());
    }

    #[test]
    fn authenticated_parent_stark_binds_exact_pre_and_post_roots() {
        let (ledger, batch) = fixture();
        let (trace, _) = prove_authenticated_cash_air(&ledger, &batch, 3, 16).unwrap();
        let proof = prove_authenticated_parent(&trace).unwrap();
        verify(proof).unwrap();
    }

    #[test]
    fn authenticated_parent_rejects_root_and_mode_substitution() {
        let (ledger, batch) = fixture();
        let (trace, _) = prove_authenticated_cash_air(&ledger, &batch, 3, 16).unwrap();

        let mut wrong_root = prove_authenticated_parent(&trace).unwrap();
        wrong_root.public.authenticated_post_root[0] += BaseElement::new(1);
        assert!(verify(wrong_root).is_err());

        let mut wrong_mode = prove_authenticated_parent(&trace).unwrap();
        wrong_mode.public.authenticated_mode = BaseElement::new(0);
        assert!(verify(wrong_mode).is_err());

        let mut wrong_row = prove_authenticated_parent(&trace).unwrap();
        wrong_row.public.authenticated_row_roots[0][0] += BaseElement::new(1);
        assert!(verify(wrong_row).is_err());
    }

    #[test]
    fn authenticated_receipt_envelope_round_trips_and_rejects_header_mutation() {
        let (ledger, batch) = fixture();
        let (trace, _) = prove_authenticated_cash_air(&ledger, &batch, 3, 16).unwrap();
        let parent = prove_authenticated_parent(&trace).unwrap();
        let receipt = AuthenticatedCashAirReceiptV1::new(
            trace.clone(),
            parent.to_bytes(),
            trace.mutations().iter().map(|_| None).collect(),
        )
        .unwrap();
        let encoded = receipt.encode_envelope().unwrap();
        let decoded = decode_envelope::<AuthenticatedCashAirReceiptV1>(&encoded).unwrap();
        assert_eq!(decoded.suite_id, CASH_AIR_COMPOSITE_SUITE_ID);
        assert_eq!(decoded.trace, trace);

        // The suite field is the first payload word after the canonical envelope header.
        let mut wrong_suite = encoded.clone();
        let suite_bytes = CASH_AIR_COMPOSITE_SUITE_ID.to_be_bytes();
        let offset = encoded
            .windows(4)
            .position(|window| window == suite_bytes)
            .unwrap();
        wrong_suite[offset..offset + 4].copy_from_slice(&CASH_AIR_PARENT_SUITE_ID.to_be_bytes());
        assert!(AuthenticatedCashAirReceiptV1::verify_bytes(&wrong_suite).is_err());
    }

    #[test]
    fn authenticated_composite_requires_exact_accepted_row_shape() {
        let (ledger, batch) = fixture();
        let (trace, _) = prove_authenticated_cash_air(&ledger, &batch, 3, 16).unwrap();
        let parent = prove_authenticated_parent(&trace).unwrap();
        let missing_proofs = super::AuthenticatedCashCompositeStarkProof {
            parent,
            mutation_shake: trace.mutations().iter().map(|_| None).collect(),
        };
        assert!(verify_authenticated_composite(missing_proofs, &trace).is_err());
    }

    #[test]
    fn authenticated_composite_budget_is_preflighted_before_proving() {
        let (ledger, batch) = fixture();
        let (trace, _) = prove_authenticated_cash_air(&ledger, &batch, 3, 16).unwrap();
        let total = super::enforce_authenticated_composite_permutation_limit(&trace).unwrap();
        assert!(total > super::MAX_AUTHENTICATED_SHAKE_PERMUTATIONS_PER_CHUNK);
        assert!(total <= super::MAX_AUTHENTICATED_SHAKE_PERMUTATIONS_PER_COMPOSITE);
        assert!(
            super::ensure_authenticated_composite_permutation_total(
                super::MAX_AUTHENTICATED_SHAKE_PERMUTATIONS_PER_COMPOSITE + 1,
            )
            .is_err()
        );
    }

    #[test]
    #[ignore = "full-depth authenticated SHAKE timing is an explicit release benchmark gate"]
    fn full_authenticated_composite_proves_and_verifies() {
        let (ledger, batch) = fixture();
        let (trace, _) = prove_authenticated_cash_air(&ledger, &batch, 3, 16).unwrap();
        let proof = prove_authenticated_composite(&trace).unwrap();
        assert_eq!(proof.mutation_proof_count(), 2);
        let parent_bytes = proof.parent.to_bytes();
        let mutation_bytes = proof
            .mutation_shake
            .iter()
            .map(|proof| proof.as_ref().map(|value| value.encode_bytes().unwrap()))
            .collect();
        let receipt = AuthenticatedCashAirReceiptV1::new(trace, parent_bytes, mutation_bytes)
            .unwrap();
        let encoded = receipt.encode_envelope().unwrap();
        AuthenticatedCashAirReceiptV1::verify_bytes(&encoded).unwrap();
    }
}
