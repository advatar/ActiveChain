use activechain_canonical_codec::encode_envelope;
use activechain_wallet_core::CashSessionAdmissionWitnessV1;
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use winterfell::{
    AcceptableOptions, Air, AirContext, Assertion, AuxRandElements, BatchingMethod,
    CompositionPoly, CompositionPolyTrace, ConstraintCompositionCoefficients,
    DefaultConstraintCommitment, DefaultConstraintEvaluator, DefaultTraceLde, EvaluationFrame,
    FieldExtension, PartitionOptions, Proof, ProofOptions, Prover, StarkDomain, TraceInfo,
    TracePolyTable, TraceTable, TransitionConstraintDegree,
    crypto::{DefaultRandomCoin, MerkleTree, hashers::Blake3_256},
    math::{FieldElement, ToElements, fields::f128::BaseElement},
    matrix::ColMatrix,
};

const BIT_ROWS: usize = 128;
const TRACE_LENGTH: usize = 256;
const AMOUNT: usize = 0;
const FEE: usize = 1;
const SPEND: usize = 2;
const PRE: usize = 3;
const POST: usize = 4;
const MAX: usize = 5;
const REMAINING: usize = 6;
const SPEND_CARRY: usize = 7;
const POST_CARRY: usize = 8;
const LIMIT_CARRY: usize = 9;
const TRACE_WIDTH: usize = 10;
const PUBLIC_VALUES: usize = 5;
const WITNESS_DOMAIN: &[u8] = b"ACTIVECHAIN-CASH-SESSION-AIR-WITNESS-V1";

#[derive(Clone, Debug)]
struct SessionPublicInputs {
    witness_commitment: [BaseElement; 6],
    bits: [[BaseElement; BIT_ROWS]; PUBLIC_VALUES],
}

impl ToElements<BaseElement> for SessionPublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        self.witness_commitment
            .into_iter()
            .chain(self.bits.iter().flat_map(|bits| bits.iter().copied()))
            .collect()
    }
}

struct SessionAir {
    context: AirContext<BaseElement>,
    public: SessionPublicInputs,
}

impl Air for SessionAir {
    type BaseField = BaseElement;
    type PublicInputs = SessionPublicInputs;

    fn new(trace_info: TraceInfo, public: Self::PublicInputs, options: ProofOptions) -> Self {
        assert_eq!(trace_info.width(), TRACE_WIDTH);
        assert_eq!(trace_info.length(), TRACE_LENGTH);
        let mut degrees = vec![TransitionConstraintDegree::new(2); 13];
        for degree in &mut degrees[10..] {
            *degree = TransitionConstraintDegree::new(1);
        }
        Self {
            context: AirContext::new(trace_info, degrees, PUBLIC_VALUES * BIT_ROWS + 6, options),
            public,
        }
    }

    fn evaluate_transition<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        _periodic_values: &[E],
        result: &mut [E],
    ) {
        let current = frame.current();
        let next = frame.next();
        for column in 0..TRACE_WIDTH {
            result[column] = current[column] * (current[column] - E::ONE);
        }
        result[10] = current[AMOUNT] + current[FEE] + current[SPEND_CARRY]
            - current[SPEND]
            - E::from(2_u8) * next[SPEND_CARRY];
        result[11] = current[PRE] + current[SPEND] + current[POST_CARRY]
            - current[POST]
            - E::from(2_u8) * next[POST_CARRY];
        result[12] = current[POST] + current[REMAINING] + current[LIMIT_CARRY]
            - current[MAX]
            - E::from(2_u8) * next[LIMIT_CARRY];
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let mut assertions = Vec::with_capacity(PUBLIC_VALUES * BIT_ROWS + 6);
        for row in 0..BIT_ROWS {
            for (column, bits) in
                [AMOUNT, FEE, PRE, POST, MAX].into_iter().zip(self.public.bits.iter())
            {
                assertions.push(Assertion::single(column, row, bits[row]));
            }
        }
        for carry in [SPEND_CARRY, POST_CARRY, LIMIT_CARRY] {
            assertions.push(Assertion::single(carry, 0, BaseElement::ZERO));
            assertions.push(Assertion::single(carry, BIT_ROWS, BaseElement::ZERO));
        }
        assertions
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }
}

struct SessionProver {
    options: ProofOptions,
    public: SessionPublicInputs,
}

impl Prover for SessionProver {
    type BaseField = BaseElement;
    type Air = SessionAir;
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

    fn get_pub_inputs(&self, _trace: &Self::Trace) -> SessionPublicInputs {
        self.public.clone()
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

pub struct CashSessionStarkProof {
    proof: Proof,
    public: SessionPublicInputs,
}

impl CashSessionStarkProof {
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.proof.to_bytes()
    }
}

pub fn prove_session_budget(
    witness: &CashSessionAdmissionWitnessV1,
) -> Result<CashSessionStarkProof, &'static str> {
    let public = public_inputs(witness)?;
    let trace = build_trace(witness)?;
    let prover = SessionProver { options: proof_options(), public: public.clone() };
    let proof = prover.prove(trace).map_err(|_| "cash session proving failed")?;
    Ok(CashSessionStarkProof { proof, public })
}

pub fn verify_session_budget(
    proof: CashSessionStarkProof,
    witness: &CashSessionAdmissionWitnessV1,
) -> Result<(), &'static str> {
    let expected = public_inputs(witness)?;
    if proof.public.to_elements() != expected.to_elements() {
        return Err("cash session public inputs do not match witness");
    }
    winterfell::verify::<
        SessionAir,
        Blake3_256<BaseElement>,
        DefaultRandomCoin<Blake3_256<BaseElement>>,
        MerkleTree<Blake3_256<BaseElement>>,
    >(proof.proof, expected, &AcceptableOptions::MinConjecturedSecurity(95))
    .map_err(|_| "cash session verification failed")
}

fn build_trace(
    witness: &CashSessionAdmissionWitnessV1,
) -> Result<TraceTable<BaseElement>, &'static str> {
    let spend = witness.amount().checked_add(witness.fee()).ok_or("cash session spend overflow")?;
    let remaining = witness
        .max_spend()
        .checked_sub(witness.post_spent())
        .ok_or("cash session budget exceeded")?;
    let values = [
        witness.amount(),
        witness.fee(),
        spend,
        witness.pre_spent(),
        witness.post_spent(),
        witness.max_spend(),
        remaining,
    ];
    let mut trace = TraceTable::new(TRACE_WIDTH, TRACE_LENGTH);
    let mut spend_carry = 0_u128;
    let mut post_carry = 0_u128;
    let mut limit_carry = 0_u128;
    for row in 0..BIT_ROWS {
        for (column, value) in values.into_iter().enumerate() {
            trace.set(column, row, BaseElement::new((value >> row) & 1));
        }
        trace.set(SPEND_CARRY, row, BaseElement::new(spend_carry));
        trace.set(POST_CARRY, row, BaseElement::new(post_carry));
        trace.set(LIMIT_CARRY, row, BaseElement::new(limit_carry));
        spend_carry =
            (((witness.amount() >> row) & 1) + ((witness.fee() >> row) & 1) + spend_carry) >> 1;
        post_carry = (((witness.pre_spent() >> row) & 1) + ((spend >> row) & 1) + post_carry) >> 1;
        limit_carry =
            (((witness.post_spent() >> row) & 1) + ((remaining >> row) & 1) + limit_carry) >> 1;
    }
    if spend_carry != 0 || post_carry != 0 || limit_carry != 0 {
        return Err("cash session arithmetic overflow");
    }
    // The unconstrained second half carries a fixed, valid ripple-addition exercise. It keeps
    // every carry column algebraically non-constant so Winterfell's debug degree validator checks
    // the declared boolean constraints even for public witnesses whose real additions need no
    // carry. Only rows 0..128 are tied to the public statement.
    let padding_values = [u128::MAX - 1, 5, 3, u128::MAX, 2, 1, u128::MAX];
    spend_carry = 0;
    post_carry = 0;
    limit_carry = 0;
    for bit in 0..BIT_ROWS {
        let row = BIT_ROWS + bit;
        for (column, value) in padding_values.into_iter().enumerate() {
            trace.set(column, row, BaseElement::new((value >> bit) & 1));
        }
        trace.set(SPEND_CARRY, row, BaseElement::new(spend_carry));
        trace.set(POST_CARRY, row, BaseElement::new(post_carry));
        trace.set(LIMIT_CARRY, row, BaseElement::new(limit_carry));
        spend_carry = (((padding_values[AMOUNT] >> bit) & 1)
            + ((padding_values[FEE] >> bit) & 1)
            + spend_carry)
            >> 1;
        post_carry = (((padding_values[PRE] >> bit) & 1)
            + ((padding_values[SPEND] >> bit) & 1)
            + post_carry)
            >> 1;
        limit_carry = (((padding_values[POST] >> bit) & 1)
            + ((padding_values[REMAINING] >> bit) & 1)
            + limit_carry)
            >> 1;
    }
    Ok(trace)
}

fn public_inputs(
    witness: &CashSessionAdmissionWitnessV1,
) -> Result<SessionPublicInputs, &'static str> {
    let encoded = encode_envelope(witness).map_err(|_| "cash session witness encoding failed")?;
    let mut hasher = Shake256::default();
    hasher.update(WITNESS_DOMAIN);
    hasher.update(&(encoded.len() as u64).to_be_bytes());
    hasher.update(&encoded);
    let mut commitment = [0_u8; 48];
    hasher.finalize_xof().read(&mut commitment);
    let witness_commitment = core::array::from_fn(|index| {
        let mut limb = [0_u8; 8];
        limb.copy_from_slice(&commitment[index * 8..(index + 1) * 8]);
        BaseElement::new(u64::from_be_bytes(limb).into())
    });
    let values = [
        witness.amount(),
        witness.fee(),
        witness.pre_spent(),
        witness.post_spent(),
        witness.max_spend(),
    ];
    let bits = values.map(|value| core::array::from_fn(|bit| BaseElement::new((value >> bit) & 1)));
    Ok(SessionPublicInputs { witness_commitment, bits })
}

fn proof_options() -> ProofOptions {
    ProofOptions::new(
        32,
        8,
        0,
        FieldExtension::None,
        8,
        31,
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    )
}

#[cfg(test)]
mod tests {
    use activechain_protocol_types::{ChainId, Digest384, PrincipalId};
    use activechain_wallet_core::CashSessionAdmissionWitnessV1;

    use super::{prove_session_budget, verify_session_budget};

    fn digest(byte: u8) -> Digest384 {
        Digest384::new([byte; 48])
    }

    fn witness(amount: u128, fee: u128, pre: u128, max: u128) -> CashSessionAdmissionWitnessV1 {
        CashSessionAdmissionWitnessV1::new(
            ChainId::new(digest(1)),
            PrincipalId::new(digest(2)),
            digest(3),
            5,
            1,
            10,
            amount,
            fee,
            max,
            pre,
            pre + amount + fee,
        )
        .unwrap()
    }

    #[test]
    fn bitwise_air_proves_non_wrapping_budget_consumption() {
        let admission = witness(10, 1, (1_u128 << 96) + 7, (1_u128 << 100) + 20);
        let proof = prove_session_budget(&admission).unwrap();
        verify_session_budget(proof, &admission).unwrap();
    }

    #[test]
    fn proof_is_bound_to_the_exact_canonical_runtime_witness() {
        let admission = witness(10, 1, 7, 100);
        let substituted = witness(9, 2, 7, 100);
        let proof = prove_session_budget(&admission).unwrap();
        assert!(verify_session_budget(proof, &substituted).is_err());
    }

    #[test]
    fn witness_rejects_overflow_and_budget_excess_before_proving() {
        assert!(
            CashSessionAdmissionWitnessV1::new(
                ChainId::new(digest(1)),
                PrincipalId::new(digest(2)),
                digest(3),
                5,
                1,
                10,
                u128::MAX,
                1,
                u128::MAX,
                0,
                0,
            )
            .is_err()
        );
        assert!(
            CashSessionAdmissionWitnessV1::new(
                ChainId::new(digest(1)),
                PrincipalId::new(digest(2)),
                digest(3),
                5,
                1,
                10,
                10,
                1,
                10,
                0,
                11,
            )
            .is_err()
        );
    }
}
