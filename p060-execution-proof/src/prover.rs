use thiserror::Error;
use winterfell::crypto::{DefaultRandomCoin, MerkleTree};
use winterfell::math::{FieldElement, fields::f64::BaseElement};
use winterfell::{
    AuxRandElements, CompositionPoly, CompositionPolyTrace, ConstraintCompositionCoefficients,
    DefaultConstraintCommitment, DefaultConstraintEvaluator, DefaultTraceLde, PartitionOptions,
    ProofOptions, Prover, StarkDomain, TraceInfo, TracePolyTable, TraceTable,
};

use crate::air::{AccumulatorAir, AccumulatorInputs, padded_actions};
use crate::codec::{CodecError, Receipt, ReceiptHeader};
use crate::hash::Shake256_384;
use crate::model::{Block, ModelError, Opcode, canonical_field};
use crate::suite::{TRACE_WIDTH, proof_options, trace_length};

type SuiteHasher = Shake256_384<BaseElement>;

#[derive(Debug, Error)]
pub enum ProveError {
    #[error(transparent)]
    Model(#[from] ModelError),
    #[error("STARK prover rejected the execution trace: {0}")]
    Stark(#[from] winterfell::ProverError),
    #[error(transparent)]
    Codec(#[from] CodecError),
}

struct AccumulatorProver {
    options: ProofOptions,
    inputs: AccumulatorInputs,
}

impl Prover for AccumulatorProver {
    type BaseField = BaseElement;
    type Air = AccumulatorAir;
    type Trace = TraceTable<Self::BaseField>;
    type HashFn = SuiteHasher;
    type VC = MerkleTree<Self::HashFn>;
    type RandomCoin = DefaultRandomCoin<Self::HashFn>;
    type TraceLde<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultTraceLde<E, Self::HashFn, Self::VC>;
    type ConstraintCommitment<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintCommitment<E, Self::HashFn, Self::VC>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintEvaluator<'a, Self::Air, E>;

    fn get_pub_inputs(&self, _trace: &Self::Trace) -> AccumulatorInputs {
        self.inputs.clone()
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }

    fn new_trace_lde<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        trace_info: &TraceInfo,
        main_trace: &winterfell::matrix::ColMatrix<Self::BaseField>,
        domain: &StarkDomain<Self::BaseField>,
        partition_option: PartitionOptions,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>) {
        DefaultTraceLde::new(trace_info, main_trace, domain, partition_option)
    }

    fn build_constraint_commitment<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        composition_poly_trace: CompositionPolyTrace<E>,
        num_constraint_composition_columns: usize,
        domain: &StarkDomain<Self::BaseField>,
        partition_options: PartitionOptions,
    ) -> (Self::ConstraintCommitment<E>, CompositionPoly<E>) {
        DefaultConstraintCommitment::new(
            composition_poly_trace,
            num_constraint_composition_columns,
            domain,
            partition_options,
        )
    }

    fn new_evaluator<'a, E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        air: &'a Self::Air,
        aux_rand_elements: Option<AuxRandElements<E>>,
        composition_coefficients: ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }
}

pub fn prove(pre_state: u64, block: &Block) -> Result<Receipt, ProveError> {
    block.validate()?;
    canonical_field(pre_state)?;
    let post_state = block.execute(pre_state)?;
    let header = ReceiptHeader::for_execution(pre_state, post_state, block)?;
    let inputs = AccumulatorInputs::new(header.clone(), pre_state, post_state, block)?;
    let trace = build_trace(pre_state, block)?;
    let prover = AccumulatorProver {
        options: proof_options(),
        inputs,
    };
    let proof = prover.prove(trace)?;
    Receipt::new(
        header,
        pre_state,
        post_state,
        block.clone(),
        proof.to_bytes(),
    )
    .map_err(ProveError::from)
}

fn build_trace(pre_state: u64, block: &Block) -> Result<TraceTable<BaseElement>, ModelError> {
    let len = trace_length(block.actions.len());
    let actions = padded_actions(block, len);
    let mut trace = TraceTable::new(TRACE_WIDTH, len);
    let pre = canonical_field(pre_state)?;
    trace.fill(
        |row| {
            row[0] = pre;
            row[1] = BaseElement::new(actions[0].opcode as u64);
            row[2] = BaseElement::new(actions[0].operand);
        },
        |step, row| {
            let opcode = actions[step].opcode;
            let operand = BaseElement::new(actions[step].operand);
            row[0] = match opcode {
                Opcode::Add => row[0] + operand,
                Opcode::Mul => row[0] * operand,
            };
            if step + 1 < actions.len() {
                row[1] = BaseElement::new(actions[step + 1].opcode as u64);
                row[2] = BaseElement::new(actions[step + 1].operand);
            }
        },
    );
    debug_assert_eq!(
        block.execute(pre_state).unwrap(),
        trace.get(0, len - 1).as_int()
    );
    Ok(trace)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Action;
    use crate::verifier::{VerifyError, verify_receipt};
    use winterfell::{BatchingMethod, FieldExtension};

    #[test]
    fn verifier_rejects_an_individually_valid_unregistered_parameter_set() {
        let block = Block::new(vec![Action::add(3), Action::mul(7)]).unwrap();
        let pre_state = 2;
        let post_state = block.execute(pre_state).unwrap();
        let header = ReceiptHeader::for_execution(pre_state, post_state, &block).unwrap();
        let inputs = AccumulatorInputs::new(header.clone(), pre_state, post_state, &block).unwrap();
        let unregistered_options = ProofOptions::new(
            47,
            8,
            16,
            FieldExtension::Quadratic,
            8,
            31,
            BatchingMethod::Linear,
            BatchingMethod::Linear,
        );
        let prover = AccumulatorProver {
            options: unregistered_options,
            inputs,
        };
        let proof = prover
            .prove(build_trace(pre_state, &block).unwrap())
            .unwrap();
        let receipt = Receipt::new(header, pre_state, post_state, block, proof.to_bytes()).unwrap();
        assert!(matches!(
            verify_receipt(&receipt.encode().unwrap(), None),
            Err(VerifyError::ProofParameters)
        ));
    }
}
