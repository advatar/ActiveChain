use winterfell::math::{FieldElement, ToElements, fields::f64::BaseElement};
use winterfell::{
    Air, AirContext, Assertion, EvaluationFrame, ProofOptions, TraceInfo,
    TransitionConstraintDegree,
};

use crate::codec::ReceiptHeader;
use crate::model::{Action, Block, Opcode, canonical_field};
use crate::suite::{TRACE_WIDTH, trace_length};

#[derive(Debug, Clone)]
pub struct AccumulatorInputs {
    pub header: ReceiptHeader,
    pub pre_state: BaseElement,
    pub post_state: BaseElement,
    pub actions: Vec<Action>,
}

impl AccumulatorInputs {
    pub fn new(
        header: ReceiptHeader,
        pre_state: u64,
        post_state: u64,
        block: &Block,
    ) -> Result<Self, crate::model::ModelError> {
        Ok(Self {
            header,
            pre_state: canonical_field(pre_state)?,
            post_state: canonical_field(post_state)?,
            actions: block.actions.clone(),
        })
    }
}

impl ToElements<BaseElement> for AccumulatorInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        let mut result = Vec::with_capacity(40 + self.actions.len() * 2);
        result.push(BaseElement::new(self.header.codec_version as u64));
        result.push(BaseElement::new(self.header.receipt_kind as u64));
        result.push(BaseElement::new(self.header.protocol_version as u64));
        result.push(BaseElement::new(self.header.verifier_version as u64));
        result.push(BaseElement::new(self.header.suite_id as u64));
        result.push(BaseElement::new(self.header.flags as u64));
        for digest in [
            &self.header.program_id,
            &self.header.pre_state_root,
            &self.header.block_id,
            &self.header.post_state_root,
        ] {
            append_digest_elements(&mut result, digest);
        }
        result.push(self.pre_state);
        result.push(self.post_state);
        result.push(BaseElement::new(self.actions.len() as u64));
        for action in &self.actions {
            result.push(BaseElement::new(action.opcode as u64));
            result.push(BaseElement::new(action.operand));
        }
        result
    }
}

fn append_digest_elements(target: &mut Vec<BaseElement>, digest: &[u8; 48]) {
    // Seven bytes always fit canonically in the 64-bit Goldilocks field.
    for chunk in digest.chunks(7) {
        let mut buf = [0_u8; 8];
        buf[..chunk.len()].copy_from_slice(chunk);
        target.push(BaseElement::new(u64::from_le_bytes(buf)));
    }
}

pub struct AccumulatorAir {
    context: AirContext<BaseElement>,
    pre_state: BaseElement,
    post_state: BaseElement,
    opcodes: Vec<BaseElement>,
    operands: Vec<BaseElement>,
}

impl Air for AccumulatorAir {
    type BaseField = BaseElement;
    type PublicInputs = AccumulatorInputs;

    fn new(trace_info: TraceInfo, pub_inputs: Self::PublicInputs, options: ProofOptions) -> Self {
        assert_eq!(TRACE_WIDTH, trace_info.width());
        assert_eq!(trace_length(pub_inputs.actions.len()), trace_info.length());

        let transition_rows = trace_info.length() - 1;
        let mut opcodes = vec![BaseElement::ZERO; transition_rows];
        let mut operands = vec![BaseElement::ZERO; transition_rows];
        for (i, action) in pub_inputs.actions.iter().enumerate() {
            opcodes[i] = BaseElement::new(action.opcode as u64);
            operands[i] = BaseElement::new(action.operand);
        }

        let degrees = vec![
            TransitionConstraintDegree::new(2),
            TransitionConstraintDegree::new(3),
        ];
        let assertion_count = 2 + transition_rows * 2;
        Self {
            context: AirContext::new(trace_info, degrees, assertion_count, options),
            pre_state: pub_inputs.pre_state,
            post_state: pub_inputs.post_state,
            opcodes,
            operands,
        }
    }

    fn evaluate_transition<E>(
        &self,
        frame: &EvaluationFrame<E>,
        _periodic_values: &[E],
        result: &mut [E],
    ) where
        E: FieldElement<BaseField = Self::BaseField>,
    {
        let current = frame.current();
        let next = frame.next();
        let state = current[0];
        let opcode = current[1];
        let operand = current[2];
        let one = E::ONE;

        // Opcode is boolean: 0 selects addition and 1 selects multiplication.
        result[0] = opcode * (opcode - one);
        let expected = (one - opcode) * (state + operand) + opcode * state * operand;
        result[1] = next[0] - expected;
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let last = self.context.trace_len() - 1;
        let mut assertions = Vec::with_capacity(2 + self.opcodes.len() * 2);
        assertions.push(Assertion::single(0, 0, self.pre_state));
        assertions.push(Assertion::single(0, last, self.post_state));
        for row in 0..self.opcodes.len() {
            assertions.push(Assertion::single(1, row, self.opcodes[row]));
            assertions.push(Assertion::single(2, row, self.operands[row]));
        }
        assertions
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }
}

pub fn padded_actions(block: &Block, trace_len: usize) -> Vec<Action> {
    let mut actions = block.actions.clone();
    actions.resize(
        trace_len - 1,
        Action {
            opcode: Opcode::Add,
            operand: 0,
        },
    );
    actions
}
