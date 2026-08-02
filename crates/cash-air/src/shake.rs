use core::borrow::Borrow;
use serde::{Deserialize, Serialize};

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::BabyBear;
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2Bowers;
use p3_field::{PrimeField64, extension::BinomialExtensionField};
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_keccak::KeccakF;
use p3_keccak_air::{KeccakAir, KeccakCols, NUM_ROUNDS_MIN_1, generate_trace_rows};
use p3_matrix::{Matrix, dense::RowMajorMatrix};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_sha256::Sha256;
use p3_symmetric::{CompressionFunctionFromHasher, Permutation, SerializingHasher};
use p3_uni_stark::{
    Proof, StarkConfig, prove, prove_with_preprocessed, setup_preprocessed, verify,
    verify_with_preprocessed,
};

use activechain_cash_kernel::{
    AUTHENTICATED_CASH_DEPTH, CoinCellMutationWitness, CoinCellTransitionWitness,
    authenticated_coin_cell_count_root_hash, authenticated_coin_cell_leaf_hash,
    authenticated_coin_cell_leaf_transcript, authenticated_coin_cell_node_hash,
    authenticated_coin_cell_node_transcript, authenticated_coin_cell_root_transcript,
    authenticated_empty_coin_cell_leaf_hash, authenticated_empty_coin_cell_leaf_transcript,
    verify_coin_cell_transition,
};
use activechain_protocol_types::Digest384;

const RATE_BYTES: usize = 136;
const SHAKE128_RATE_BYTES: usize = 168;
const STATE_LANES: usize = 25;
const LIMBS_PER_LANE: usize = 4;
const STATE_PUBLIC_VALUES: usize = STATE_LANES * LIMBS_PER_LANE;
const TOTAL_PUBLIC_VALUES: usize = STATE_PUBLIC_VALUES * 2;
pub const CASH_AIR_SHAKE_SUITE_ID: u32 = 0xCA50_0301;
pub const CASH_AIR_SHAKE128_XOF_SUITE_ID: u32 = 0xCA50_0302;
const KECCAK_ROUNDS: usize = 24;
pub const MAX_CASH_SHAKE_MESSAGE: usize = 512;
pub const MAX_CASH_SHAKE_XOF_MESSAGE: usize = 2_048;
pub const MAX_CASH_SHAKE_XOF_OUTPUT: usize = 16_384;
/// Maximum number of Keccak permutations aggregated into one FRI proof.
///
/// A complete authenticated Coin Cell mutation needs 772 SHAKE messages. Keeping
/// this below that path size repeats the very wide Keccak opening for every
/// chunk, producing receipts far beyond the bounded ingress ceiling. This cap
/// admits one complete path per proof while the independent composite cap still
/// bounds total validator work.
pub const MAX_AUTHENTICATED_SHAKE_PERMUTATIONS_PER_CHUNK: usize = 1_024;
pub const MAX_AUTHENTICATED_SHAKE_PERMUTATIONS_PER_COMPOSITE: usize = 16_384;

type Val = BabyBear;
type Challenge = BinomialExtensionField<Val, 4>;
type ByteHash = Sha256;
type FieldHash = SerializingHasher<ByteHash>;
type Compress = CompressionFunctionFromHasher<ByteHash, 2, 32>;
type ValMmcs = MerkleTreeMmcs<Val, u8, FieldHash, Compress, 2, 32>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
type Pcs = TwoAdicFriPcs<Val, Radix2Bowers, ValMmcs, ChallengeMmcs>;
type Challenger = SerializingChallenger32<Val, HashChallenger<u8, ByteHash, 32>>;
type Config = StarkConfig<Pcs, Challenge, Challenger>;

#[derive(Debug)]
struct BoundKeccakAir;

#[derive(Debug)]
struct OrderedBatchKeccakAir {
    bindings: Vec<([u64; STATE_LANES], [u64; STATE_LANES])>,
}

impl<F: PrimeField64> BaseAir<F> for OrderedBatchKeccakAir {
    fn width(&self) -> usize {
        <KeccakAir as BaseAir<F>>::width(&KeccakAir {})
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        let height = (self.bindings.len() * KECCAK_ROUNDS).next_power_of_two();
        let zero_post = permuted_state([0; STATE_LANES]);
        let mut values = F::zero_vec(height * TOTAL_PUBLIC_VALUES);
        for row in 0..height {
            let slot = row / KECCAK_ROUNDS;
            let (pre, post) =
                self.bindings.get(slot).copied().unwrap_or(([0; STATE_LANES], zero_post));
            let bound = state_values::<F>(pre, post);
            let offset = row * TOTAL_PUBLIC_VALUES;
            values[offset..offset + TOTAL_PUBLIC_VALUES].copy_from_slice(&bound);
        }
        Some(RowMajorMatrix::new(values, TOTAL_PUBLIC_VALUES))
    }

    fn preprocessed_width(&self) -> usize {
        TOTAL_PUBLIC_VALUES
    }
}

impl<AB: AirBuilder> Air<AB> for OrderedBatchKeccakAir
where
    AB::F: PrimeField64,
{
    fn eval(&self, builder: &mut AB) {
        KeccakAir {}.eval(builder);
        let expected = builder.preprocessed().current_slice().to_vec();
        let main = builder.main();
        let local: &KeccakCols<AB::Var> = main.current_slice().borrow();
        let first_round = local.step_flags[0];
        let final_round = local.step_flags[NUM_ROUNDS_MIN_1];
        for y in 0..5 {
            for x in 0..5 {
                let lane = x + 5 * y;
                for limb in 0..LIMBS_PER_LANE {
                    let index = lane * LIMBS_PER_LANE + limb;
                    builder
                        .when(first_round)
                        .assert_eq(local.preimage[y][x][limb], expected[index]);
                    builder.when(final_round).assert_eq(
                        local.a_prime_prime_prime(y, x, limb),
                        expected[STATE_PUBLIC_VALUES + index],
                    );
                }
            }
        }
    }
}

impl<F> BaseAir<F> for BoundKeccakAir {
    fn width(&self) -> usize {
        <KeccakAir as BaseAir<F>>::width(&KeccakAir {})
    }

    fn num_public_values(&self) -> usize {
        TOTAL_PUBLIC_VALUES
    }
}

impl<AB: AirBuilder> Air<AB> for BoundKeccakAir {
    fn eval(&self, builder: &mut AB) {
        KeccakAir {}.eval(builder);

        let public = builder.public_values().to_vec();
        let main = builder.main();
        let local: &KeccakCols<AB::Var> = main.current_slice().borrow();
        let first = builder.is_first_row();
        let final_round = local.step_flags[NUM_ROUNDS_MIN_1];

        for y in 0..5 {
            for x in 0..5 {
                let lane = x + 5 * y;
                for limb in 0..LIMBS_PER_LANE {
                    let public_index = lane * LIMBS_PER_LANE + limb;
                    builder
                        .when(first.clone())
                        .assert_eq(local.preimage[y][x][limb], public[public_index]);
                    builder.when(final_round).assert_eq(
                        local.a_prime_prime_prime(y, x, limb),
                        public[STATE_PUBLIC_VALUES + public_index],
                    );
                }
            }
        }
    }
}

pub struct KeccakPermutationStarkProof {
    proof: Proof<Config>,
}

pub struct Shake256StarkProof {
    permutations: Vec<KeccakPermutationStarkProof>,
    digest: [u8; 48],
}

pub struct Shake256XofStarkProof {
    proof: Proof<Config>,
    output: Vec<u8>,
    permutation_count: usize,
}

pub struct Shake128XofStarkProof {
    proof: Proof<Config>,
    output: Vec<u8>,
    permutation_count: usize,
}

impl Shake128XofStarkProof {
    #[must_use]
    pub const fn suite_id() -> u32 {
        CASH_AIR_SHAKE128_XOF_SUITE_ID
    }

    #[must_use]
    pub fn output(&self) -> &[u8] {
        &self.output
    }

    #[must_use]
    pub const fn permutation_count(&self) -> usize {
        self.permutation_count
    }
}

impl Shake256XofStarkProof {
    #[must_use]
    pub const fn suite_id() -> u32 {
        CASH_AIR_SHAKE_SUITE_ID
    }

    #[must_use]
    pub fn output(&self) -> &[u8] {
        &self.output
    }

    #[must_use]
    pub const fn permutation_count(&self) -> usize {
        self.permutation_count
    }
}

impl Shake256StarkProof {
    #[must_use]
    pub const fn suite_id() -> u32 {
        CASH_AIR_SHAKE_SUITE_ID
    }
}

#[derive(Serialize, Deserialize)]
pub struct BatchedShake256StarkProof {
    proof: Proof<Config>,
    #[serde(skip)]
    digests: Vec<[u8; 48]>,
    permutation_count: usize,
}

#[derive(Serialize, Deserialize)]
pub struct AuthenticatedCashShakeStarkProof {
    batches: Vec<BatchedShake256StarkProof>,
}

impl AuthenticatedCashShakeStarkProof {
    #[must_use]
    pub const fn suite_id() -> u32 {
        CASH_AIR_SHAKE_SUITE_ID
    }

    pub fn encode_bytes(&self) -> Result<Vec<u8>, &'static str> {
        postcard::to_stdvec(self).map_err(|_| "CashAIR SHAKE proof encoding failed")
    }

    pub fn decode_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.is_empty() || bytes.len() > crate::MAX_CASH_AIR_COMPOSITE_BYTES {
            return Err("CashAIR SHAKE proof size is out of bounds");
        }
        let (proof, remaining) =
            postcard::take_from_bytes(bytes).map_err(|_| "malformed CashAIR SHAKE proof")?;
        if !remaining.is_empty() {
            return Err("trailing bytes in CashAIR SHAKE proof");
        }
        Ok(proof)
    }
}

impl AuthenticatedCashShakeStarkProof {
    #[must_use]
    pub fn permutation_count(&self) -> usize {
        self.batches.iter().map(BatchedShake256StarkProof::permutation_count).sum()
    }

    #[must_use]
    pub fn chunk_count(&self) -> usize {
        self.batches.len()
    }
}

pub fn prove_authenticated_cash_shake(
    transition: &CoinCellTransitionWitness,
) -> Result<AuthenticatedCashShakeStarkProof, &'static str> {
    let (messages, expected) = authenticated_transition_batch(transition)?;
    let chunks = authenticated_chunks(&messages)?;
    let mut batches = Vec::with_capacity(chunks.len());
    let mut digest_offset = 0;
    for chunk in chunks {
        let batch = prove_shake256_384_batch(chunk)?;
        let end = digest_offset + chunk.len();
        if batch.digests() != &expected[digest_offset..end] {
            return Err("authenticated cash SHAKE digest derivation mismatch");
        }
        batches.push(batch);
        digest_offset = end;
    }
    Ok(AuthenticatedCashShakeStarkProof { batches })
}

pub fn authenticated_cash_shake_permutation_count(
    transition: &CoinCellTransitionWitness,
) -> Result<usize, &'static str> {
    let (messages, _) = authenticated_transition_batch(transition)?;
    messages.iter().try_fold(0_usize, |total, message| {
        total
            .checked_add(padded_blocks(message)?.len())
            .ok_or("authenticated SHAKE permutation count overflow")
    })
}

pub fn verify_authenticated_cash_shake(
    proof: &AuthenticatedCashShakeStarkProof,
    transition: &CoinCellTransitionWitness,
) -> Result<(), &'static str> {
    let (messages, expected) = authenticated_transition_batch(transition)?;
    let chunks = authenticated_chunks(&messages)?;
    if proof.batches.len() != chunks.len() {
        return Err("authenticated cash SHAKE chunk count mismatch");
    }
    let mut digest_offset = 0;
    for (batch, chunk) in proof.batches.iter().zip(chunks) {
        let end = digest_offset + chunk.len();
        verify_shake256_384_batch(batch, chunk, &expected[digest_offset..end])?;
        digest_offset = end;
    }
    Ok(())
}

impl BatchedShake256StarkProof {
    #[must_use]
    pub fn digests(&self) -> &[[u8; 48]] {
        &self.digests
    }

    #[must_use]
    pub const fn permutation_count(&self) -> usize {
        self.permutation_count
    }
}

pub fn prove_shake256_384_batch(
    messages: &[Vec<u8>],
) -> Result<BatchedShake256StarkProof, &'static str> {
    if messages.is_empty() {
        return Err("SHAKE batch must be nonempty");
    }
    let (bindings, inputs, digests) = batch_witness(messages)?;
    let permutation_count = inputs.len();
    let air = OrderedBatchKeccakAir { bindings };
    let trace = generate_trace_rows::<Val>(inputs, 1);
    let degree_bits = trace.height().ilog2() as usize;
    let config = config();
    let (preprocessed, _) = setup_preprocessed(&config, &air, degree_bits)
        .ok_or("missing ordered Keccak binding table")?;
    let proof = prove_with_preprocessed(&config, &air, trace, &[], Some(&preprocessed));
    Ok(BatchedShake256StarkProof { proof, digests, permutation_count })
}

pub fn verify_shake256_384_batch(
    proof: &BatchedShake256StarkProof,
    messages: &[Vec<u8>],
    expected_digests: &[[u8; 48]],
) -> Result<(), &'static str> {
    let (bindings, _, digests) = batch_witness(messages)?;
    if messages.is_empty()
        || proof.permutation_count != bindings.len()
        || digests != expected_digests
    {
        return Err("SHAKE batch shape or digest mismatch");
    }
    let air = OrderedBatchKeccakAir { bindings };
    let config = config();
    let (_, verifier_key) = setup_preprocessed(&config, &air, proof.proof.degree_bits)
        .ok_or("missing ordered Keccak binding table")?;
    verify_with_preprocessed(&config, &air, &proof.proof, &[], Some(&verifier_key))
        .map_err(|_| "batched SHAKE proof verification failed")
}

pub fn prove_shake256_xof(
    message: &[u8],
    output_length: usize,
) -> Result<Shake256XofStarkProof, &'static str> {
    let (proof, output, permutation_count) = prove_xof::<RATE_BYTES>(message, output_length)?;
    Ok(Shake256XofStarkProof { proof, output, permutation_count })
}

pub fn prove_shake128_xof(
    message: &[u8],
    output_length: usize,
) -> Result<Shake128XofStarkProof, &'static str> {
    let (proof, output, permutation_count) =
        prove_xof::<SHAKE128_RATE_BYTES>(message, output_length)?;
    Ok(Shake128XofStarkProof { proof, output, permutation_count })
}

pub fn verify_shake256_xof(
    proof: &Shake256XofStarkProof,
    message: &[u8],
    expected_output: &[u8],
) -> Result<(), &'static str> {
    verify_xof::<RATE_BYTES>(
        &proof.proof,
        proof.permutation_count,
        &proof.output,
        message,
        expected_output,
    )
}

pub fn verify_shake128_xof(
    proof: &Shake128XofStarkProof,
    message: &[u8],
    expected_output: &[u8],
) -> Result<(), &'static str> {
    verify_xof::<SHAKE128_RATE_BYTES>(
        &proof.proof,
        proof.permutation_count,
        &proof.output,
        message,
        expected_output,
    )
}

impl Shake256StarkProof {
    #[must_use]
    pub const fn digest(&self) -> [u8; 48] {
        self.digest
    }

    #[must_use]
    pub fn permutation_count(&self) -> usize {
        self.permutations.len()
    }
}

pub fn prove_shake256_384(message: &[u8]) -> Result<Shake256StarkProof, &'static str> {
    let blocks = padded_blocks(message)?;
    let config = config();
    let mut state = [0_u64; STATE_LANES];
    let mut permutations = Vec::with_capacity(blocks.len());
    for block in blocks {
        absorb(&mut state, &block);
        let pre = state;
        KeccakF.permute_mut(&mut state);
        let public = public_values(pre, state);
        let trace = generate_trace_rows::<Val>(vec![pre], 1);
        let proof = prove(&config, &BoundKeccakAir, trace, &public);
        permutations.push(KeccakPermutationStarkProof { proof });
    }
    Ok(Shake256StarkProof { permutations, digest: squeeze_384(&state) })
}

pub fn verify_shake256_384(
    proof: &Shake256StarkProof,
    message: &[u8],
    expected_digest: [u8; 48],
) -> Result<(), &'static str> {
    let blocks = padded_blocks(message)?;
    if proof.permutations.len() != blocks.len() || proof.digest != expected_digest {
        return Err("SHAKE proof shape or digest mismatch");
    }
    let config = config();
    let mut state = [0_u64; STATE_LANES];
    for (block, permutation) in blocks.iter().zip(&proof.permutations) {
        absorb(&mut state, block);
        let pre = state;
        KeccakF.permute_mut(&mut state);
        verify(&config, &BoundKeccakAir, &permutation.proof, &public_values(pre, state))
            .map_err(|_| "SHAKE permutation proof verification failed")?;
    }
    if squeeze_384(&state) != expected_digest {
        return Err("SHAKE digest does not match constrained state");
    }
    Ok(())
}

fn config() -> Config {
    let byte_hash = ByteHash {};
    let field_hash = FieldHash::new(ByteHash {});
    let compress = Compress::new(byte_hash);
    let val_mmcs = ValMmcs::new(field_hash, compress, 3);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    // Pinned protocol parameters; do not use upstream benchmark helpers on
    // the consensus path. Conjectured FRI security is 3*32+16 = 112 bits,
    // above the protocol's 100-bit minimum (the query proof-of-work adds
    // availability grinding but is not counted in this floor).
    let fri = FriParameters {
        log_blowup: 3,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: 32,
        commit_proof_of_work_bits: 16,
        query_proof_of_work_bits: 16,
        mmcs: challenge_mmcs,
    };
    let pcs = Pcs::new(Radix2Bowers, val_mmcs, fri);
    let challenger = Challenger::from_hasher(vec![], ByteHash {});
    Config::new(pcs, challenger)
}

fn public_values(pre: [u64; STATE_LANES], post: [u64; STATE_LANES]) -> Vec<Val> {
    state_values(pre, post)
}

fn state_values<F: PrimeField64>(pre: [u64; STATE_LANES], post: [u64; STATE_LANES]) -> Vec<F> {
    pre.into_iter()
        .chain(post)
        .flat_map(|lane| {
            core::array::from_fn::<_, LIMBS_PER_LANE, _>(|index| {
                F::from_u16((lane >> (index * 16)) as u16)
            })
        })
        .collect()
}

fn padded_blocks(message: &[u8]) -> Result<Vec<[u8; RATE_BYTES]>, &'static str> {
    padded_blocks_for::<RATE_BYTES>(message, MAX_CASH_SHAKE_MESSAGE)
}

fn padded_blocks_for<const RATE: usize>(
    message: &[u8],
    maximum_message_length: usize,
) -> Result<Vec<[u8; RATE]>, &'static str> {
    if message.len() > maximum_message_length {
        return Err("SHAKE message exceeds CashAIR bound");
    }
    let block_count = message.len() / RATE + 1;
    let mut blocks = vec![[0_u8; RATE]; block_count];
    for (index, byte) in message.iter().copied().enumerate() {
        blocks[index / RATE][index % RATE] = byte;
    }
    let suffix_index = message.len();
    blocks[suffix_index / RATE][suffix_index % RATE] ^= 0x1f;
    blocks.last_mut().unwrap()[RATE - 1] ^= 0x80;
    Ok(blocks)
}

fn absorb(state: &mut [u64; STATE_LANES], block: &[u8; RATE_BYTES]) {
    absorb_for(state, block);
}

fn absorb_for<const RATE: usize>(state: &mut [u64; STATE_LANES], block: &[u8; RATE]) {
    for (index, chunk) in block.chunks_exact(8).enumerate() {
        state[index] ^= u64::from_le_bytes(chunk.try_into().unwrap());
    }
}

fn permuted_state(mut state: [u64; STATE_LANES]) -> [u64; STATE_LANES] {
    KeccakF.permute_mut(&mut state);
    state
}

type BatchWitness =
    (Vec<([u64; STATE_LANES], [u64; STATE_LANES])>, Vec<[u64; STATE_LANES]>, Vec<[u8; 48]>);
type XofWitness = (Vec<([u64; STATE_LANES], [u64; STATE_LANES])>, Vec<[u64; STATE_LANES]>, Vec<u8>);
type AuthenticatedTranscriptBatch = (Vec<Vec<u8>>, Vec<[u8; 48]>);

fn prove_xof<const RATE: usize>(
    message: &[u8],
    output_length: usize,
) -> Result<(Proof<Config>, Vec<u8>, usize), &'static str> {
    let (bindings, inputs, output) = xof_witness::<RATE>(message, output_length)?;
    let permutation_count = inputs.len();
    let air = OrderedBatchKeccakAir { bindings };
    let trace = generate_trace_rows::<Val>(inputs, 1);
    let degree_bits = trace.height().ilog2() as usize;
    let config = config();
    let (preprocessed, _) = setup_preprocessed(&config, &air, degree_bits)
        .ok_or("missing SHAKE XOF Keccak binding table")?;
    let proof = prove_with_preprocessed(&config, &air, trace, &[], Some(&preprocessed));
    Ok((proof, output, permutation_count))
}

fn verify_xof<const RATE: usize>(
    proof: &Proof<Config>,
    permutation_count: usize,
    proof_output: &[u8],
    message: &[u8],
    expected_output: &[u8],
) -> Result<(), &'static str> {
    let (bindings, _, output) = xof_witness::<RATE>(message, expected_output.len())?;
    if permutation_count != bindings.len()
        || proof_output != expected_output
        || output != expected_output
    {
        return Err("SHAKE XOF shape or output mismatch");
    }
    let air = OrderedBatchKeccakAir { bindings };
    let config = config();
    let (_, verifier_key) = setup_preprocessed(&config, &air, proof.degree_bits)
        .ok_or("missing SHAKE XOF Keccak binding table")?;
    verify_with_preprocessed(&config, &air, proof, &[], Some(&verifier_key))
        .map_err(|_| "SHAKE XOF proof verification failed")
}

fn xof_witness<const RATE: usize>(
    message: &[u8],
    output_length: usize,
) -> Result<XofWitness, &'static str> {
    if output_length == 0 || output_length > MAX_CASH_SHAKE_XOF_OUTPUT {
        return Err("SHAKE XOF output length is out of bounds");
    }
    let mut bindings = Vec::new();
    let mut inputs = Vec::new();
    let mut state = [0_u64; STATE_LANES];
    for block in padded_blocks_for::<RATE>(message, MAX_CASH_SHAKE_XOF_MESSAGE)? {
        absorb_for(&mut state, &block);
        let pre = state;
        state = permuted_state(state);
        bindings.push((pre, state));
        inputs.push(pre);
    }

    let mut output = Vec::with_capacity(output_length);
    loop {
        let rate = squeeze_rate_for::<RATE>(&state);
        let take = (output_length - output.len()).min(RATE);
        output.extend_from_slice(&rate[..take]);
        if output.len() == output_length {
            break;
        }
        let pre = state;
        state = permuted_state(state);
        bindings.push((pre, state));
        inputs.push(pre);
    }
    Ok((bindings, inputs, output))
}

fn batch_witness(messages: &[Vec<u8>]) -> Result<BatchWitness, &'static str> {
    let mut bindings = Vec::new();
    let mut inputs = Vec::new();
    let mut digests = Vec::with_capacity(messages.len());
    for message in messages {
        let mut state = [0_u64; STATE_LANES];
        for block in padded_blocks(message)? {
            absorb(&mut state, &block);
            let pre = state;
            state = permuted_state(state);
            bindings.push((pre, state));
            inputs.push(pre);
        }
        digests.push(squeeze_384(&state));
    }
    Ok((bindings, inputs, digests))
}

fn authenticated_transition_batch(
    transition: &CoinCellTransitionWitness,
) -> Result<AuthenticatedTranscriptBatch, &'static str> {
    verify_coin_cell_transition(transition).map_err(|_| "invalid authenticated cash transition")?;
    let mut messages = Vec::new();
    let mut digests = Vec::new();
    for mutation in transition.mutations() {
        append_mutation_path(mutation, true, &mut messages, &mut digests)?;
        append_mutation_path(mutation, false, &mut messages, &mut digests)?;
    }
    Ok((messages, digests))
}

fn authenticated_chunks(messages: &[Vec<u8>]) -> Result<Vec<&[Vec<u8>]>, &'static str> {
    let mut chunks = Vec::new();
    let mut start = 0;
    let mut permutations = 0;
    for (index, message) in messages.iter().enumerate() {
        let message_permutations = padded_blocks(message)?.len();
        if message_permutations > MAX_AUTHENTICATED_SHAKE_PERMUTATIONS_PER_CHUNK {
            return Err("authenticated SHAKE message exceeds per-chunk permutation cap");
        }
        if permutations + message_permutations > MAX_AUTHENTICATED_SHAKE_PERMUTATIONS_PER_CHUNK {
            chunks.push(&messages[start..index]);
            start = index;
            permutations = 0;
        }
        permutations += message_permutations;
    }
    if start < messages.len() {
        chunks.push(&messages[start..]);
    }
    Ok(chunks)
}

fn append_mutation_path(
    mutation: &CoinCellMutationWitness,
    pre: bool,
    messages: &mut Vec<Vec<u8>>,
    digests: &mut Vec<[u8; 48]>,
) -> Result<(), &'static str> {
    let record = if pre { mutation.previous() } else { mutation.next() };
    let count = if pre { mutation.pre_count() } else { mutation.post_count() };
    let (leaf_message, mut current) = if let Some(record) = record {
        (
            authenticated_coin_cell_leaf_transcript(&record)
                .map_err(|_| "invalid authenticated cash leaf transcript")?,
            authenticated_coin_cell_leaf_hash(&record)
                .map_err(|_| "invalid authenticated cash leaf hash")?,
        )
    } else {
        (authenticated_empty_coin_cell_leaf_transcript(), authenticated_empty_coin_cell_leaf_hash())
    };
    messages.push(leaf_message);
    digests.push(current.into_bytes());

    let key = mutation.id().into_digest();
    for (offset, sibling) in mutation.siblings().iter().copied().enumerate() {
        let depth = AUTHENTICATED_CASH_DEPTH - 1 - offset;
        let (left, right) =
            if digest_bit(key, depth) == 0 { (current, sibling) } else { (sibling, current) };
        messages.push(
            authenticated_coin_cell_node_transcript(depth, left, right)
                .map_err(|_| "invalid authenticated cash node transcript")?,
        );
        current = authenticated_coin_cell_node_hash(depth, left, right)
            .map_err(|_| "invalid authenticated cash node hash")?;
        digests.push(current.into_bytes());
    }

    messages.push(
        authenticated_coin_cell_root_transcript(count as usize, current)
            .map_err(|_| "invalid authenticated cash root transcript")?,
    );
    let root = authenticated_coin_cell_count_root_hash(count as usize, current)
        .map_err(|_| "invalid authenticated cash root hash")?;
    let expected = if pre { mutation.pre_root() } else { mutation.post_root() };
    if root != expected {
        return Err("authenticated cash path root mismatch");
    }
    digests.push(root.into_digest().into_bytes());
    Ok(())
}

fn digest_bit(digest: Digest384, depth: usize) -> u8 {
    let byte = depth / 8;
    let bit = 7 - depth % 8;
    (digest.as_bytes()[byte] >> bit) & 1
}

fn squeeze_384(state: &[u64; STATE_LANES]) -> [u8; 48] {
    let mut output = [0_u8; 48];
    for (index, chunk) in output.chunks_exact_mut(8).enumerate() {
        chunk.copy_from_slice(&state[index].to_le_bytes());
    }
    output
}

fn squeeze_rate_for<const RATE: usize>(state: &[u64; STATE_LANES]) -> [u8; RATE] {
    let mut output = [0_u8; RATE];
    for (index, chunk) in output.chunks_exact_mut(8).enumerate() {
        chunk.copy_from_slice(&state[index].to_le_bytes());
    }
    output
}

#[cfg(test)]
mod tests {
    use activechain_cash_kernel::{
        CashLedger, CoinCellSet, GenesisAllocation, GenesisEconomy, NativeAssetDefinition,
        authenticated_coin_cell_count_root_hash, authenticated_coin_cell_leaf_hash,
        authenticated_coin_cell_leaf_transcript, authenticated_coin_cell_node_hash,
        authenticated_coin_cell_node_transcript, authenticated_coin_cell_root_transcript,
        prove_coin_cell_mutation, prove_coin_cell_transition,
    };
    use activechain_protocol_types::{ChainId, Digest384, PrincipalId};
    use sha3::{
        Shake128, Shake256,
        digest::{ExtendableOutput, Update, XofReader},
    };

    use super::*;

    fn reference(message: &[u8]) -> [u8; 48] {
        let mut hasher = Shake256::default();
        hasher.update(message);
        let mut output = [0_u8; 48];
        hasher.finalize_xof().read(&mut output);
        output
    }

    fn reference_xof(message: &[u8], output_length: usize) -> Vec<u8> {
        let mut hasher = Shake256::default();
        hasher.update(message);
        let mut output = vec![0_u8; output_length];
        hasher.finalize_xof().read(&mut output);
        output
    }

    fn reference_xof128(message: &[u8], output_length: usize) -> Vec<u8> {
        let mut hasher = Shake128::default();
        hasher.update(message);
        let mut output = vec![0_u8; output_length];
        hasher.finalize_xof().read(&mut output);
        output
    }

    fn digest(byte: u8) -> Digest384 {
        Digest384::new([byte; 48])
    }

    fn cash_record() -> activechain_cash_kernel::CoinCellRecord {
        let definition = NativeAssetDefinition::new(
            ChainId::new(digest(1)),
            b"ACT".to_vec(),
            18,
            100,
            150,
            digest(2),
            digest(3),
            digest(4),
        )
        .unwrap();
        let economy = GenesisEconomy::new(
            definition,
            vec![GenesisAllocation::new(PrincipalId::new(digest(5)), 100, 0).unwrap()],
            0,
        )
        .unwrap();
        CashLedger::from_genesis(&economy).unwrap().cells().as_slice()[0]
    }

    #[test]
    fn specialized_keccak_air_proves_shake256_384() {
        let message = b"ActiveChain authenticated Coin Cell node";
        let expected = reference(message);
        let proof = prove_shake256_384(message).unwrap();
        assert_eq!(proof.digest(), expected);
        assert_eq!(proof.permutation_count(), 1);
        verify_shake256_384(&proof, message, expected).unwrap();
    }

    #[test]
    fn shake_proof_rejects_message_and_digest_substitution() {
        let message = b"cash leaf";
        let expected = reference(message);
        let proof = prove_shake256_384(message).unwrap();
        assert!(verify_shake256_384(&proof, b"cash leef", expected).is_err());
        let mut wrong = expected;
        wrong[0] ^= 1;
        assert!(verify_shake256_384(&proof, message, wrong).is_err());
    }

    #[test]
    fn shake_xof_proves_absorption_and_multiple_squeeze_blocks() {
        let message = vec![0xa5; RATE_BYTES + 17];
        let expected = reference_xof(&message, RATE_BYTES * 2 + 1);
        let proof = prove_shake256_xof(&message, expected.len()).unwrap();
        assert_eq!(proof.output(), expected);
        assert_eq!(proof.permutation_count(), 4);
        verify_shake256_xof(&proof, &message, &expected).unwrap();
    }

    #[test]
    fn shake_xof_rejects_message_length_output_and_bound_substitution() {
        let message = b"ML-DSA bounded XOF";
        let expected = reference_xof(message, RATE_BYTES + 1);
        let proof = prove_shake256_xof(message, expected.len()).unwrap();

        assert!(verify_shake256_xof(&proof, b"ML-DSA bounded XOg", &expected).is_err());
        assert!(verify_shake256_xof(&proof, message, &expected[..RATE_BYTES]).is_err());
        let mut substituted = expected;
        substituted[RATE_BYTES] ^= 1;
        assert!(verify_shake256_xof(&proof, message, &substituted).is_err());
        assert!(prove_shake256_xof(message, 0).is_err());
        assert!(prove_shake256_xof(message, MAX_CASH_SHAKE_XOF_OUTPUT + 1).is_err());
        assert!(prove_shake256_xof(&vec![0; MAX_CASH_SHAKE_XOF_MESSAGE + 1], 1).is_err());
    }

    #[test]
    fn shake128_xof_matches_standard_across_absorb_and_squeeze_boundaries() {
        let message = vec![0x3c; SHAKE128_RATE_BYTES + 1];
        let expected = reference_xof128(&message, SHAKE128_RATE_BYTES * 2 + 1);
        let proof = prove_shake128_xof(&message, expected.len()).unwrap();
        assert_eq!(proof.output(), expected);
        assert_eq!(proof.permutation_count(), 4);
        verify_shake128_xof(&proof, &message, &expected).unwrap();

        let mut substituted = expected;
        substituted[SHAKE128_RATE_BYTES] ^= 1;
        assert!(verify_shake128_xof(&proof, &message, &substituted).is_err());
    }

    #[test]
    fn multi_block_shake_absorption_is_chained_between_permutation_proofs() {
        let message = vec![0xa5; RATE_BYTES + 17];
        let expected = reference(&message);
        let proof = prove_shake256_384(&message).unwrap();
        assert_eq!(proof.permutation_count(), 2);
        verify_shake256_384(&proof, &message, expected).unwrap();
        let mut substituted = message;
        substituted[RATE_BYTES] ^= 1;
        assert!(verify_shake256_384(&proof, &substituted, expected).is_err());
    }

    #[test]
    fn authenticated_cash_leaf_and_node_transcripts_match_specialized_shake_air() {
        let record = cash_record();
        let leaf_transcript = authenticated_coin_cell_leaf_transcript(&record).unwrap();
        let leaf_digest = authenticated_coin_cell_leaf_hash(&record).unwrap().into_bytes();
        let leaf_proof = prove_shake256_384(&leaf_transcript).unwrap();
        verify_shake256_384(&leaf_proof, &leaf_transcript, leaf_digest).unwrap();

        let sibling = Digest384::new([0x5a; 48]);
        let node_transcript =
            authenticated_coin_cell_node_transcript(383, Digest384::new(leaf_digest), sibling)
                .unwrap();
        let node_digest =
            authenticated_coin_cell_node_hash(383, Digest384::new(leaf_digest), sibling)
                .unwrap()
                .into_bytes();
        let node_proof = prove_shake256_384(&node_transcript).unwrap();
        verify_shake256_384(&node_proof, &node_transcript, node_digest).unwrap();
        assert_eq!(node_proof.permutation_count(), 2);

        let tree = Digest384::new(node_digest);
        let root_transcript = authenticated_coin_cell_root_transcript(1, tree).unwrap();
        let root_digest =
            authenticated_coin_cell_count_root_hash(1, tree).unwrap().into_digest().into_bytes();
        let root_proof = prove_shake256_384(&root_transcript).unwrap();
        verify_shake256_384(&root_proof, &root_transcript, root_digest).unwrap();
    }

    #[test]
    fn shake_padding_handles_rate_boundary_and_enforces_bound() {
        for length in [RATE_BYTES - 1, RATE_BYTES, RATE_BYTES + 1] {
            let message = vec![0x5a; length];
            let blocks = padded_blocks(&message).unwrap();
            assert_eq!(blocks.len(), length / RATE_BYTES + 1);
        }
        assert!(padded_blocks(&vec![0; MAX_CASH_SHAKE_MESSAGE + 1]).is_err());
    }

    #[test]
    fn ordered_batch_binds_multiple_messages_in_one_stark() {
        let messages = vec![b"leaf transcript".to_vec(), vec![0xa5; RATE_BYTES + 7]];
        let expected: Vec<_> = messages.iter().map(|message| reference(message)).collect();
        let proof = prove_shake256_384_batch(&messages).unwrap();
        assert_eq!(proof.digests(), expected);
        assert_eq!(proof.permutation_count(), 3);
        verify_shake256_384_batch(&proof, &messages, &expected).unwrap();
    }

    #[test]
    fn ordered_batch_proves_exact_authenticated_leaf_node_and_root_sequence() {
        let record = cash_record();
        let leaf = authenticated_coin_cell_leaf_transcript(&record).unwrap();
        let leaf_digest = authenticated_coin_cell_leaf_hash(&record).unwrap();
        let node = authenticated_coin_cell_node_transcript(383, leaf_digest, digest(0x5a)).unwrap();
        let node_digest =
            authenticated_coin_cell_node_hash(383, leaf_digest, digest(0x5a)).unwrap();
        let root = authenticated_coin_cell_root_transcript(1, node_digest).unwrap();
        let messages = vec![leaf, node, root];
        let expected = vec![
            leaf_digest.into_bytes(),
            node_digest.into_bytes(),
            authenticated_coin_cell_count_root_hash(1, node_digest)
                .unwrap()
                .into_digest()
                .into_bytes(),
        ];
        let proof = prove_shake256_384_batch(&messages).unwrap();
        verify_shake256_384_batch(&proof, &messages, &expected).unwrap();
    }

    #[test]
    fn ordered_batch_rejects_order_digest_and_padding_slot_substitution() {
        let messages = vec![b"first".to_vec(), b"second".to_vec(), b"third".to_vec()];
        let expected: Vec<_> = messages.iter().map(|message| reference(message)).collect();
        let proof = prove_shake256_384_batch(&messages).unwrap();
        assert_eq!(proof.permutation_count(), 3);

        let mut reordered = messages.clone();
        reordered.swap(0, 1);
        assert!(verify_shake256_384_batch(&proof, &reordered, &expected).is_err());

        let mut wrong_digest = expected.clone();
        wrong_digest[2][0] ^= 1;
        assert!(verify_shake256_384_batch(&proof, &messages, &wrong_digest).is_err());

        let mut extra = messages;
        extra.push(Vec::new());
        let extra_expected: Vec<_> = extra.iter().map(|message| reference(message)).collect();
        assert!(verify_shake256_384_batch(&proof, &extra, &extra_expected).is_err());
    }

    #[test]
    fn authenticated_path_adapter_derives_both_ordered_root_chains() {
        let record = cash_record();
        let pre = CoinCellSet::new(vec![record]).unwrap();
        let post = CoinCellSet::new(Vec::new()).unwrap();
        let transition = prove_coin_cell_transition(&pre, &post).unwrap();
        let mutation = prove_coin_cell_mutation(&pre, record.id(), None).unwrap();
        let (messages, digests) = authenticated_transition_batch(&transition).unwrap();

        assert_eq!(messages.len(), 2 * (AUTHENTICATED_CASH_DEPTH + 2));
        assert_eq!(messages.len(), digests.len());
        assert_eq!(
            digests[AUTHENTICATED_CASH_DEPTH + 1],
            mutation.pre_root().into_digest().into_bytes()
        );
        assert_eq!(
            digests.last().copied().unwrap(),
            mutation.post_root().into_digest().into_bytes()
        );
    }

    #[test]
    fn authenticated_chunk_plan_is_ordered_and_strictly_permutation_bounded() {
        let messages = (0_usize..600)
            .map(|index| vec![(index % 251) as u8; RATE_BYTES + 2])
            .collect::<Vec<_>>();
        let chunks = authenticated_chunks(&messages).unwrap();
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks.concat(), messages);
        for chunk in chunks {
            let permutations: usize =
                chunk.iter().map(|message| padded_blocks(message).unwrap().len()).sum();
            assert!(permutations <= MAX_AUTHENTICATED_SHAKE_PERMUTATIONS_PER_CHUNK);
        }
    }
}
