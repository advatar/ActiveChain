use core::borrow::Borrow;

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

const RATE_BYTES: usize = 136;
const STATE_LANES: usize = 25;
const LIMBS_PER_LANE: usize = 4;
const STATE_PUBLIC_VALUES: usize = STATE_LANES * LIMBS_PER_LANE;
const TOTAL_PUBLIC_VALUES: usize = STATE_PUBLIC_VALUES * 2;
const KECCAK_ROUNDS: usize = 24;
pub const MAX_CASH_SHAKE_MESSAGE: usize = 512;

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

pub struct BatchedShake256StarkProof {
    proof: Proof<Config>,
    digests: Vec<[u8; 48]>,
    permutation_count: usize,
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
        || proof.digests != expected_digests
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
    let fri = FriParameters::new_benchmark(challenge_mmcs);
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
    if message.len() > MAX_CASH_SHAKE_MESSAGE {
        return Err("SHAKE message exceeds CashAIR bound");
    }
    let block_count = message.len() / RATE_BYTES + 1;
    let mut blocks = vec![[0_u8; RATE_BYTES]; block_count];
    for (index, byte) in message.iter().copied().enumerate() {
        blocks[index / RATE_BYTES][index % RATE_BYTES] = byte;
    }
    let suffix_index = message.len();
    blocks[suffix_index / RATE_BYTES][suffix_index % RATE_BYTES] ^= 0x1f;
    blocks.last_mut().unwrap()[RATE_BYTES - 1] ^= 0x80;
    Ok(blocks)
}

fn absorb(state: &mut [u64; STATE_LANES], block: &[u8; RATE_BYTES]) {
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

fn squeeze_384(state: &[u64; STATE_LANES]) -> [u8; 48] {
    let mut output = [0_u8; 48];
    for (index, chunk) in output.chunks_exact_mut(8).enumerate() {
        chunk.copy_from_slice(&state[index].to_le_bytes());
    }
    output
}

#[cfg(test)]
mod tests {
    use activechain_cash_kernel::{
        CashLedger, GenesisAllocation, GenesisEconomy, NativeAssetDefinition,
        authenticated_coin_cell_count_root_hash, authenticated_coin_cell_leaf_hash,
        authenticated_coin_cell_leaf_transcript, authenticated_coin_cell_node_hash,
        authenticated_coin_cell_node_transcript, authenticated_coin_cell_root_transcript,
    };
    use activechain_protocol_types::{ChainId, Digest384, PrincipalId};
    use sha3::{
        Shake256,
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
}
