use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::BabyBear;
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2Bowers;
use p3_field::{PrimeCharacteristicRing, extension::BinomialExtensionField};
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_keccak::KeccakF;
use p3_keccak_air::{KeccakAir, KeccakCols, NUM_ROUNDS_MIN_1, generate_trace_rows};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_sha256::Sha256;
use p3_symmetric::{CompressionFunctionFromHasher, Permutation, SerializingHasher};
use p3_uni_stark::{Proof, StarkConfig, prove, verify};

const RATE_BYTES: usize = 136;
const STATE_LANES: usize = 25;
const LIMBS_PER_LANE: usize = 4;
const STATE_PUBLIC_VALUES: usize = STATE_LANES * LIMBS_PER_LANE;
const TOTAL_PUBLIC_VALUES: usize = STATE_PUBLIC_VALUES * 2;
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
    pre.into_iter()
        .chain(post)
        .flat_map(|lane| {
            core::array::from_fn::<_, LIMBS_PER_LANE, _>(|index| {
                Val::from_u16((lane >> (index * 16)) as u16)
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

fn squeeze_384(state: &[u64; STATE_LANES]) -> [u8; 48] {
    let mut output = [0_u8; 48];
    for (index, chunk) in output.chunks_exact_mut(8).enumerate() {
        chunk.copy_from_slice(&state[index].to_le_bytes());
    }
    output
}

#[cfg(test)]
mod tests {
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
    fn shake_padding_handles_rate_boundary_and_enforces_bound() {
        for length in [RATE_BYTES - 1, RATE_BYTES, RATE_BYTES + 1] {
            let message = vec![0x5a; length];
            let blocks = padded_blocks(&message).unwrap();
            assert_eq!(blocks.len(), length / RATE_BYTES + 1);
        }
        assert!(padded_blocks(&vec![0; MAX_CASH_SHAKE_MESSAGE + 1]).is_err());
    }
}
