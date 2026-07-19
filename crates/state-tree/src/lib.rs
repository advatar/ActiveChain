#![no_std]
#![forbid(unsafe_code)]

//! P-031's canonical fixed-depth sparse state tree and single-key witnesses.

extern crate alloc;

mod hash;
mod proof;
mod tree;

pub use proof::{
    StateCommitment, StateProof, StateProofKind, StateProofLevel, StateProofValidationError,
    StateProofVerificationError, verify_membership, verify_non_membership,
};
pub use tree::{
    MAX_REFERENCE_STATE_OBJECTS, STATE_TREE_ARITY, STATE_TREE_DEPTH, StateTreeError,
    commit_objects, partition_id, path_nibble, prove_object,
};

#[cfg(test)]
mod tests;
