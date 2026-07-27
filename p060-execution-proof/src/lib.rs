#![forbid(unsafe_code)]

pub mod air;
pub mod codec;
pub mod hash;
pub mod model;
pub mod prover;
pub mod suite;
pub mod verifier;

pub use codec::{Receipt, ReceiptHeader};
pub use model::{Action, Block, Opcode};
pub use prover::{ProveError, prove};
pub use verifier::{
    ExpectedContext, VerificationReport, VerifyError, verify_model_receipt, verify_receipt,
};
