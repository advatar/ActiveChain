#![no_std]
#![forbid(unsafe_code)]

//! Pure P-021 credential acceptance over explicit preverified evidence.

extern crate alloc;

mod verify;

pub use verify::{
    CredentialFactError, CredentialStatus, CredentialVerificationError, PresentationContext,
    PreverifiedIssuerEvidence, PreverifiedStatusEvidence, VerifiedCredentialFact,
    canonical_schema_facts, credential_id, credential_issuance_commitment, verify_presentation,
};

#[cfg(test)]
mod tests;
