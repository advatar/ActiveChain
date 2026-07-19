#![no_std]
#![forbid(unsafe_code)]

//! ActiveChain Authorization Policy Language (APL) semantic kernel.
//!
//! Policies are already parsed, typed, and bounded when they reach this crate.
//! Evaluation is total for every validated policy and request: there is no I/O,
//! clock, recursion, dynamic dispatch, or external function registry.

extern crate alloc;

mod ast;
mod eval;
mod request;

pub use ast::{
    APL_LANGUAGE_VERSION, ActorBinding, MAX_OBLIGATIONS_PER_RULE, MAX_POLICY_OBLIGATIONS,
    MAX_POLICY_PREDICATES, MAX_POLICY_RULES, PolicyEffect, PolicyObligation, PolicyPredicate,
    PolicyRule, PolicyRuleError, PolicySet, PolicySetError,
};
pub use eval::{
    DecisionResult, MAX_EVALUATION_STEPS, PolicyDecision, PolicyDecisionError, combine_effects,
    evaluate,
};
pub use request::{
    ApprovalFact, ApprovalFactError, MAX_APPROVAL_FACTS, MAX_CAPABILITY_FACTS,
    MAX_CREDENTIAL_FACTS, PolicyRequest, PolicyRequestError, PolicyRequestFields,
};
