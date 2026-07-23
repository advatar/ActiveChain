#ifndef ACTIVECHAIN_VERIFIER_H
#define ACTIVECHAIN_VERIFIER_H

#include <stdint.h>

/* Stable result codes shared by C, Swift, Kotlin, and JavaScript adapters. */
#define ACTIVECHAIN_VERIFY_OK 0u
#define ACTIVECHAIN_VERIFY_TOO_LARGE 1u
#define ACTIVECHAIN_VERIFY_DECODE_ERROR 2u
#define ACTIVECHAIN_VERIFY_TYPE_MISMATCH 3u
#define ACTIVECHAIN_VERIFY_VERSION_MISMATCH 4u
#define ACTIVECHAIN_VERIFY_COMMITMENT_MISMATCH 5u
#define ACTIVECHAIN_VERIFY_NULL_POINTER 6u
#define ACTIVECHAIN_VERIFY_RELATION_MISMATCH 7u

uint32_t activechain_verifier_abi_revision(void);
uint32_t activechain_verifier_schema_revision(void);
uint64_t activechain_verifier_protocol_revision(void);

/*
 * Adapter contract. The adapter owns all input/output buffers; the verifier never
 * retains pointers, writes through them, or allocates unbounded memory.
 */
uint32_t activechain_inspect_envelope_code(
    const uint8_t *bytes,
    uint32_t bytes_len,
    uint16_t expected_type,
    uint16_t expected_version);

uint32_t activechain_verify_commitment_code(
    const uint8_t *domain,
    uint32_t domain_len,
    const uint8_t *body,
    uint32_t body_len,
    const uint8_t expected_digest384[48]);

uint32_t activechain_verify_principal_code(
    const uint8_t *bytes,
    uint32_t bytes_len);

uint32_t activechain_verify_capability_code(
    const uint8_t *bytes,
    uint32_t bytes_len);

uint32_t activechain_verify_capability_attenuation_code(
    const uint8_t *parent,
    uint32_t parent_len,
    const uint8_t *child,
    uint32_t child_len);

uint32_t activechain_verify_policy_decision_code(
    const uint8_t *bytes,
    uint32_t bytes_len);

uint32_t activechain_verify_state_membership_code(
    const uint8_t *commitment,
    uint32_t commitment_len,
    const uint8_t *object,
    uint32_t object_len,
    const uint8_t *proof,
    uint32_t proof_len);

uint32_t activechain_verify_state_non_membership_code(
    const uint8_t *commitment,
    uint32_t commitment_len,
    const uint8_t object_id[48],
    const uint8_t *proof,
    uint32_t proof_len);

#endif
