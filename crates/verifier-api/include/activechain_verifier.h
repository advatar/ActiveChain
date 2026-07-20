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

#endif
