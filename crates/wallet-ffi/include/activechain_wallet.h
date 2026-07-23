#ifndef ACTIVECHAIN_WALLET_H
#define ACTIVECHAIN_WALLET_H
#include <stdint.h>
typedef uint32_t (*activechain_wallet_sign_callback)(
    void *context,
    const uint8_t *payload,
    uint32_t payload_len,
    uint8_t *signature_out,
    uint32_t signature_len);
typedef uint32_t (*activechain_wallet_submit_callback)(
    void *context,
    const uint8_t *envelope,
    uint32_t envelope_len);
uint32_t activechain_wallet_ffi_revision(void);
uint32_t activechain_wallet_session_valid(const uint8_t *session_id,
                                          const uint8_t *relying_party,
                                          uint64_t expires_at,
                                          uint64_t height);
uint32_t activechain_wallet_select_cells(const uint8_t *cells,
                                         uint32_t cells_len,
                                         const uint8_t owner[48],
                                         uint64_t amount_high,
                                         uint64_t amount_low,
                                         uint64_t fee_high,
                                         uint64_t fee_low,
                                         uint8_t payment_out[48],
                                         uint8_t fee_reserve_out[48]);
uint32_t activechain_wallet_policy_allows(uint64_t daily_limit_high,
                                          uint64_t daily_limit_low,
                                          uint64_t max_single_high,
                                          uint64_t max_single_low,
                                          const uint8_t *allowed_recipient,
                                          uint64_t amount_high,
                                          uint64_t amount_low,
                                          const uint8_t recipient[48],
                                          uint64_t spent_high,
                                          uint64_t spent_low);
uint32_t activechain_wallet_build_cash_intent(
    const uint8_t chain_id[48],
    const uint8_t signer[48],
    const uint8_t recipient[48],
    const uint8_t input[48],
    const uint8_t fee_reserve[48],
    uint64_t nonce,
    const uint8_t session_id[48],
    uint64_t session_expires_at,
    uint64_t amount_high,
    uint64_t amount_low,
    uint64_t fee_high,
    uint64_t fee_low,
    uint64_t valid_until,
    uint8_t *output,
    uint32_t output_capacity,
    uint32_t *required_len,
    uint8_t intent_out[48]);
uint32_t activechain_wallet_sign_cash_intent(
    const uint8_t *request,
    uint32_t request_len,
    const uint8_t public_key[1312],
    activechain_wallet_sign_callback callback,
    void *callback_context,
    uint8_t *output,
    uint32_t output_capacity,
    uint32_t *required_len);
uint32_t activechain_wallet_submit_authorized(
    const uint8_t *envelope,
    uint32_t envelope_len,
    const uint8_t public_key[1312],
    activechain_wallet_submit_callback callback,
    void *callback_context);
#endif
