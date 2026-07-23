#ifndef ACTIVECHAIN_WALLET_H
#define ACTIVECHAIN_WALLET_H
#include <stdint.h>
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
#endif
