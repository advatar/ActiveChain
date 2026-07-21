#ifndef ACTIVECHAIN_WALLET_H
#define ACTIVECHAIN_WALLET_H
#include <stdint.h>
uint32_t activechain_wallet_ffi_revision(void);
uint32_t activechain_wallet_session_valid(const uint8_t *session_id,
                                          const uint8_t *relying_party,
                                          uint64_t expires_at,
                                          uint64_t height);
#endif
