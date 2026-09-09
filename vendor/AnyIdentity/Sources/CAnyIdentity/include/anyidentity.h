#ifndef ANYIDENTITY_H
#define ANYIDENTITY_H
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef struct AnyIdentityKey AnyIdentityKey;
uint32_t anyidentity_abi_version(void);
AnyIdentityKey *anyidentity_key_generate(void);
AnyIdentityKey *anyidentity_key_import(const uint8_t *seed, size_t length);
bool anyidentity_key_export(const AnyIdentityKey *key, uint8_t *output, size_t length);
AnyIdentityKey *anyidentity_key_derive(const AnyIdentityKey *key, const uint8_t *audience, size_t length);
void anyidentity_key_free(AnyIdentityKey *key);
/* UTF-8 JSON, max 1 MiB. The returned NUL-terminated JSON is library-owned until
   string_free. Errors are {"ok":false,"error":{"code":...,"message":...}}.
   Keys are immutable and may be read concurrently; freeing requires exclusive ownership.
   Callers must supply valid pointers/lengths and must never free an allocation twice. */
char *anyidentity_call(const AnyIdentityKey *key, const uint8_t *request, size_t length);
void anyidentity_string_free(char *value);
bool anyidentity_sha256(const uint8_t *input, size_t length, char *output_65_bytes);
#ifdef __cplusplus
}
#endif
#endif
