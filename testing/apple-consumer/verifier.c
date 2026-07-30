#include <activechain_verifier.h>
#include <string.h>

int main(void) {
    if (activechain_verifier_abi_revision() != 1u ||
        activechain_verifier_schema_revision() != 1u ||
        activechain_verifier_protocol_revision() != 1u) {
        return 1;
    }
    static const uint8_t domain[] = "swiftledger.audit.v1";
    uint8_t digest[32] = {0};
    uint8_t reference[48] = {0};
    uint32_t statement_len = 0;
    if (activechain_anchor_statement_v1(domain, (uint32_t)strlen((const char *)domain), digest,
                                        NULL, 0, &statement_len, reference) !=
        ACTIVECHAIN_VERIFY_BUFFER_TOO_SMALL || statement_len == 0) {
        return 2;
    }
    uint8_t statement[256] = {0};
    if (statement_len > sizeof(statement) ||
        activechain_anchor_statement_v1(domain, (uint32_t)strlen((const char *)domain), digest,
                                        statement, sizeof(statement), &statement_len, reference) !=
            ACTIVECHAIN_VERIFY_OK) {
        return 3;
    }
    uint8_t request[512] = {0};
    uint32_t request_len = 0;
    if (activechain_anchor_submit_request_v1(statement, statement_len, request, sizeof(request),
                                             &request_len) != ACTIVECHAIN_VERIFY_OK ||
        request_len == 0) {
        return 4;
    }
    return 0;
}
