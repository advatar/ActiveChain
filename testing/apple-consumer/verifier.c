#include <activechain_verifier.h>

int main(void) {
    return activechain_verifier_abi_revision() == 1u &&
                   activechain_verifier_schema_revision() == 1u &&
                   activechain_verifier_protocol_revision() == 1u
               ? 0
               : 1;
}
