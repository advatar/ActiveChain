#include <activechain_wallet.h>

int main(void) {
    return activechain_wallet_ffi_revision() == 2u ? 0 : 1;
}
