import ActiveChainWallet

guard activechain_wallet_ffi_revision() == 1 else {
    fatalError("incompatible ActiveChain wallet")
}
