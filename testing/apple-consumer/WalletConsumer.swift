import ActiveChainWallet

guard activechain_wallet_ffi_revision() == 2 else {
    fatalError("incompatible ActiveChain wallet")
}
