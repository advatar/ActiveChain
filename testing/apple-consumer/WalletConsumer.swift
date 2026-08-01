import ActiveChainWallet

guard activechain_wallet_ffi_revision() == 4 else {
    fatalError("incompatible ActiveChain wallet")
}
