import ActiveChainWallet

guard activechain_wallet_ffi_revision() == 3 else {
    fatalError("incompatible ActiveChain wallet")
}
