import ActiveChainVerifier

guard activechain_verifier_abi_revision() == 1,
      activechain_verifier_schema_revision() == 1,
      activechain_verifier_protocol_revision() == 1 else {
    fatalError("incompatible ActiveChain verifier")
}
