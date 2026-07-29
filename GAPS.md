There are currently 30 open GitHub issues, but that count includes large epics and older tracking issues—not 30 independent unfinished features.

  For the regulated profile specifically, we have completed:

  - Role/jurisdiction and privacy boundary plans
  - EU/US/Tanzania/Kenya profile manifests
  - P-120/P-121 specifications
  - Canonical evidence and Travel Rule bindings
  - Signed-envelope boundary
  - Durable replay journal
  - Runtime profile selection and manual-review outcomes
  - Admission integration
  - Lean replay/signature-gate proofs
  - Rust-to-Lean conformance vectors

  Still required before a regulated-profile opinion:

  - Real ML-DSA verifier wiring with production key registries
  - Full profile inheritance/stricter-conflict implementation
  - Complete sanctions, KYC/KYB, Travel Rule, monitoring, and case-management specifications
  - Confidential evidence operations
  - Operator and counsel completion of jurisdiction matrices
  - At least a 90-day operating period
  - Independent security/compliance engagement
  - Remediation and re-test of findings

  The broader protocol still has major open areas:

  - Multi-asset state transitions and wallet support
  - Native issuer and stablecoin operations
  - Faucet and testnet funding
  - Agent enrollment/UI completion
  - Owner-scoped Coin Cell RPC
  - EUDI/TLSNotary/ZK credential pipeline
  - dBrowser verifier SDK, RPC, and wallet ABI
  - PQ-ZK and CashAIR proof work
  - Consensus/testnet qualification
  - Apple reproducibility and release gates
  - Historical branch/worktree reconciliation issues

  So the honest answer is: the compliance architecture is now substantially defined and partially implemented, but the product as a whole is not feature-complete or
  production/testnet-qualified yet. The remaining work is measured in several substantial phases, not a final cleanup pass.
