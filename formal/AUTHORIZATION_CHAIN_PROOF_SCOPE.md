# Joined authorization-chain proof scope

`formal/lean/ActiveChain/AuthorizationChain.lean` models the authoritative conjunction implemented
by `crates/authorization-kernel`. Successful admission implies actor and issuer authentication,
finalized/fresh credential and revocation evidence, non-amplifying active capability delegation,
holder/scope binding, an exactly derived APL request and permit, supported obligations, and exact
transition binding. It also proves that state, budgets, and invocation replay are changed together,
and that a duplicate concurrent invocation has at most one success under serialized atomic commit.

The model treats ML-DSA verification, finalized state-proof soundness, commitment collision
resistance, and filesystem durability as explicit boundary assumptions. Rust tests exercise those
interfaces, component substitution, stale/revoked evidence, attenuation, budget exhaustion,
restart/corruption, and a two-thread duplicate race.
