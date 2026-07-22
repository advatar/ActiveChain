# State-tree refinement proof scope

The state-tree refinement is no longer only a three-key nibble table. The Lean
model defines arbitrary 16-child proof levels, bottom-up proof folding,
membership as folded-root equality, replacement-root derivation on the same
authenticated sibling path, deterministic folding, and exact insert/replace/
delete object-count transitions. It proves that every replacement root verifies
under the same path and that positive-count deletion changes the count exactly.

The Rust production verifier and updater share `reconstruct_tree_root`, the
canonical 96-level fold. `apply_single_key_update` first authenticates the exact
membership or non-membership pre-leaf, rejects replacement-key substitution,
folds the replacement leaf through the same siblings, and changes object count
only for insertions or deletions. Deterministic insert, replacement, and deletion
tests compare its result with `commit_objects` full-tree recomputation. A property
test repeats replacement equivalence for arbitrary before/after versions, and a
separate property compares arbitrary 384-bit keys and depths with an independent
nibble/partition oracle.

SHAKE256 collision resistance, the canonical object encoder, and the compiler-
level correspondence between Lean functions and Rust remain explicit external
assumptions. The result proves structural refinement and production differential
agreement; it is not a cryptographic proof or an extraction of Rust into Lean.
