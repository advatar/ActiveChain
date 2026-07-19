/-!
# ActiveChain P-030 object-version and atomic publication model

This dependency-free model fixes the checked one-step version relation and the
all-or-nothing publication rule independently of the Rust implementation.
-/

namespace ActiveChain.ObjectModel

def maxVersion : Nat := 18446744073709551615

inductive TransferResult where
  | success (nextVersion : Nat)
  | authorizationDenied
  | staleVersion
  | versionExhausted
  deriving BEq, DecidableEq, Repr

/-- Execute authorization and checked exact-version consumption. -/
def transferVersion (version expectedVersion : Nat) (authorized : Bool) : TransferResult :=
  if !authorized then
    .authorizationDenied
  else if expectedVersion != version then
    .staleVersion
  else if version == maxVersion then
    .versionExhausted
  else
    .success (version + 1)

/-- Publish scratch versions only if the complete batch succeeded. -/
def publishBatch (preState scratchState : List Nat) (succeeded : Bool) : List Nat :=
  if succeeded then scratchState else preState

theorem successIncrementsExactlyOnce
    (version expectedVersion nextVersion : Nat)
    (authorized : Bool)
    (h : transferVersion version expectedVersion authorized = .success nextVersion) :
    nextVersion = version + 1 := by
  unfold transferVersion at h
  split at h <;> try simp_all
  split at h <;> try simp_all
  split at h <;> simp_all

@[simp] theorem failedBatchPreservesPreState (preState scratchState : List Nat) :
    publishBatch preState scratchState false = preState := rfl

@[simp] theorem successfulBatchPublishesScratch (preState scratchState : List Nat) :
    publishBatch preState scratchState true = scratchState := rfl

@[simp] theorem exhaustedVersionCannotAdvance :
    transferVersion maxVersion maxVersion true = .versionExhausted := rfl

/-- Executable cases cross-checked by the Rust vector generator. -/
def versionCases : List (Nat × Nat × Bool) :=
  [
    (0, 0, true),
    (7, 6, true),
    (maxVersion, maxVersion, true),
    (7, 7, false)
  ]

def versionTable : List (Nat × Nat × Bool × TransferResult) :=
  versionCases.map fun (version, expectedVersion, authorized) =>
    (version, expectedVersion, authorized,
      transferVersion version expectedVersion authorized)

theorem versionTableHasFourRows : versionTable.length = 4 := rfl

end ActiveChain.ObjectModel
