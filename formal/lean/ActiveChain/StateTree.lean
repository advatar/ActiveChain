/-!
# ActiveChain P-031 sparse-state path and proof-fold model

This dependency-free model fixes high-to-low nibble traversal and reconstructs
every proof level as exactly sixteen children. Cryptographic hashing remains an
abstract function so the model isolates structural proof semantics from SHAKE.
-/

namespace ActiveChain.StateTree

def arity : Nat := 16

def depth : Nat := 96

/-- Depth zero reads the high nibble; odd depths read the low nibble. -/
def pathNibble (key : List Nat) (level : Nat) : Option Nat :=
  match key[level / 2]? with
  | none => none
  | some byte =>
      if level % 2 == 0 then some (byte / 16) else some (byte % 16)

/-- Logical partitions are the first twelve key bits. -/
def partitionId (first second : Nat) : Nat :=
  first * 16 + second / 16

@[simp] theorem depthZeroReadsHighNibble (byte : Nat) (tail : List Nat) :
    pathNibble (byte :: tail) 0 = some (byte / 16) := rfl

@[simp] theorem depthOneReadsLowNibble (byte : Nat) (tail : List Nat) :
    pathNibble (byte :: tail) 1 = some (byte % 16) := rfl

/-- The complete ordered input to one abstract internal-node hash. -/
abbrev Children (α : Type) := Fin arity → α

/-- One root-to-leaf proof level after canonical bitmap decoding. -/
structure ProofLevel (α : Type) where
  nodeDepth : Nat
  pathChild : Fin arity
  emptyChild : α
  sibling : Fin arity → Option α

/-- Put the current path accumulator in its slot and fill omitted siblings. -/
def reconstructChildren (level : ProofLevel α) (accumulator : α) : Children α :=
  fun child =>
    if child = level.pathChild then
      accumulator
    else
      (level.sibling child).getD level.emptyChild

@[simp] theorem reconstructedPathIsAccumulator (level : ProofLevel α) (accumulator : α) :
    reconstructChildren level accumulator level.pathChild = accumulator := by
  simp [reconstructChildren]

theorem omittedSiblingIsDefault
    (level : ProofLevel α)
    (accumulator : α)
    (child : Fin arity)
    (notPath : child ≠ level.pathChild)
    (omitted : level.sibling child = none) :
    reconstructChildren level accumulator child = level.emptyChild := by
  simp [reconstructChildren, notPath, omitted]

/-- Apply one internal-node hash to a reconstructed proof level. -/
def foldLevel
    (hashNode : Nat → Children α → α)
    (level : ProofLevel α)
    (accumulator : α) : α :=
  hashNode level.nodeDepth (reconstructChildren level accumulator)

/-- Fold root-to-leaf proof levels from leaf to root. -/
def foldProof
    (hashNode : Nat → Children α → α)
    (rootToLeaf : List (ProofLevel α))
    (leaf : α) : α :=
  rootToLeaf.reverse.foldl (fun accumulator level =>
    foldLevel hashNode level accumulator) leaf

@[simp] theorem emptyProofPreservesLeaf (hashNode : Nat → Children α → α) (leaf : α) :
    foldProof hashNode [] leaf = leaf := rfl

/-- A 48-byte key with explicit boundary bytes for executable fixtures. -/
def boundaryKey (first second last : Nat) : List Nat :=
  [first, second] ++ List.replicate 45 0 ++ [last]

structure PathCase where
  first : Nat
  second : Nat
  last : Nat

def pathCases : List PathCase :=
  [
    ⟨0, 0, 0⟩,
    ⟨18, 52, 239⟩,
    ⟨255, 255, 255⟩
  ]

def pathTable : List (Nat × Nat × Nat × Nat × Nat × Nat × Nat × Nat × Nat × Nat) :=
  pathCases.map fun test =>
    let key := boundaryKey test.first test.second test.last
    (
      test.first,
      test.second,
      test.last,
      (pathNibble key 0).getD 999,
      (pathNibble key 1).getD 999,
      (pathNibble key 2).getD 999,
      (pathNibble key 3).getD 999,
      (pathNibble key 94).getD 999,
      (pathNibble key 95).getD 999,
      partitionId test.first test.second
    )

theorem pathTableHasThreeRows : pathTable.length = 3 := rfl

end ActiveChain.StateTree
