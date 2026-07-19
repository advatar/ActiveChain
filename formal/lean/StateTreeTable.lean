import ActiveChain.StateTree

open ActiveChain.StateTree

def main : IO Unit := do
  for (first, second, last, path0, path1, path2, path3, path94, path95, partition) in
      pathTable do
    IO.println
      s!"{first},{second},{last},{path0},{path1},{path2},{path3},{path94},{path95},{partition}"
