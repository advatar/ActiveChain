# Deterministic-kernel qualification

The `Deterministic kernel` workflow has two modes.

## Development mode

Pull-request updates run development mode automatically. The initial run compares the exact proposed
revision with its base; subsequent synchronization runs compare the newly pushed commit delta. The
scope job selects only affected stage families. Documentation-only changes run the workflow-policy
check but do not occupy the ARM64 runner. Development mode is feedback, not final qualification.

## Full qualification mode

Before merging a substantive final candidate, dispatch `Deterministic kernel` on the exact source
branch with `qualification=full`. Pushes to `main` also run full mode. The final
`Deterministic kernel qualification` result succeeds only when all mandatory jobs succeed for the
same `github.sha`:

- workflow policy;
- formatting, registries, independent-client budget, Go reader, Clippy, and no-std checks;
- Lean, Tamarin, Verus, and differential conformance;
- all Kani suites;
- debug and documentation tests;
- release build and reproducible Apple distributions;
- release tests and validator/Kanalen process rehearsals; and
- canonical vectors and Rust/Lean semantic tables.

The ARM64 jobs remain serial because they share one machine. They use a persistent Cargo target
directory namespaced by exact SHA, so clean source checkouts can reuse compilation safely. GitHub's
**Re-run failed jobs** action reruns only a failed stage and its aggregate result; already-green
formal proofs and test jobs remain authoritative for that workflow attempt.

Never treat `Deterministic kernel development checks` as final qualification. Never merge an
executable, formal, vector, build, workflow, dependency, packaging, or release-input change without
a green full aggregate result on its exact final candidate.
