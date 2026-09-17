# Capability manifests

PRODUCTION.md G18 asks for maturity to become an executable release property, so
that a claim can be checked against evidence instead of classified by hand.

A manifest is one JSON file per capability in this directory. It states what the
capability is, how mature it is, and — the part that matters — the exact local
commands that substantiate the claim. `tools/check_capabilities.py` validates every
manifest against the rules below and, with `--run`, executes each declared gate and
fails if the recorded expectations do not hold.

A manifest is not documentation. It is a claim that a checker can refute.

## Fields

| Field | Required | Meaning |
| --- | --- | --- |
| `id` | yes | Stable kebab-case identifier, unique in this repository |
| `title` | yes | One line, what the capability is |
| `maturity` | yes | `IMPLEMENTED`, `DEMONSTRATED`, `RESEARCH` or `TARGET` |
| `gates` | yes | PRODUCTION.md gate ids this contributes to, e.g. `["G3", "G4"]` |
| `scope` | yes | What the capability covers, in one or two sentences |
| `assumptions` | yes | What must hold for the evidence to mean anything |
| `verification` | yes | List of gates: `{command, expect_tests, description}` |
| `known_failures` | yes | What is known not to work, or not to be covered. May be empty only for `TARGET` |
| `clinical_use` | yes | `none`, `research_only` or `clinical` |
| `dependencies` | no | Other capability ids, or external pins such as an upstream commit |
| `qualified_versions` | no | Versions this claim is bound to |
| `last_reviewed` | yes | ISO date the claim was last checked against its evidence |

## Maturity

The meanings are deliberately demanding, because the point of G18 is to stop a
claim drifting upward without evidence.

- **IMPLEMENTED** — runs on the production path, with automated verification that
  fails when the behaviour regresses. Requires at least one `verification` entry
  with `expect_tests`.
- **DEMONSTRATED** — works end to end on a real path, but under a fixture,
  synthetic data or a narrowed scope. Requires at least one `verification` entry.
- **RESEARCH** — explored and possibly working, but not integrated on any real
  path. `verification` may be empty.
- **TARGET** — intended, not built. `verification` must be empty, and a `TARGET`
  capability may not declare `clinical_use: clinical`.

## Rules the checker enforces

1. Every field above that is required is present and non-empty, with the stated type.
2. `id` is unique and matches the filename.
3. `maturity` satisfies the verification requirements above.
4. `known_failures` is non-empty unless `maturity` is `TARGET`. Claiming no known
   limitation is itself a claim, and an unlikely one.
5. `clinical_use: clinical` requires `maturity: IMPLEMENTED` and an explicit
   qualification dependency. Nothing in this repository currently qualifies.
6. Declared `dependencies` that name a capability id must resolve.
7. With `--run`, each `verification.command` executes from the repository root and
   must exit zero. When `expect_tests` is set, the command's output must report
   exactly that many passing tests; a changed count fails rather than silently
   passing, so evidence cannot quietly shrink.

Rule 7 is what makes the manifest a claim rather than a comment.
