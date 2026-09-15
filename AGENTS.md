```md
# AGENTS

## Working Rules

- Always `git add` and commit and push after creating or editing files. Use clear, descriptive commit messages.
- Verify builds locally before claiming completion for any change.
- After assessing a request, add or update related tasks in `STATUS.md` before implementation. Also, create a github issue with all the details and the plan.
- THIS IS IMPORTANT: Keep going without pausing for confirmation if you already know what the next step is; only ask when a decision is blocking progress.
- Never stage, commit, or alter files you did not edit for the task; leave unrelated changes for their owner.
- Merge a feature into `main` promptly once it is working and verified; do not let completed work drift on long-lived branches.
- Use exactly one active implementation branch per GitHub issue. Reuse that branch for follow-up
  fixes; do not create tangential, duplicate, or differently named branches for the same scope.
- Keep branch names and commits aligned with the issue scope. If the work changes materially,
  update the issue and rename or replace the branch before adding unrelated changes.
- Before declaring an issue complete, verify the intended commits or patch-equivalent changes are
  reachable from `origin/main`; a closed issue, green branch, cherry-pick, or squash is not by
  itself proof that the work is integrated.
- After a verified merge, delete the source branch immediately. Before starting new feature work,
  run `git branch -r --no-merged origin/main` and reconcile any unexpected branch instead of
  accumulating more parallel work.
- Do not merge an ahead branch merely because Git reports commits missing from `main`. Compare its
  effective diff and current normative requirements, run the relevant tests, and explicitly
  retire branches whose work is superseded, duplicated, stale, or unsafe.
- Other agents may be working in the same repo; mind your own business and avoid unrelated investigation or edits.
- Claim a work unit BEFORE implementing it: push the issue branch with one small initial commit
  and open a draft PR titled "<area>: <unit> (#<issue>)" whose body starts with
  "Claimed by <agent-name> — in progress". A unit with an open draft PR or a pushed
  `feat/<issue>-*` branch belongs to that agent; pick a different unit instead of duplicating it.
  Convert the draft to ready only when the unit is qualified. If a claim goes untouched for more
  than a day, comment on the PR before taking it over.
- When you have unchecked tasks, complete them one by one after passing tests, do not stop
- If any open issue or unchecked roadmap task remains, do not stop to report status to the user;
  continue directly with the next actionable step. Pause only when a genuinely blocking decision
  or missing authority requires user input.
- When adding new functionality add unit tests

## Verification Cadence

- Select verification from the effective diff against the merge base. Run formatting, builds,
  tests, proofs, process rehearsals, and distribution checks only where the changed files or their
  consumers can be affected. A packaging-only iOS change needs Apple archive/distribution checks,
  not unrelated kernel proofs or runtime rehearsals.
- For touched crates, run their relevant checks and tests, including all-feature Clippy where
  appropriate. Batch related fixes locally and push one consolidated revision.
- Before merge, require the change-scoped CI jobs and relevant local checks to pass on the final
  implementation revision. If a check fails, diagnose its stage, fix the related cause, and rerun
  only the affected checks. Verify that the merged changes are reachable from `origin/main`.
- Run the complete deterministic-kernel gate only when the changed boundary spans every stage,
  for release qualification, or when the project owner explicitly requests an exhaustive audit.
  Do not trigger it automatically for routine pushes or narrow PRs.
