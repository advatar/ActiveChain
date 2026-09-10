# Mobile store release

Issue [#847](https://github.com/advatar/ActiveChain/issues/847) adds explicit build and
submission commands for `dev.activechain.wallet`. The implementation is in
`mobile/release/`; `.github/workflows/mobile-store-release.yml` exposes the same
operations through workflow dispatch on `main`.

## Current readiness

The release commands are under development. No store upload has been performed.
Apple/Google authentication, app records, signing identities and live submission
results still need qualification. Android currently targets API 35: the release
preflight blocks its store build until the API 36 upgrade is qualified with Android
parity [#795](https://github.com/advatar/ActiveChain/issues/795). The stakeholder's
Tanzanian identity flow is tracked separately in [#846](https://github.com/advatar/ActiveChain/issues/846).

## One-time account setup

The account owner must have the correct app records, accepted agreements, privacy
policy, store listing, age/content ratings, review contact and any required app
access instructions configured. Apple requires a usable distribution signing
identity and provisioning capability for team `L2AF8KFX35`. Google requires the
existing upload key for an existing Play app; do not replace that key casually.
Create/configure the Play app and Play App Signing before its first API upload.

Create the GitHub environment `mobile-store` and restrict it to trusted `main`
releases. Configure these secrets through the authorized secret store; never put
their contents in an issue, workflow input, release note or repository file:

| GitHub secret | Purpose |
| --- | --- |
| `ASC_KEY_ID`, `ASC_ISSUER_ID` | App Store Connect API key identifiers |
| `ASC_PRIVATE_KEY_P8_BASE64` | Base64-encoded Apple API private key |
| `ASC_SUBMISSION_INFORMATION_BASE64` | Base64 JSON of the owner's accurate Apple review/export declarations |
| `GOOGLE_PLAY_CREDENTIALS_BASE64` | Base64 service-account JSON with access to this Play app |
| `ANDROID_KEYSTORE_BASE64` | Base64 existing Android upload keystore |
| `ANDROID_STORE_PASSWORD`, `ANDROID_KEY_ALIAS`, `ANDROID_KEY_PASSWORD` | Upload signing configuration |

Set environment variables `ASC_APP_ID` (the numeric Apple app ID for this bundle)
and `ASC_TESTFLIGHT_GROUPS` (comma-separated existing external testing groups).
Account configuration and tester invitations are separate from uploading a build.
The beta lane does not send automatic tester notifications.

The release runner is the configured macOS ARM64 `activechain-ci` host. It needs
Xcode, the repository's Rust toolchain/Apple targets, Java 17, Android SDK/NDK,
Python 3.11+, Ruby/Bundler and `gh`. Fastlane is pinned with a checksummed Gemfile
lock. Bundler uses a dedicated cache, not the system gem directory.

## Qualification and artifacts

Build from a clean checkout of an exact SHA already integrated into `origin/main`.
Supply the successful full `kernel.yml` run for that source. The release wrapper
checks every required full-qualification job, repository and revision. A green
development-only run is insufficient. Only subsequent `STATUS.md` bookkeeping
may differ from the qualified candidate.

Choose an explicit three-component version and a new increasing integer build
number after checking the corresponding store. The tool validates their format
and journals submissions, but remote build-number availability is not inferred
from Git. Never reuse a number for different binary contents. Android version
codes increase across all versions and tracks. Store-side monotonic-number
rejection and processing identifiers remain part of the pending live qualification.

The build operation creates an IPA or signed AAB and `release.json` outside the
checkout. The manifest records the application, version, build number, source SHA,
qualification run/revision and artifact SHA-256. iOS verifies cached native
distribution contents and source before archiving. Android release tasks reject
missing signing or version configuration; debug builds keep their normal setup.

Workflow dispatch inputs:

| Operation | Required inputs in addition to exact `source` |
| --- | --- |
| `build-ios`, `build-android` | `qualification_run`, `version`, `build_number` |
| `ios-beta`, `android-internal` | Successful build `artifact_run`, nonempty `notes` |
| `ios-review`, `android-production` | Successful build `artifact_run` |

The default `execute=false` validates and previews without building or submitting.
It still requires qualification evidence and the applicable configuration.
Set `execute=true` to perform the selected operation. Submissions download the
explicit build run's artifact and verify its manifest, hash and exact checkout
again. They never select a vaguely defined “latest” build.

`ios-beta` uploads and waits for processing, then submits to the configured external
TestFlight group. Applicable Beta App Review still governs external availability.
`ios-review` submits the exact uploaded version/build for App Store review and
retains manual public release. `android-internal` submits to internal testing;
`android-production` promotes the explicit build present on that internal track.
The production operation requests a completed production rollout: dispatch it only
when that public release is intended. Google review still applies, including any
managed-publishing settings. A successful command is submission evidence, not a
claim that a store has approved or publicly published the build.

Only IPA/AAB files and JSON evidence are retained as workflow artifacts for 30
days. Private credential files are created with owner-only permissions under the
run's temporary directory and removed afterward. Archives/DerivedData and keys
are not uploaded as evidence. Fastlane uses a temporary report location and its
shared-directory shell transporter is disabled.

## Local commands

Run from the qualified source checkout. Configure the applicable environment:

- Apple: `ASC_KEY_ID`, `ASC_ISSUER_ID`, `ASC_PRIVATE_KEY_PATH`; submissions also
  require `ASC_APP_ID`, and either `ASC_TESTFLIGHT_GROUPS` for beta or
  `ASC_SUBMISSION_INFORMATION_PATH` for review.
- Google: `GOOGLE_PLAY_CREDENTIALS_PATH` for submission. Builds use
  `ACTIVECHAIN_ANDROID_KEYSTORE`, `ACTIVECHAIN_ANDROID_STORE_PASSWORD`,
  `ACTIVECHAIN_ANDROID_KEY_ALIAS`, `ACTIVECHAIN_ANDROID_KEY_PASSWORD`.

Credential paths must be absolute, regular, non-symlink files readable only by
their owner (`chmod 600`). Install dependencies with `BUNDLE_PATH` set to the
dedicated cache used by `release.py`, then use the CLI's explicit arguments:

```sh
python3 mobile/release/release.py build --help
python3 mobile/release/release.py submit --help
```

No default version, destination directory, qualification run or artifact is
invented. Add `--execute` after reviewing the validated operation. Release builds
will not start while another `xcodebuild` is active. Do not overlap a locally
started build with another build of the same project/DerivedData.

## Failed or repeated submissions

Before the first store mutation, the tool durably writes an `attempting` receipt
both beside the artifact and in
`~/.cache/activechain-mobile-release/submissions`. It holds a per-app/action/build
file lock throughout submission. After Fastlane succeeds, both receipts become
`submitted` with timestamps. Repeating the exact completed operation is a no-op.
A conflicting artifact or uncertain result stops rather than uploading again.

Preserve the journal across runner restarts. If more than one host can run this
workflow, configure `ACTIVECHAIN_RELEASE_JOURNAL` to the same durable filesystem
with working file locks; workflow concurrency alone does not preserve prior
submission outcomes on another host. Back up submission receipts with release
records. Do not delete the journal to retry an unexplained failure.

For an `attempting` result, inspect the exact app/version/build in the store and
retain its processing/submission ID and state with the artifact. A successful
upload followed by failed distribution/review must be resumed at that later
stage; do not re-upload its binary. Automated store reconciliation and live
processing-ID capture are not yet qualified. A receipt may only be repaired after
the remote outcome has been established; uncertainty is not evidence of failure.

## Contextual verification

During implementation use the release admission tests, Ruby syntax/lane loading,
workflow lint and affected Gradle tasks. Do not rerun the full kernel gate after
each edit. Run it once on the settled substantive merge candidate, and verify the
effective change is reachable from `origin/main` before calling this work complete.

Official references: [Apple external testing](https://developer.apple.com/help/app-store-connect/test-a-beta-version/invite-external-testers/),
[Google Play publishing API](https://developers.google.com/android-publisher),
[Google target API requirements](https://support.google.com/googleplay/android-developer/answer/11926878),
[Fastlane TestFlight](https://docs.fastlane.tools/actions/upload_to_testflight/),
[Fastlane App Store](https://docs.fastlane.tools/actions/upload_to_app_store/),
[Fastlane Play Store](https://docs.fastlane.tools/actions/upload_to_play_store/).
