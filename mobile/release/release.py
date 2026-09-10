#!/usr/bin/env python3
"""Build and submit explicit, qualified ActiveChain mobile releases. Preview by default."""
import argparse
from contextlib import contextmanager, nullcontext
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
APP_ID = "dev.activechain.wallet"
REPOSITORY = "advatar/ActiveChain"
REQUIRED_JOBS = {
    "Verify qualification policy", "Determine qualification scope", "Static kernel checks",
    "Lean and Tamarin models", "Release build and Apple distribution", "Kani bounded-model checks",
    "Debug and documentation tests", "Release tests and process rehearsals",
    "Verus and proof conformance", "Canonical vectors and semantic tables",
    "Deterministic kernel qualification",
}
ACTIONS = {"ios-beta": ("ios", "beta"), "ios-review": ("ios", "review"),
           "android-internal": ("android", "internal"), "android-production": ("android", "production")}


class ReleaseError(Exception):
    pass


def capture(*args):
    return subprocess.check_output(args, cwd=ROOT, text=True).strip()


def run(args, env=None, cwd=ROOT):
    subprocess.run(args, cwd=cwd, env=env, check=True)


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def validate_version(version, number):
    if not isinstance(version, str) or not re.fullmatch(r"(?:0|[1-9][0-9]{0,3})(?:\.(?:0|[1-9][0-9]{0,3})){2}", version):
        raise ReleaseError("Version must be three numeric components, such as 0.2.0")
    if type(number) is not int or not 1 <= number <= 2_100_000_000:
        raise ReleaseError("Build number must be 1..2100000000; use a new number for a new binary")


def validate_qualification(info, detail):
    if (info.get("repository", {}).get("full_name") != REPOSITORY
            or info.get("path") != ".github/workflows/kernel.yml"
            or info.get("status") != "completed" or info.get("conclusion") != "success"):
        raise ReleaseError("Qualification must be a successful completed kernel.yml run in this repository")
    jobs = {job["name"]: job.get("conclusion") for job in detail.get("jobs", [])}
    if any(jobs.get(name) != "success" for name in REQUIRED_JOBS):
        raise ReleaseError("All full-qualification jobs must pass; development checks alone do not qualify")
    if detail.get("headSha") != info.get("head_sha"):
        raise ReleaseError("Qualification revision mismatch")
    if not re.fullmatch(r"[0-9a-f]{40}", info.get("head_sha", "")):
        raise ReleaseError("Qualification has an invalid source revision")
    return info["head_sha"]


def qualify(run_id, source=None):
    if capture("git", "status", "--porcelain", "--untracked-files=normal"):
        raise ReleaseError("Release requires a clean worktree")
    run(["git", "fetch", "origin", "main"])
    head = capture("git", "rev-parse", "HEAD")
    if source is not None and source != head:
        raise ReleaseError("Check out the artifact's exact source revision before submission")
    run(["git", "merge-base", "--is-ancestor", head, "origin/main"])
    info = json.loads(capture("gh", "api", f"repos/{REPOSITORY}/actions/runs/{run_id}"))
    detail = json.loads(capture("gh", "run", "view", str(run_id), "--repo", REPOSITORY,
                                "--json", "headSha,jobs"))
    qualified = validate_qualification(info, detail)
    run(["git", "merge-base", "--is-ancestor", qualified, head])
    # The repository explicitly exempts post-merge STATUS bookkeeping, not release inputs.
    changed = capture("git", "diff", "--name-only", qualified, head).splitlines()
    if set(changed) - {"STATUS.md"}:
        raise ReleaseError("Source differs from the qualified candidate beyond STATUS.md bookkeeping")
    return head, qualified


def require_environment(names):
    missing = [name for name in names if not os.environ.get(name, "").strip()]
    if missing:
        raise ReleaseError("Missing configuration: " + ", ".join(missing))


def apple_configuration():
    require_environment(["ASC_KEY_ID", "ASC_ISSUER_ID", "ASC_PRIVATE_KEY_PATH"])
    private_file("ASC_PRIVATE_KEY_PATH")


def private_file(name):
    path = Path(os.environ[name]).expanduser()
    if not path.is_absolute() or not path.is_file() or path.is_symlink():
        raise ReleaseError(f"{name} must name an existing absolute regular file")
    if path.stat().st_mode & 0o077:
        raise ReleaseError(f"{name} must be readable only by its owner (chmod 600)")
    return path


def fastlane(platform, lane, env):
    # API keys travel in files/environment, never command-line JSON or verbose/debug logs.
    env = dict(env, FASTLANE_SKIP_UPDATE_CHECK="1", FASTLANE_HIDE_CHANGELOG="1",
               FASTLANE_OPT_OUT_USAGE="1", FASTLANE_DISABLE_COLORS="1",
               FASTLANE_SKIP_DOCS="1", FASTLANE_ITUNES_TRANSPORTER_USE_SHELL_SCRIPT="0",
               BUNDLE_PATH=env.get("BUNDLE_PATH", str(Path.home() / ".cache/activechain-mobile-release/gems")),
               BUNDLE_GEMFILE=str(ROOT / "mobile/release/Gemfile"))
    # Fastlane's shell transporter writes to and removes a shared Apple key directory.
    # macOS's altool/Java transport uses a disposable key directory instead.
    with tempfile.TemporaryDirectory(prefix="activechain-fastlane-report-") as report:
        env["FL_REPORT_PATH"] = report
        run(["bundle", "exec", "fastlane", platform, lane], env=env, cwd=ROOT / "mobile/release")


def write_json(path, value):
    descriptor, filename = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    temporary = Path(filename)
    try:
        with os.fdopen(descriptor, "w") as stream:
            stream.write(json.dumps(value, indent=2) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def journal_path(record, action):
    directory = Path(os.environ.get("ACTIVECHAIN_RELEASE_JOURNAL",
                                   str(Path.home() / ".cache/activechain-mobile-release/submissions")))
    identity = f"{APP_ID}:{action}:{record['version']}:{record['build_number']}"
    return directory / (hashlib.sha256(identity.encode()).hexdigest() + ".json")


@contextmanager
def submission_lock(path):
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    if path.parent.is_symlink() or path.is_symlink():
        raise ReleaseError("Submission journal must not use symlinks")
    descriptor = os.open(path.with_suffix(".lock"), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise ReleaseError("This store/build submission is already running") from error
        yield path
    finally:
        os.close(descriptor)


def build(args):
    validate_version(args.version, args.build_number)
    output = Path(args.output).expanduser().resolve()
    if output.exists():
        raise ReleaseError("Output already exists; preserve prior artifacts and choose a new directory")
    if output.is_relative_to(ROOT):
        raise ReleaseError("Use an output directory outside the checkout")
    head, qualified = qualify(args.qualification_run)
    if args.platform == "ios":
        if sys.platform != "darwin":
            raise ReleaseError("Apple release builds require the configured macOS runner")
        apple_configuration()
        if subprocess.run(["pgrep", "-x", "xcodebuild"], capture_output=True).returncode == 0:
            raise ReleaseError("An Xcode build/test is active; wait before the release archive")
    else:
        require_environment(["ACTIVECHAIN_ANDROID_KEYSTORE", "ACTIVECHAIN_ANDROID_STORE_PASSWORD",
                             "ACTIVECHAIN_ANDROID_KEY_ALIAS", "ACTIVECHAIN_ANDROID_KEY_PASSWORD"])
        private_file("ACTIVECHAIN_ANDROID_KEYSTORE")
        android_source = (ROOT / "mobile/android/app/build.gradle.kts").read_text()
        target = re.search(r"targetSdk\s*=\s*(\d+)", android_source)
        if target is None or int(target.group(1)) < 36:
            raise ReleaseError("Google Play requires target API 36; complete and qualify Android parity #795 first")
    if not args.execute:
        print(json.dumps({"operation": "build", "platform": args.platform, "source_sha": head,
                          "version": args.version, "build_number": args.build_number,
                          "output": str(output), "executed": False}, indent=2))
        return
    output.mkdir(parents=True, mode=0o700)
    env = dict(os.environ, ACTIVECHAIN_RELEASE_VERSION=args.version,
               ACTIVECHAIN_RELEASE_BUILD=str(args.build_number), ACTIVECHAIN_RELEASE_OUTPUT=str(output))
    if args.platform == "ios":
        distribution = ROOT / "dist/apple" / head
        if not distribution.exists():
            run([str(ROOT / "scripts/build-apple-distribution.sh"), str(distribution), head])
        compatibility = distribution / "activechain-compatibility.json"
        if json.loads(compatibility.read_text()).get("source_revision") != head:
            raise ReleaseError("Cached Apple distribution has a different source revision")
        run(["cargo", "run", "--locked", "-p", "activechain-apple-distribution", "--",
             "verify", str(compatibility), str(distribution)])
        current = ROOT / "dist/apple/current"
        if current.exists() and not current.is_symlink():
            raise ReleaseError("dist/apple/current is not a symlink")
        current.unlink(missing_ok=True)
        current.symlink_to(head)
        run([str(ROOT / "scripts/build-anyidentity.sh")])
        fastlane("ios", "archive", env)
        artifact = output / "ActiveChainWallet.ipa"
    else:
        run([str(ROOT / "mobile/android/gradlew"), "--no-daemon", ":app:bundleRelease"],
            env=env, cwd=ROOT / "mobile/android")
        import shutil
        artifact = output / "ActiveChainWallet.aab"
        shutil.copyfile(ROOT / "mobile/android/app/build/outputs/bundle/release/app-release.aab", artifact)
    if not artifact.is_file() or artifact.is_symlink():
        raise ReleaseError("Build did not produce the expected regular artifact")
    write_json(output / "release.json", {
        "format": 1, "platform": args.platform, "application_id": APP_ID,
        "source_sha": head, "qualified_sha": qualified, "qualification_run": args.qualification_run,
        "version": args.version, "build_number": args.build_number,
        "artifact": artifact.name, "sha256": digest(artifact),
    })
    print(f"Built release manifest: {output / 'release.json'}")


def load_record(path, platform):
    record = json.loads(path.read_text())
    if record.get("format") != 1 or record.get("platform") != platform or record.get("application_id") != APP_ID:
        raise ReleaseError("Artifact platform/application/manifest format mismatch")
    validate_version(record["version"], record["build_number"])
    filename = Path(record["artifact"])
    if filename.is_absolute() or filename.parent != Path("."):
        raise ReleaseError("Artifact must be a filename next to the release manifest")
    artifact = path.parent / filename
    if (not artifact.is_file() or artifact.is_symlink()
            or artifact.suffix != {"ios": ".ipa", "android": ".aab"}[platform]
            or digest(artifact) != record.get("sha256")):
        raise ReleaseError("Artifact missing, substituted or modified since the build")
    return record


def submit(args):
    platform, lane = ACTIONS[args.action]
    manifest = Path(args.manifest).expanduser().resolve()
    record = load_record(manifest, platform)
    _, qualified = qualify(record["qualification_run"], record["source_sha"])
    if qualified != record["qualified_sha"]:
        raise ReleaseError("Recorded qualification does not match GitHub evidence")
    env = dict(os.environ, ACTIVECHAIN_RELEASE_MANIFEST=str(manifest))
    if platform == "ios":
        if sys.platform != "darwin":
            raise ReleaseError("Apple submissions require the configured macOS runner")
        apple_configuration()
        require_environment(["ASC_APP_ID"])
        if lane == "beta":
            require_environment(["ASC_TESTFLIGHT_GROUPS"])
        else:
            require_environment(["ASC_SUBMISSION_INFORMATION_PATH"])
            private_file("ASC_SUBMISSION_INFORMATION_PATH")
    else:
        require_environment(["GOOGLE_PLAY_CREDENTIALS_PATH"])
        private_file("GOOGLE_PLAY_CREDENTIALS_PATH")
    durable = journal_path(record, args.action)
    with submission_lock(durable) if args.execute else nullcontext(durable):
        publish_locked(args, manifest, record, env, durable)


def publish_locked(args, manifest, record, env, durable):
    platform, lane = ACTIONS[args.action]
    receipt = manifest.with_name(args.action + ".json")
    previous = durable if durable.exists() else receipt
    if previous.exists():
        prior = json.loads(previous.read_text())
        if (prior.get("state") == "submitted" and prior.get("artifact_sha256") == record["sha256"]
                and prior.get("action") == args.action and prior.get("application_id") == APP_ID
                and prior.get("version") == record["version"] and prior.get("build_number") == record["build_number"]):
            if args.execute:
                write_json(durable, prior)
                write_json(receipt, prior)
            print("Already submitted: " + str(receipt))
            return
        raise ReleaseError("Prior attempt has an uncertain result; reconcile the exact build in the store before retrying")
    notes = Path(args.notes).expanduser().resolve() if args.notes else None
    if lane in {"beta", "internal"}:
        if notes is None or not notes.is_file() or not notes.read_text().strip():
            raise ReleaseError("Beta uploads require a nonempty UTF-8 --notes file")
        if platform == "android" and len(notes.read_text()) > 500:
            raise ReleaseError("Google Play release notes are limited to 500 characters")
    plan = {"action": args.action, "application_id": APP_ID, "version": record["version"],
            "build_number": record["build_number"], "artifact_sha256": record["sha256"],
            "qualification_run": record["qualification_run"], "executed": args.execute}
    print(json.dumps(plan, indent=2))
    if not args.execute:
        return
    # Persist before the first store mutation. A transport error must not trigger a blind re-upload.
    attempt = dict(plan, state="attempting", attempted_at=int(time.time()))
    write_json(durable, attempt)
    write_json(receipt, attempt)
    with tempfile.TemporaryDirectory(prefix="activechain-play-metadata-") as temporary:
        if notes:
            env["ACTIVECHAIN_RELEASE_NOTES"] = str(notes)
            changelogs = Path(temporary) / "en-US/changelogs"
            changelogs.mkdir(parents=True)
            (changelogs / f"{record['build_number']}.txt").write_text(notes.read_text())
            env["ACTIVECHAIN_PLAY_METADATA"] = temporary
        fastlane(platform, lane, env)
    completed = dict(attempt, state="submitted", submitted_at=int(time.time()))
    write_json(durable, completed)
    write_json(receipt, completed)
    print("Store submission completed; store approval/availability is tracked separately: " + str(receipt))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    builder = sub.add_parser("build")
    builder.add_argument("--platform", choices=["ios", "android"], required=True)
    builder.add_argument("--version", required=True)
    builder.add_argument("--build-number", type=int, required=True)
    builder.add_argument("--qualification-run", type=int, required=True)
    builder.add_argument("--output", required=True)
    builder.add_argument("--execute", action="store_true")
    publisher = sub.add_parser("submit")
    publisher.add_argument("--action", choices=ACTIONS, required=True)
    publisher.add_argument("--manifest", required=True)
    publisher.add_argument("--notes")
    publisher.add_argument("--execute", action="store_true")
    args = parser.parse_args()
    try:
        (build if args.command == "build" else submit)(args)
    except (ReleaseError, KeyError, ValueError, OSError, subprocess.CalledProcessError) as error:
        print(f"Release stopped: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
